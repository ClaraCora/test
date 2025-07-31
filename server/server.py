# 文件名: server.py (v_secure_plus - 终极安全和功能版)
import json
import requests
import hmac
import hashlib
import time
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, Response
from collections import Counter

# 导入我们自己的模块
import config
import database

# --- 初始化 ---
app = Flask(__name__)
app.secret_key = 'a_random_secret_key_for_flask_session' 
cfg = config.load_config()
database.init_db()

# --- 安全功能：HTTP基础认证 ---
def check_auth(username, password):
    """检查用户名和密码是否正确"""
    return username == cfg.get('ADMIN_USER', 'admin') and password == cfg.get('ADMIN_PASS', 'password')

def authenticate():
    """发送401响应，要求浏览器进行认证"""
    return Response('Could not verify your access level for that URL.\n'
                    'You have to login with proper credentials', 401,
                    {'WWW-Authenticate': 'Basic realm="Login Required"'})

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

# --- 辅助函数 ---
def get_majority_country(report_data):
    """健壮地分析Factor数据，通过投票找出最可能的国家"""
    try:
        country_codes = report_data.get('Factor', [{}])[0].get('CountryCode', {})
        if not country_codes: raise ValueError("CountryCode data is empty")
        valid_codes = [c for c in country_codes.values() if isinstance(c, str) and len(c) == 2 and c != "N/A"]
        if not valid_codes: raise ValueError("No valid codes")
        most_common_code = Counter(valid_codes).most_common(1)[0][0]
        country_map = {"US": "美国", "JP": "日本", "SG": "新加坡", "HK": "香港", "GB": "英国", "DE": "德国", "FR": "法国", "KR": "韩国", "TW": "台湾", "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "BR": "巴西", "PH": "菲律宾", "SC": "塞舌尔", "CN": "中国"}
        return country_map.get(most_common_code, most_common_code)
    except (IndexError, KeyError, TypeError, ValueError):
        try: return report_data.get('Info', [{}])[0].get('Region', {}).get('Name', 'N/A')
        except: return 'N/A'

def process_clients_data(clients_raw):
    """健壮地处理从数据库获取的原始数据，能识别正常和错误报告"""
    clients_processed = []; regions_set = set()
    for client in clients_raw:
        client_dict = dict(client)
        try:
            report_data = json.loads(client_dict['last_report_data'])
            client_dict['report_data'] = report_data
            info_block = report_data.get('Info', [{}])[0]
            if info_block.get('ASN') == 'ERROR':
                client_dict['is_error'] = True; client_dict['display_region'] = '执行失败'
            else:
                client_dict['is_error'] = False; display_region = get_majority_country(report_data)
                client_dict['display_region'] = display_region
                if display_region and display_region not in ['N/A', '执行失败']: regions_set.add(display_region)
        except (json.JSONDecodeError, TypeError, IndexError):
            client_dict['report_data'] = {"Info": [{"ASN": "ERROR", "Organization": "报告JSON解析失败"}]}
            client_dict['is_error'] = True; client_dict['display_region'] = '数据错误'
        clients_processed.append(client_dict)
    return clients_processed, sorted(list(regions_set))

# --- API 路由 (增加HMAC签名验证) ---
@app.route('/report', methods=['POST'])
def handle_client_report():
    client_ip = request.remote_addr
    print(f"\n--- Received report from IP: {client_ip} ---")
    
    client_key = request.headers.get('X-Client-Key')
    signature_header = request.headers.get('X-Signature')
    
    if not client_key or not signature_header:
        return jsonify({"status": "error", "message": "Missing security headers"}), 403

    try:
        sig_parts = {p.split('=')[0]: p.split('=')[1] for p in signature_header.split(',')}
        timestamp = int(sig_parts['t'])
        client_signature = sig_parts['s']

        if abs(time.time() - timestamp) > 300:
            return jsonify({"status": "error", "message": "Stale request"}), 408

        body = request.get_data()
        message = f"{timestamp}.{body.decode('utf-8')}".encode('utf-8')
        secret = client_key.encode('utf-8')
        server_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(server_signature, client_signature):
            return jsonify({"status": "error", "message": "Invalid signature"}), 403
            
    except Exception as e:
        return jsonify({"status": "error", "message": "Signature verification failed"}), 403
    
    print("Signature verified successfully.")
    report_data = json.loads(body)
    client_port = report_data.get('client_listen_port', 37028)
    database.save_report(client_ip, client_port, client_key, report_data)
    
    print(f"Report from {client_ip} saved successfully.")
    return jsonify({"status": "success"}), 200

# --- Web 界面路由 ---
@app.route('/')
def guest_dashboard():
    clients_raw = database.get_all_clients(); clients_processed, regions = process_clients_data(clients_raw)
    machine_counter = 1
    for client in clients_processed: client['machine_id'] = f"机器-{machine_counter:02d}"; machine_counter += 1
    return render_template('guest_dashboard.html', clients=clients_processed, regions=regions)

@app.route('/cadmin')
@requires_auth
def admin_dashboard():
    sort_by = request.args.get('sort_by', 'time')
    clients_raw = database.get_all_clients(sort_by=sort_by)
    clients_processed, regions = process_clients_data(clients_raw)
    return render_template('cadmin_dashboard.html', clients=clients_processed, regions=regions, current_sort=sort_by)

@app.route('/trigger_retest/<ip>', methods=['POST'])
@requires_auth
def trigger_retest(ip):
    client = database.get_client_by_ip(ip)
    if not client: flash(f"错误：未找到IP为 {ip} 的客户端。", "error"); return redirect(url_for('admin_dashboard'))
    client_url = f"http://{client['ip']}:{client['port']}/retest"; headers = {'X-Server-Key': cfg['SERVER_SECRET_KEY']}
    try:
        response = requests.post(client_url, headers=headers, timeout=15)
        if response.status_code == 200:
            flash(f"客户端 {ip} 确认：检测任务已成功完成。", "success")
        else:
            # 将客户端返回的错误信息显示出来
            error_msg = response.json().get('message', '未知错误')
            flash(f"客户端 {ip} 报告错误: {error_msg}", "error")
    except requests.exceptions.RequestException as e: flash(f"连接客户端 {ip} 失败: {e}", "error")
    return redirect(url_for('admin_dashboard'))

@app.route('/update_remark', methods=['POST'])
@requires_auth
def update_remark():
    ip = request.form.get('ip'); remark = request.form.get('remark')
    if ip: database.update_remark(ip, remark); flash(f"已更新 {ip} 的备注。", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/delete_client/<ip>', methods=['POST'])
@requires_auth
def delete_client(ip):
    database.delete_client_by_ip(ip)
    flash(f"已删除机器 {ip} 的记录。", "success")
    return redirect(url_for('admin_dashboard'))

# --- 启动主程序 ---
if __name__ == '__main__':
    server_port = cfg.get('SERVER_PORT', 28037)
    print(f"主控端启动，将在 http://0.0.0.0:{server_port} 上监听")
    app.run(host='0.0.0.0', port=server_port, debug=False)
