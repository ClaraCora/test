# 文件名: server.py (最终、完整、包含所有功能的版本)
import os
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
cfg = config.load_config()
app.secret_key = cfg.get('FLASK_SECRET_KEY', os.urandom(24))
database.init_db()

app.config['TEMPLATES_AUTO_RELOAD'] = True

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

# --- API 路由 (完整的HMAC验证) ---
@app.route('/report', methods=['POST'])
def handle_client_report():
    client_ip = request.remote_addr
    print(f"\n--- Received report from IP: {client_ip} ---")

    try:
        client_key = request.headers.get('X-Client-Key')
        signature_header = request.headers.get('X-Signature')

        if not client_key or not signature_header:
            print(f"[{client_ip}] REJECTED: Missing security headers.")
            return jsonify({"status": "error", "message": "Missing security headers"}), 403

        sig_parts = {p.split('=')[0]: p.split('=')[1] for p in signature_header.split(',')}
        timestamp = int(sig_parts['t'])
        client_signature = sig_parts['s']

        if abs(time.time() - timestamp) > 300:
            print(f"[{client_ip}] REJECTED: Stale request (timestamp expired).")
            return jsonify({"status": "error", "message": "Stale request"}), 408

        body = request.get_data()
        if not body:
            print(f"[{client_ip}] REJECTED: Empty request body.")
            return jsonify({"status": "error", "message": "Empty request body"}), 400

        message = f"{timestamp}.{body.decode('utf-8')}".encode('utf-8')
        secret = client_key.encode('utf-8')
        server_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

        if not hmac.compare_digest(server_signature, client_signature):
            print(f"[{client_ip}] REJECTED: Invalid signature.")
            return jsonify({"status": "error", "message": "Invalid signature"}), 403

        print(f"[{client_ip}] Signature verified successfully.")

        report_data = json.loads(body)
        client_port = report_data.get('client_listen_port', 37028)

        database.save_report(client_ip, client_port, client_key, report_data)

        print(f"[{client_ip}] Report saved successfully.")
        return jsonify({"status": "success"}), 200

    except json.JSONDecodeError:
        print(f"[{client_ip}] ERROR: Request body is not valid JSON, although signature was correct.")
        return jsonify({"status": "error", "message": "Invalid JSON format in request body"}), 400
    except Exception as e:
        print(f"[{client_ip}] CRITICAL ERROR in /report endpoint: {e}")
        return jsonify({"status": "error", "message": f"Internal Server Error: {e}"}), 500


# --- Web 界面路由 ---
@app.route('/')
def guest_dashboard():
    # 在访客页面，我们仍然可以按编号排序，但显示的是连续的“机器-XX”
    clients_raw = database.get_all_clients(sort_by='id')
    clients_processed, regions = process_clients_data(clients_raw)
    machine_counter = 1
    for client in clients_processed:
        client['machine_id_display'] = f"机器-{machine_counter:02d}"
        machine_counter += 1
    return render_template('guest_dashboard.html', clients=clients_processed, regions=regions)

@app.route('/cadmin')
@requires_auth
def admin_dashboard():
    sort_by = request.args.get('sort_by', 'id') # 默认按编号排序
    clients_raw = database.get_all_clients(sort_by=sort_by)
    clients_processed, regions = process_clients_data(clients_raw)
    return render_template('cadmin_dashboard.html', clients=clients_processed, regions=regions, current_sort=sort_by)

@app.route('/trigger_retest/<ip>', methods=['POST'])
@requires_auth
def trigger_retest(ip):
    # 完整的AJAX请求处理
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    client = database.get_client_by_ip(ip)
    if not client:
        message = f"错误：未找到IP为 {ip} 的客户端。"
        if is_ajax: return jsonify({"status": "error", "message": message}), 404
        else: flash(message, "error"); return redirect(url_for('admin_dashboard'))

    client_url = f"http://{client['ip']}:{client['port']}/retest"
    headers = {'X-Server-Key': cfg['SERVER_SECRET_KEY']}
    status_code, response_data = 200, {}
    try:
        response = requests.post(client_url, headers=headers, timeout=160)
        try: client_response_json = response.json()
        except json.JSONDecodeError: client_response_json = {}
        if response.status_code == 200:
            response_data = {"status": "success", "message": client_response_json.get('message', f"客户端 {ip} 的任务已成功完成。")}
        else:
            status_code = response.status_code if response.status_code >= 400 else 500
            response_data = {"status": "error", "message": f"客户端 {ip} 报告错误: {client_response_json.get('message', response.text)}"}
    except requests.exceptions.RequestException as e:
        status_code = 500
        response_data = {"status": "error", "message": f"连接客户端 {ip} 失败: {e}"}
    if is_ajax: return jsonify(response_data), status_code
    else: flash(response_data['message'], response_data['status']); return redirect(url_for('admin_dashboard'))

@app.route('/update_remark', methods=['POST'])
@requires_auth
def update_remark():
    ip = request.form.get('ip'); remark = request.form.get('remark')
    if ip: database.update_remark(ip, remark); flash(f"已更新 {ip} 的备注。", "success")
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/update_machine_id', methods=['POST'])
@requires_auth
def update_machine_id():
    """处理更新机器编号的请求"""
    ip = request.form.get('ip')
    machine_id_str = request.form.get('machine_id')
    
    if not machine_id_str:
        database.update_machine_id(ip, None)
        flash(f"已清除 {ip} 的机器编号。", "success")
        return redirect(request.referrer or url_for('admin_dashboard'))

    if not machine_id_str.isdigit():
        flash('错误：机器编号必须是一个正整数。', 'error')
        return redirect(request.referrer or url_for('admin_dashboard'))
    
    machine_id = int(machine_id_str)
    database.update_machine_id(ip, machine_id)
    flash(f"已更新 {ip} 的机器编号为 {machine_id}。", "success")
    return redirect(request.referrer or url_for('admin_dashboard'))

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
