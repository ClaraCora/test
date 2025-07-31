# 文件名: server.py (最终、完整、带精确验证逻辑)
import os
import json
import re
import requests
import hmac
import hashlib
import time
import threading
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


# --- 1. 定义一个有效国家代码的集合，用于快速查找 ---
VALID_COUNTRY_CODES = {
    "US", "GB", "JP", "HK", "SG", "TW", "CA", "AU", "DE", "FR", "KR", 
    "RU", "IN", "BR", "PH", "SC", "CN", "NF" # NF是Netflix自制剧的常见代码
}

def clean_and_validate_region_code(text):
    """
    根据您的逻辑重写的全新函数：
    1. 只保留输入字符串中的大写英文字母。
    2. 检查结果是否为2个字符。
    3. 检查结果是否存在于我们的有效国家代码列表中。
    4. 如果任一步骤失败，返回 'N/A'。
    """
    if not isinstance(text, str):
        return "N/A"
    
    # 步骤1：只保留大写英文字母
    letters_only = re.sub(r'[^A-Z]', '', text)
    
    # 步骤2：检查长度是否为2
    if len(letters_only) != 2:
        return "N/A"
        
    # 步骤3：检查是否为有效的国家代码
    if letters_only not in VALID_COUNTRY_CODES:
        return "N/A"
        
    # 所有检查通过，返回干净的代码
    return letters_only


# --- 安全功能：HTTP基础认证 ---
def check_auth(username, password):
    return username == cfg.get('ADMIN_USER', 'admin') and password == cfg.get('ADMIN_PASS', 'password')

def authenticate():
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
    clients_processed = []; regions_set = set()
    for client in clients_raw:
        client_dict = dict(client)
        try:
            report_data = json.loads(client_dict['last_report_data'])
            
            # --- 2. 在这里使用我们全新的验证函数 ---
            if 'Media' in report_data and report_data['Media']:
                media_info = report_data['Media'][0]
                for service_details in media_info.values():
                    if isinstance(service_details, dict) and 'Region' in service_details:
                        validated_region = clean_and_validate_region_code(service_details['Region'])
                        service_details['Region'] = validated_region
            
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

# --- API 路由 ---
@app.route('/report', methods=['POST'])
def handle_client_report():
    # ... (此函数无需修改) ...
    client_ip = request.remote_addr
    try:
        client_key = request.headers.get('X-Client-Key')
        signature_header = request.headers.get('X-Signature')
        if not client_key or not signature_header: return jsonify({"status": "error", "message": "Missing security headers"}), 403
        sig_parts = {p.split('=')[0]: p.split('=')[1] for p in signature_header.split(',')}
        timestamp = int(sig_parts['t'])
        client_signature = sig_parts['s']
        if abs(time.time() - timestamp) > 300: return jsonify({"status": "error", "message": "Stale request"}), 408
        body = request.get_data()
        if not body: return jsonify({"status": "error", "message": "Empty request body"}), 400
        message = f"{timestamp}.{body.decode('utf-8')}".encode('utf-8')
        secret = client_key.encode('utf-8')
        server_signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(server_signature, client_signature): return jsonify({"status": "error", "message": "Invalid signature"}), 403
        report_data = json.loads(body)
        client_port = report_data.get('client_listen_port', 37028)
        database.save_report(client_ip, client_port, client_key, report_data)
        return jsonify({"status": "success"}), 200
    except Exception as e: return jsonify({"status": "error", "message": f"Internal Server Error: {e}"}), 500

# --- Web 界面路由 ---
@app.route('/')
def guest_dashboard():
    # ... (此函数无需修改) ...
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
    # ... (此函数无需修改) ...
    sort_by = request.args.get('sort_by', 'id')
    clients_raw = database.get_all_clients(sort_by=sort_by)
    clients_processed, regions = process_clients_data(clients_raw)
    return render_template('cadmin_dashboard.html', clients=clients_processed, regions=regions, current_sort=sort_by)

def trigger_retest_internal(ip, port):
    """内部函数，用于触发重测，不处理Web请求"""
    client_url = f"http://{ip}:{port}/retest"
    headers = {'X-Server-Key': cfg['SERVER_SECRET_KEY']}
    try:
        response = requests.post(client_url, headers=headers, timeout=20)
        if response.status_code == 200 or response.status_code == 202:
            print(f"AUTO-RETEST: 成功向 {ip} 发送重测指令。")
            return True
        else:
            print(f"AUTO-RETEST: 客户端 {ip} 拒绝指令，状态码: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print(f"AUTO-RETEST: 连接客户端 {ip} 失败: {e}")
        return False

@app.route('/trigger_retest/<ip>', methods=['POST'])
@requires_auth
def trigger_retest(ip):
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    client = database.get_client_by_ip(ip)
    if not client:
        message = f"错误：未找到IP为 {ip} 的客户端。"
        if is_ajax: return jsonify({"status": "error", "message": message}), 404
        else: flash(message, "error"); return redirect(url_for('admin_dashboard'))
    
    success = trigger_retest_internal(client['ip'], client['port'])
    
    if success:
        response_data = {"status": "success", "message": f"已向客户端 {ip} 发送重测指令。请稍后刷新查看结果。"}
        status_code = 200
    else:
        response_data = {"status": "error", "message": f"向客户端 {ip} 发送指令失败，请检查日志。"}
        status_code = 500

    if is_ajax: return jsonify(response_data), status_code
    else: flash(response_data['message'], response_data['status']); return redirect(url_for('admin_dashboard'))

@app.route('/update_remark', methods=['POST'])
@requires_auth
def update_remark():
    # ... (此函数无需修改) ...
    ip = request.form.get('ip'); remark = request.form.get('remark')
    if ip: database.update_remark(ip, remark); flash(f"已更新 {ip} 的备注。", "success")
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/update_machine_id', methods=['POST'])
@requires_auth
def update_machine_id():
    # ... (此函数无需修改) ...
    ip = request.form.get('ip')
    machine_id_str = request.form.get('machine_id')
    if not machine_id_str:
        database.update_machine_id(ip, None)
        flash(f"已清除 {ip} 的机器编号。", "success")
    elif not machine_id_str.isdigit():
        flash('错误：机器编号必须是一个正整数。', 'error')
    else:
        machine_id = int(machine_id_str)
        database.update_machine_id(ip, machine_id)
        flash(f"已更新 {ip} 的机器编号为 {machine_id}。", "success")
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/delete_client/<ip>', methods=['POST'])
@requires_auth
def delete_client(ip):
    # ... (此函数无需修改) ...
    database.delete_client_by_ip(ip)
    flash(f"已删除机器 {ip} 的记录。", "success")
    return redirect(url_for('admin_dashboard'))

# --- 后台健康检查与自动重测的函数 ---
def health_checker():
    """
    后台线程，每10分钟检查一次所有客户端的状态。
    如果发现有客户端的报告是“执行失败”，则自动触发一次重测。
    """
    print("后台健康检查线程已启动。")
    while True:
        time.sleep(600) # 暂停10分钟
        print("\n--- HEALTH CHECK: 开始检查失败节点 ---")
        
        try:
            clients_raw = database.get_all_clients()
            failed_clients = []
            for client in clients_raw:
                try:
                    report_data = json.loads(client['last_report_data'])
                    if report_data.get('Info', [{}])[0].get('ASN') == 'ERROR':
                        failed_clients.append(dict(client))
                except (json.JSONDecodeError, IndexError):
                    failed_clients.append(dict(client))
            
            if not failed_clients:
                print("HEALTH CHECK: 未发现失败节点。")
            else:
                print(f"HEALTH CHECK: 发现 {len(failed_clients)} 个失败节点，将尝试触发重测...")
                for client_to_retest in failed_clients:
                    print(f"HEALTH CHECK: 正在为 {client_to_retest['ip']} 触发重测...")
                    trigger_retest_internal(client_to_retest['ip'], client_to_retest['port'])
                    time.sleep(5)
            
            print("--- HEALTH CHECK: 检查完成 ---")

        except Exception as e:
            print(f"HEALTH CHECK: 执行检查时发生严重错误: {e}")


# --- 启动主程序 ---
if __name__ == '__main__':
    checker_thread = threading.Thread(target=health_checker, daemon=True)
    checker_thread.start()

    server_port = cfg.get('SERVER_PORT', 28037)
    print(f"主控端启动，将在 http://0.0.0.0:{server_port} 上监听")
    app.run(host='0.0.0.0', port=server_port, debug=False)
