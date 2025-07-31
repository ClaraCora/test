# 文件名: server.py (真正完整版 - 适配错误报告)
import json
import requests
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from collections import Counter

# 导入我们自己的模块
import config
import database

# --- 初始化 ---
app = Flask(__name__)
app.secret_key = 'a_random_secret_key_for_flask_session' 
cfg = config.load_config()
database.init_db()


# --- 辅助函数 (重构以增加健壮性) ---

def get_majority_country(report_data):
    """健壮地分析Factor数据，通过投票找出最可能的国家"""
    try:
        # 使用 .get() 链式调用，避免 KeyError
        country_codes = report_data.get('Factor', [{}])[0].get('CountryCode', {})
        if not country_codes:
            raise ValueError("CountryCode data is empty or missing")

        valid_codes = [
            code for code in country_codes.values() 
            if isinstance(code, str) and len(code) == 2 and code != "N/A"
        ]
        
        if not valid_codes:
            raise ValueError("No valid country codes found in Factor")
        
        most_common_code = Counter(valid_codes).most_common(1)[0][0]
        
        country_map = {
            "US": "美国", "JP": "日本", "SG": "新加坡", "HK": "香港", "GB": "英国",
            "DE": "德国", "FR": "法国", "KR": "韩国", "TW": "台湾", "CA": "加拿大",
            "AU": "澳大利亚", "RU": "俄罗斯", "IN": "印度", "BR": "巴西", "PH": "菲律宾",
            "SC": "塞舌尔", "CN": "中国"
        }
        return country_map.get(most_common_code, most_common_code)

    except (IndexError, KeyError, TypeError, ValueError) as e:
        # 如果从Factor提取失败，安全地回退到Info
        print(f"[DEBUG] Failed to get majority country from Factor: {e}. Falling back to Info.")
        try:
            return report_data.get('Info', [{}])[0].get('Region', {}).get('Name', 'N/A')
        except (IndexError, KeyError, TypeError):
            return 'N/A'

def process_clients_data(clients_raw):
    """健壮地处理从数据库获取的原始数据，能识别正常和错误报告"""
    clients_processed = []
    regions_set = set()
    
    for client in clients_raw:
        client_dict = dict(client)
        try:
            report_data = json.loads(client_dict['last_report_data'])
            client_dict['report_data'] = report_data
            
            # 智能判断报告类型
            info_block = report_data.get('Info', [{}])[0]
            if info_block.get('ASN') == 'ERROR':
                client_dict['is_error'] = True
                client_dict['display_region'] = '执行失败'
            else:
                client_dict['is_error'] = False
                display_region = get_majority_country(report_data)
                client_dict['display_region'] = display_region
                if display_region and display_region not in ['N/A', '执行失败']:
                    regions_set.add(display_region)
                
        except (json.JSONDecodeError, TypeError, IndexError):
            print(f"!!! SERVER ERROR: Failed to parse report data for IP {client_dict.get('ip')}.")
            client_dict['report_data'] = {"Info": [{"ASN": "ERROR", "Organization": "报告JSON解析失败"}]}
            client_dict['is_error'] = True
            client_dict['display_region'] = '数据错误'
        
        clients_processed.append(client_dict)
        
    return clients_processed, sorted(list(regions_set))


# --- API 路由 ---
@app.route('/report', methods=['POST'])
def handle_client_report():
    client_ip = request.remote_addr
    print(f"\n--- Received report from IP: {client_ip} ---")
    
    try:
        client_key = request.headers.get('X-Client-Key')
        if not client_key:
            print("!!! REPORT REJECTED: Client key missing.")
            return jsonify({"status": "error", "message": "Client key missing"}), 403

        report_data = request.json
        client_port = report_data.get('client_listen_port', 37028)
        
        print(f"Received data snippet: {str(report_data)[:200]}...")

        database.save_report(client_ip, client_port, client_key, report_data)
        
        print(f"Report from {client_ip} saved successfully.")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"!!! SERVER CRITICAL ERROR in /report endpoint: {e}")
        try:
            print(f"Raw request body: {request.get_data(as_text=True)}")
        except Exception as read_error:
            print(f"Could not read raw request body: {read_error}")
        return jsonify({"status": "error", "message": "Internal Server Error"}), 500


# --- Web 界面路由 ---
@app.route('/')
def guest_dashboard():
    clients_raw = database.get_all_clients()
    clients_processed, regions = process_clients_data(clients_raw)
    machine_counter = 1
    for client in clients_processed:
        client['machine_id'] = f"机器-{machine_counter:02d}"
        machine_counter += 1
    return render_template('guest_dashboard.html', clients=clients_processed, regions=regions)

@app.route('/cadmin')
def admin_dashboard():
    clients_raw = database.get_all_clients()
    clients_processed, regions = process_clients_data(clients_raw)
    return render_template('cadmin_dashboard.html', clients=clients_processed, regions=regions)

@app.route('/trigger_retest/<ip>', methods=['POST'])
def trigger_retest(ip):
    client = database.get_client_by_ip(ip)
    if not client:
        flash(f"错误：未找到IP为 {ip} 的客户端。", "error")
        return redirect(url_for('admin_dashboard'))
        
    client_url = f"http://{client['ip']}:{client['port']}/retest"
    headers = {'X-Server-Key': cfg['SERVER_SECRET_KEY']}
    
    print(f"正在向 {client_url} 发送重测指令...")
    try:
        response = requests.post(client_url, headers=headers, timeout=15)
        if response.status_code == 202:
            flash(f"已成功向 {ip} 发送重测指令。", "success")
        else:
            flash(f"向 {ip} 发送指令失败，客户端响应: {response.status_code}", "error")
    except requests.exceptions.RequestException as e:
        print(f"连接客户端 {ip} 失败: {e}")
        flash(f"连接客户端 {ip} 失败: {e}", "error")
        
    return redirect(url_for('admin_dashboard'))

@app.route('/update_remark', methods=['POST'])
def update_remark():
    ip = request.form.get('ip')
    remark = request.form.get('remark')
    
    if ip:
        database.update_remark(ip, remark)
        flash(f"已更新 {ip} 的备注。", "success")
        
    return redirect(url_for('admin_dashboard'))


# --- 启动主程序 ---
if __name__ == '__main__':
    server_port = cfg.get('SERVER_PORT', 28037)
    print(f"主控端启动，将在 http://0.0.0.0:{server_port} 上监听")
    print(f"访客页面: http://<你的IP>:{server_port}/")
    print(f"管理页面: http://<你的IP>:{server_port}/cadmin")
    app.run(host='0.0.0.0', port=server_port, debug=False)