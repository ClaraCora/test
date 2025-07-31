# 文件名: client.py (最终、完整、异步任务版)
import os
import json
import subprocess
import threading
import time
import requests
import hmac
import hashlib
from flask import Flask, request, jsonify

# --- 配置 ---
APP_DIR = '/opt/ip-reporter'
CONFIG_FILE = os.path.join(APP_DIR, 'config.json')
RESULT_FILE = os.path.join(APP_DIR, 'data.json')

app = Flask(__name__)
config = {}

def load_config():
    """加载配置文件"""
    global config
    if not os.path.exists(CONFIG_FILE):
        print(f"错误: 配置文件 {CONFIG_FILE} 不存在。")
        exit(1)
    with open(CONFIG_FILE, 'r') as f:
        config = json.load(f)
    print("配置加载成功。")

def run_ip_check():
    """执行官方脚本生成报告，并确保结果是有效的JSON"""
    print("开始调用官方脚本生成报告...")
    try:
        if os.path.exists(RESULT_FILE):
            os.remove(RESULT_FILE)

        command_to_run = f"LC_ALL=C.UTF-8 LANG=C.UTF-8 bash <(curl -sL https://IP.Check.Place) -4 -y -n -o {RESULT_FILE}"

        process = subprocess.run(
            ['/bin/bash', '-c', command_to_run],
            capture_output=True,
            text=True,
            timeout=300
        )

        if not os.path.exists(RESULT_FILE):
            print(f"官方脚本执行后结果文件不存在。返回码: {process.returncode}")
            error_report = { "Info": [{"ASN": "ERROR", "Organization": f"脚本执行后未生成文件, 返回码: {process.returncode}"}], "ErrorLog": { "stdout": process.stdout, "stderr": process.stderr } }
            with open(RESULT_FILE, 'w', encoding='utf-8') as f: json.dump(error_report, f, ensure_ascii=False)
            return True

        try:
            with open(RESULT_FILE, 'r', encoding='utf-8') as f: json.load(f)
            print("官方脚本执行成功，结果文件是有效的UTF-8 JSON。")
            return True
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            print(f"官方脚本生成的结果文件无效或编码错误: {e}。")
            error_report = { "Info": [{"ASN": "ERROR", "Organization": f"脚本生成了无效的JSON文件: {e}"}], "ErrorLog": { "stdout": process.stdout, "stderr": process.stderr } }
            with open(RESULT_FILE, 'w', encoding='utf-8') as f: json.dump(error_report, f, ensure_ascii=False)
            return True

    except subprocess.TimeoutExpired:
        print("执行官方脚本超时。")
        error_report = { "Info": [{"ASN": "ERROR", "Organization": "执行官方脚本超时"}] }
        with open(RESULT_FILE, 'w', encoding='utf-8') as f: json.dump(error_report, f, ensure_ascii=False)
        return True
    except Exception as e:
        print(f"执行官方脚本时发生未知错误: {e}")
        return False

def send_report_to_server():
    """读取结果并将其签名后发送到主控端"""
    if not os.path.exists(RESULT_FILE): return
    try:
        with open(RESULT_FILE, 'r', encoding='utf-8') as f: report_data = json.load(f)
    except (json.JSONDecodeError, UnicodeDecodeError): return

    server_url = f"http://{config['server_host']}:{config['server_port']}/report"
    report_data['client_listen_port'] = config.get('client_port')
    report_data['client_public_ip'] = config.get('client_public_ip')
    body = json.dumps(report_data, separators=(',', ':'), sort_keys=True, ensure_ascii=False).encode('utf-8')
    timestamp = str(int(time.time()))
    client_key = config['client_key']
    message = f"{timestamp}.{body.decode('utf-8')}".encode('utf-8')
    secret = client_key.encode('utf-8')
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()
    headers = { 'Content-Type': 'application/json; charset=utf-8', 'X-Client-Key': client_key, 'X-Signature': f"t={timestamp},s={signature}" }
    
    print(f"正在向 {server_url} 发送报告...")
    try:
        response = requests.post(server_url, data=body, headers=headers, timeout=30)
        if response.status_code == 200: print("报告成功发送。")
        else: print(f"发送报告失败。状态码: {response.status_code}, 响应: {response.text}")
    except requests.exceptions.RequestException as e: print(f"连接主控端时发生错误: {e}")

def run_and_report_task():
    """封装了“执行检测并上报”的完整后台任务"""
    print("后台任务启动：开始执行检测...")
    if run_ip_check():
        print("后台任务：检测完成，开始上报...")
        send_report_to_server()
    else:
        print("后台任务：检测执行时发生严重错误，无法上报。")

def periodic_reporter():
    """后台定时报告器"""
    interval_hours = config.get('report_interval_hours', 6)
    interval_seconds = interval_hours * 3600
    print(f"定时报告功能已启动，每 {interval_hours} 小时上报一次。")
    while True:
        time.sleep(interval_seconds)
        print("定时器：开始执行定时上报任务...")
        # 定时任务也使用后台线程，避免长时间阻塞定时器
        threading.Thread(target=run_and_report_task).start()

@app.route('/retest', methods=['POST'])
def handle_retest_request():
    """处理来自主控端的重测请求 (异步)"""
    server_auth_key = request.headers.get('X-Server-Key')
    if not server_auth_key or server_auth_key != config['server_key']:
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    
    print("收到有效的重测请求，将在后台启动任务。")
    
    # --- 核心修改点：不直接执行，而是启动一个后台线程 ---
    task_thread = threading.Thread(target=run_and_report_task)
    task_thread.start()
    
    # --- 立即返回202 Accepted响应，告诉主控端“指令已收到，正在处理” ---
    return jsonify({
        "status": "accepted", 
        "message": "重测任务已接受并在后台运行。"
    }), 202

if __name__ == '__main__':
    load_config()
    print("客户端启动，执行首次后台上报...")
    threading.Thread(target=run_and_report_task).start()
    
    reporter_thread = threading.Thread(target=periodic_reporter, daemon=True)
    reporter_thread.start()
    
    print(f"启动监听服务在 0.0.0.0:{config['client_port']}...")
    app.run(host='0.0.0.0', port=config['client_port'])
