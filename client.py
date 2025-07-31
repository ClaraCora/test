# 文件名: client.py (v_secure - 增加HMAC签名)
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
    """执行官方脚本生成报告"""
    print("开始调用官方脚本生成报告...")
    try:
        if os.path.exists(RESULT_FILE):
            os.remove(RESULT_FILE)

        command_to_run = f"bash <(curl -sL https://IP.Check.Place) -4 -y -n -o {RESULT_FILE}"
        
        process = subprocess.run(
            ['/bin/bash', '-c', command_to_run],
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if process.returncode == 0 and os.path.exists(RESULT_FILE):
            print("官方脚本执行成功。")
            return True
        else:
            print(f"官方脚本执行失败。返回码: {process.returncode}")
            error_report = {
                "Head": [{"IP": config.get('client_public_ip', 'Unknown'), "Version": "OFFICIAL_SCRIPT_ERROR"}],
                "Info": [{"ASN": "ERROR", "Organization": f"官方脚本执行失败，返回码: {process.returncode}"}],
                "ErrorLog": { "stdout": process.stdout, "stderr": process.stderr }
            }
            with open(RESULT_FILE, 'w') as f:
                json.dump(error_report, f)
            return True
            
    except Exception as e:
        print(f"执行官方脚本时发生未知错误: {e}")
        return False

def send_report_to_server():
    """读取结果并将其签名后发送到主控端"""
    if not os.path.exists(RESULT_FILE): 
        print(f"结果文件 {RESULT_FILE} 不存在，无法上报。")
        return
    try:
        with open(RESULT_FILE, 'r') as f: 
            report_data = json.load(f)
    except json.JSONDecodeError:
        print(f"错误：无法解析结果文件 {RESULT_FILE}。")
        return
        
    server_url = f"http://{config['server_host']}:{config['server_port']}/report"
    
    # 1. 准备数据
    report_data['client_listen_port'] = config.get('client_port')
    report_data['client_public_ip'] = config.get('client_public_ip')
    body = json.dumps(report_data, separators=(',', ':'), sort_keys=True).encode('utf-8')
    timestamp = str(int(time.time()))
    client_key = config['client_key']

    # 2. 创建签名
    message = f"{timestamp}.{body.decode('utf-8')}".encode('utf-8')
    secret = client_key.encode('utf-8')
    signature = hmac.new(secret, message, hashlib.sha256).hexdigest()

    # 3. 构建请求头
    headers = {
        'Content-Type': 'application/json',
        'X-Client-Key': client_key,
        'X-Signature': f"t={timestamp},s={signature}"
    }
    
    print(f"正在向 {server_url} 发送已签名的报告...")
    try:
        response = requests.post(server_url, data=body, headers=headers, timeout=30)
        if response.status_code == 200: 
            print("报告成功发送到主控端。")
        else: 
            print(f"发送报告失败。状态码: {response.status_code}, 响应: {response.text}")
    except requests.exceptions.RequestException as e: 
        print(f"连接主控端时发生错误: {e}")

def retest_and_report():
    """用于启动时和定时的非阻塞报告任务"""
    def task():
        if run_ip_check():
            send_report_to_server()
    threading.Thread(target=task).start()

def periodic_reporter():
    """后台定时报告器"""
    interval_hours = config.get('report_interval_hours', 6)
    interval_seconds = interval_hours * 3600
    print(f"定时报告功能已启动，每 {interval_hours} 小时上报一次。")
    while True:
        time.sleep(interval_seconds)
        print("定时器：开始执行定时上报任务...")
        retest_and_report()

@app.route('/retest', methods=['POST'])
def handle_retest_request():
    """处理来自主控端的重测请求 (阻塞式)"""
    server_auth_key = request.headers.get('X-Server-Key')
    if not server_auth_key or server_auth_key != config['server_key']: 
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    
    print("收到有效的重测请求，开始阻塞式执行...")
    
    # 直接调用 run_ip_check 并等待其完成
    success = run_ip_check()
    
    if success:
        print("阻塞式执行成功，将在后台异步上报结果。")
        # 成功后，启动一个后台线程去上报
        threading.Thread(target=send_report_to_server).start()
        return jsonify({"status": "success", "message": "检测任务已成功完成"}), 200
    else:
        # run_ip_check 内部已经生成了错误报告，这里也认为是“成功”启动了任务
        # 但返回一个服务器错误码，让主控端知道执行层面有问题
        print(f"阻塞式执行失败。")
        threading.Thread(target=send_report_to_server).start()
        return jsonify({"status": "error", "message": "检测脚本执行失败，请检查主控端日志"}), 500

if __name__ == '__main__':
    load_config()
    print("客户端启动，执行首次后台上报...")
    retest_and_report()
    
    reporter_thread = threading.Thread(target=periodic_reporter, daemon=True)
    reporter_thread.start()
    
    print(f"启动监听服务在 0.0.0.0:{config['client_port']}...")
    app.run(host='0.0.0.0', port=config['client_port'])
