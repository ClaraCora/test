# 文件名: client.py (阻塞式+超时版)
import os
import json
import subprocess
import threading
import time
import requests
from flask import Flask, request, jsonify

# --- 配置 ---
APP_DIR = '/opt/ip-reporter'
CONFIG_FILE = os.path.join(APP_DIR, 'config.json')
RESULT_FILE = os.path.join(APP_DIR, 'data.json')

app = Flask(__name__)
config = {}

def load_config():
    global config
    if not os.path.exists(CONFIG_FILE): 
        print(f"错误: 配置文件 {CONFIG_FILE} 不存在。")
        exit(1)
    with open(CONFIG_FILE, 'r') as f: 
        config = json.load(f)
    print("配置加载成功。")

def run_ip_check():
    print("开始调用官方脚本生成报告...")
    try:
        if os.path.exists(RESULT_FILE):
            print(f"清理旧的结果文件: {RESULT_FILE}")
            os.remove(RESULT_FILE)

        command_to_run = f"bash <(curl -sL https://IP.Check.Place) -4 -y -n -o {RESULT_FILE}"

        # --- 核心修改点：将超时时间改为120秒 ---
        process = subprocess.run(
            ['/bin/bash', '-c', command_to_run],
            capture_output=True,
            text=True,
            timeout=120 # 2分钟超时
        )
        
        if process.returncode == 0 and os.path.exists(RESULT_FILE):
            print("官方脚本执行成功，并已生成结果文件。")
            return True, "官方脚本执行成功"
        else:
            print(f"官方脚本执行失败。返回码: {process.returncode}")
            error_message = f"官方脚本执行失败，返回码: {process.returncode}\nstderr: {process.stderr}"
            print(error_message)
            # 正常情况下，官方脚本失败也会生成一个错误JSON，所以我们依然尝试读取
            # 但如果连文件都没有，就返回False
            if not os.path.exists(RESULT_FILE):
                return False, error_message
            return True, "官方脚本执行成功（但可能包含错误报告）"
            
    except subprocess.TimeoutExpired:
        error_message = "执行官方脚本超时（超过120秒）。"
        print(error_message)
        return False, error_message
    except Exception as e:
        error_message = f"执行官方脚本时发生未知错误: {e}"
        print(error_message)
        return False, error_message

def send_report_to_server():
    # 这个函数保持不变，只负责上报
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
    headers = {'Content-Type': 'application/json', 'X-Client-Key': config['client_key']}
    report_data['client_listen_port'] = config.get('client_port')
    report_data['client_public_ip'] = config.get('client_public_ip')
    
    print(f"正在后台向 {server_url} 发送报告...")
    try:
        response = requests.post(server_url, headers=headers, json=report_data, timeout=30)
        if response.status_code == 200: 
            print("后台报告发送成功。")
        else: 
            print(f"后台报告发送失败。状态码: {response.status_code}, 响应: {response.text}")
    except requests.exceptions.RequestException as e: 
        print(f"后台报告发送时连接主控端发生错误: {e}")

def initial_and_periodic_report():
    """用于启动时和定时的报告任务，必须是非阻塞的"""
    def task():
        success, _ = run_ip_check()
        if success:
            send_report_to_server()
    threading.Thread(target=task).start()

def periodic_reporter():
    interval_hours = config.get('report_interval_hours', 6)
    interval_seconds = interval_hours * 3600
    print(f"定时报告功能已启动，每 {interval_hours} 小时上报一次。")
    while True:
        time.sleep(interval_seconds)
        print("定时器：开始执行定时上报任务...")
        initial_and_periodic_report() # 调用非阻塞的上报函数

# --- 核心修改点：重构 /retest 路由 ---
@app.route('/retest', methods=['POST'])
def handle_retest_request():
    server_auth_key = request.headers.get('X-Server-Key')
    if not server_auth_key or server_auth_key != config['server_key']: 
        return jsonify({"status": "error", "message": "Forbidden"}), 403
    
    print("收到有效的重测请求，开始阻塞式执行...")
    
    # 直接、阻塞式地调用 run_ip_check
    success, message = run_ip_check()
    
    if success:
        print("阻塞式执行成功，将在后台异步上报结果。")
        # 成功后，启动一个后台线程去上报，以免让主控端等待上报完成
        threading.Thread(target=send_report_to_server).start()
        return jsonify({"status": "success", "message": message}), 200
    else:
        print(f"阻塞式执行失败: {message}")
        return jsonify({"status": "error", "message": message}), 500

if __name__ == '__main__':
    load_config()
    print("客户端启动，执行首次后台上报...")
    initial_and_periodic_report() # 启动时和定时的任务，必须是非阻塞的
    
    reporter_thread = threading.Thread(target=periodic_reporter, daemon=True)
    reporter_thread.start()
    
    print(f"启动监听服务在 0.0.0.0:{config['client_port']}...")
    app.run(host='0.0.0.0', port=config['client_port'])
