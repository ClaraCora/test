#!/bin/bash
# ==============================================================================
#  统一管理脚本 (v18 - 完全无编译Python部署版)
# ==============================================================================

set -e

# --- 全局配置 ---
# Server 配置
SERVER_INSTALL_DIR="/opt/main-server"
SERVER_CONFIG_FILE="$SERVER_INSTALL_DIR/server-config.json"
SERVER_PY_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/server.py"       # <-- 修改: server.py 脚本的URL
SERVER_DB_PY_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/database.py"   # <-- 修改: database.py 脚本的URL
SERVER_CFG_PY_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/config.py"    # <-- 修改: config.py 脚本的URL
SERVER_HTML_ADMIN_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/templates/cadmin_dashboard.html" # <-- 修改: 管理员模板URL
SERVER_HTML_GUEST_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/templates/guest_dashboard.html" # <-- 修改: 访客模板URL
SERVER_CSS_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/server/static/style.css"       # <-- 修改: CSS文件URL
SERVER_SERVICE_NAME="main-server.service"
SERVER_SERVICE_FILE="/etc/systemd/system/$SERVER_SERVICE_NAME"

# Client 配置
CLIENT_INSTALL_DIR="/opt/ip-reporter"
CLIENT_CONFIG_FILE="$CLIENT_INSTALL_DIR/config.json"
CLIENT_PY_URL="https://raw.githubusercontent.com/ClaraCora/test/refs/heads/main/client.py"       # <-- 修改: client.py 脚本的URL
CLIENT_SERVICE_NAME="ip-reporter.service"
CLIENT_SERVICE_FILE="/etc/systemd/system/$CLIENT_SERVICE_NAME"

# --- 权限检查 ---
if [ "$(id -u)" != "0" ]; then echo "错误：此脚本必须以 root 用户身份运行。" 1>&2; exit 1; fi

# --- 通用函数 ---
press_any_key() { read -p "按 [Enter] 键返回..."; }
check_url() { if curl --head -s -f -o /dev/null "$1"; then return 0; else return 1; fi; }

# --- Server 相关函数 (全新重构) ---
check_server_installed() { [ -f "$SERVER_SERVICE_FILE" ]; }

update_server() {
    echo "--- 开始更新主控端 (Server) ---"
    # 检查所有URL
    if ! check_url "$SERVER_PY_URL" || ! check_url "$SERVER_DB_PY_URL" || ! check_url "$SERVER_CFG_PY_URL" || \
       ! check_url "$SERVER_HTML_ADMIN_URL" || ! check_url "$SERVER_HTML_GUEST_URL" || ! check_url "$SERVER_CSS_URL"; then
        echo "错误：一个或多个主控端文件URL无效，请检查脚本配置。"; return;
    fi
    systemctl stop "$SERVER_SERVICE_NAME"
    echo "--> 正在下载更新文件..."
    # 下载到.new，成功后再替换
    curl -L -o "$SERVER_INSTALL_DIR/src/server.py.new" "$SERVER_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/database.py.new" "$SERVER_DB_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/config.py.new" "$SERVER_CFG_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/templates/cadmin_dashboard.html.new" "$SERVER_HTML_ADMIN_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/templates/guest_dashboard.html.new" "$SERVER_HTML_GUEST_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/static/style.css.new" "$SERVER_CSS_URL"
    
    # 替换旧文件
    mv "$SERVER_INSTALL_DIR/src/server.py.new" "$SERVER_INSTALL_DIR/src/server.py"
    mv "$SERVER_INSTALL_DIR/src/database.py.new" "$SERVER_INSTALL_DIR/src/database.py"
    mv "$SERVER_INSTALL_DIR/src/config.py.new" "$SERVER_INSTALL_DIR/src/config.py"
    mv "$SERVER_INSTALL_DIR/src/templates/cadmin_dashboard.html.new" "$SERVER_INSTALL_DIR/src/templates/cadmin_dashboard.html"
    mv "$SERVER_INSTALL_DIR/src/templates/guest_dashboard.html.new" "$SERVER_INSTALL_DIR/src/templates/guest_dashboard.html"
    mv "$SERVER_INSTALL_DIR/src/static/style.css.new" "$SERVER_INSTALL_DIR/src/static/style.css"

    # 更新Python库
    echo "--> 正在更新Python依赖库..."
    "$SERVER_INSTALL_DIR/venv/bin/pip" install --upgrade flask requests
    
    systemctl start "$SERVER_SERVICE_NAME"
    echo "主控端更新完成！"; sleep 2; systemctl status "$SERVER_SERVICE_NAME" --no-pager
}

install_server() {
    if check_server_installed; then echo "主控端已安装。"; return; fi
    echo "--- 开始安装主控端 (Server) ---"
    echo "--> 正在安装核心依赖 (Python3, pip, venv, curl)..."
    if [ -f /etc/debian_version ]; then export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y python3 python3-pip python3-venv curl;
    elif [ -f /etc/redhat-release ]; then yum install -y python3 python3-pip python3-virtualenv curl; fi
    
    echo "--> 正在创建目录结构..."
    mkdir -p "$SERVER_INSTALL_DIR/src/templates"
    mkdir -p "$SERVER_INSTALL_DIR/src/static"
    cd "$SERVER_INSTALL_DIR"

    echo "--> 正在创建Python虚拟环境并安装库..."
    python3 -m venv venv
    "$SERVER_INSTALL_DIR/venv/bin/pip" install flask requests
    
    echo "--> 正在下载主控端所有脚本文件..."
    curl -L -o "$SERVER_INSTALL_DIR/src/server.py" "$SERVER_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/database.py" "$SERVER_DB_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/config.py" "$SERVER_CFG_PY_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/templates/cadmin_dashboard.html" "$SERVER_HTML_ADMIN_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/templates/guest_dashboard.html" "$SERVER_HTML_GUEST_URL"
    curl -L -o "$SERVER_INSTALL_DIR/src/static/style.css" "$SERVER_CSS_URL"

    echo "--> 正在创建 systemd 服务..."
    PYTHON_EXEC="$SERVER_INSTALL_DIR/venv/bin/python"
    # 工作目录是 src 文件夹
    printf "[Unit]\nDescription=Main Control Server\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nWorkingDirectory=%s/src\nExecStart=%s %s/src/server.py\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n" \
        "$SERVER_INSTALL_DIR" "$PYTHON_EXEC" "$SERVER_INSTALL_DIR" > "$SERVER_SERVICE_FILE"
        
    echo "--> 正在启动服务..."
    systemctl daemon-reload; systemctl enable "$SERVER_SERVICE_NAME"; systemctl start "$SERVER_SERVICE_NAME"
    echo "主控端安装完成！"; sleep 3; systemctl status "$SERVER_SERVICE_NAME" --no-pager
}

manage_server() { if ! check_server_installed; then echo "主控端未安装。"; return; fi; while true; do clear; echo "--- 主控端管理菜单 ---"; systemctl status $SERVER_SERVICE_NAME --no-pager | grep "Active:"; echo "------------------------"; echo "1. 重启服务"; echo "2. 查看实时日志"; echo "3. 更新主控端程序"; echo "4. 查询通讯密钥"; echo "5. 卸载主控端"; echo "0. 返回主菜单"; read -p "请输入选择: " choice; case "$choice" in 1) systemctl restart "$SERVER_SERVICE_NAME"; echo "服务已重启。"; sleep 1; press_any_key ;; 2) journalctl -u "$SERVER_SERVICE_NAME" -f ;; 3) update_server; press_any_key ;; 4) if ! command -v jq &> /dev/null; then if [ -f /etc/debian_version ]; then apt-get install -y jq; elif [ -f /etc/redhat-release ]; then yum install -y jq; fi; fi; if [ -f "$SERVER_CONFIG_FILE" ]; then SECRET_KEY=$(jq -r '.SERVER_SECRET_KEY' "$SERVER_CONFIG_FILE"); echo "密钥是: $SECRET_KEY"; else echo "错误：找不到配置文件"; fi; press_any_key ;; 5) read -p "确定卸载吗？[y/N]: " confirm; if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then systemctl stop "$SERVER_SERVICE_NAME" 2>/dev/null || true; systemctl disable "$SERVER_SERVICE_NAME" 2>/dev/null || true; rm -f "$SERVER_SERVICE_FILE"; read -p "警告：是否删除安装目录($SERVER_INSTALL_DIR)？[y/N]: " del_confirm; if [[ "$del_confirm" == "y" || "$del_confirm" == "Y" ]]; then rm -rf "$SERVER_INSTALL_DIR"; fi; systemctl daemon-reload; echo "已卸载。"; press_any_key; return; fi ;; 0) return ;; *) echo "无效输入。"; sleep 1 ;; esac; done; }

# --- Client 相关函数 (保持不变) ---
check_client_installed() { [ -f "$CLIENT_SERVICE_FILE" ]; }
update_client() { if ! check_url "$CLIENT_PY_URL"; then echo "错误：无法访问 client.py 的URL。"; return; fi; systemctl stop "$CLIENT_SERVICE_NAME"; echo "--> 正在下载新的 client.py 脚本..."; curl -L -o "$CLIENT_INSTALL_DIR/client.py" "$CLIENT_PY_URL"; if ! grep -q "import os" "$CLIENT_INSTALL_DIR/client.py"; then echo "错误：下载的 client.py 文件内容不正确！"; systemctl start "$CLIENT_SERVICE_NAME"; return; fi; systemctl start "$CLIENT_SERVICE_NAME"; echo "客户端更新完成！"; sleep 2; systemctl status "$CLIENT_SERVICE_NAME" --no-pager; }
install_client() { if check_client_installed; then echo "客户端已安装。"; return; fi; echo "--- 开始安装客户端 (Client) ---"; echo "--> 正在安装核心依赖..."; if [ -f /etc/debian_version ]; then export DEBIAN_FRONTEND=noninteractive; apt-get update -y; apt-get install -y python3 python3-pip python3-venv curl jq; elif [ -f /etc/redhat-release ]; then yum install -y python3 python3-pip python3-virtualenv curl jq; fi; mkdir -p "$CLIENT_INSTALL_DIR"; cd "$CLIENT_INSTALL_DIR"; echo "--> 正在创建Python虚拟环境..."; python3 -m venv venv; echo "--> 正在虚拟环境中安装Python库..."; "$CLIENT_INSTALL_DIR/venv/bin/pip" install flask requests; echo "--> 开始配置..."; PUBLIC_IP=$(curl -s4 ifconfig.me); [ -z "$PUBLIC_IP" ] && read -p "无法自动获取IP: " PUBLIC_IP; CLIENT_KEY=$(cat /proc/sys/kernel/random/uuid); while [ -z "$SERVER_HOST" ]; do read -p "请输入主控端IP或域名: " SERVER_HOST; done; read -p "请输入主控端端口 [28037]: " SERVER_PORT; SERVER_PORT=${SERVER_PORT:-28037}; while [ -z "$SERVER_KEY" ]; do read -p "请输入主控通讯密钥: " SERVER_KEY; done; echo "--> 正在生成配置文件..."; printf '{\n  "client_public_ip": "%s",\n  "client_port": 37028,\n  "client_key": "%s",\n  "server_host": "%s",\n  "server_port": %d,\n  "server_key": "%s",\n  "report_interval_hours": 6\n}\n' "$PUBLIC_IP" "$CLIENT_KEY" "$SERVER_HOST" "$SERVER_PORT" "$SERVER_KEY" > "$CLIENT_CONFIG_FILE"; echo "--> 正在下载 client.py 脚本..."; curl -L -o "$CLIENT_INSTALL_DIR/client.py" "$CLIENT_PY_URL"; if ! grep -q "import os" "$CLIENT_INSTALL_DIR/client.py"; then echo "错误：下载的 client.py 文件内容不正确！安装中止。"; rm -rf "$CLIENT_INSTALL_DIR"; exit 1; fi; echo "--> 正在创建并启动服务..."; PYTHON_EXEC="$CLIENT_INSTALL_DIR/venv/bin/python"; printf "[Unit]\nDescription=IP Reporter Client Service\nAfter=network.target\n\n[Service]\nType=simple\nUser=root\nWorkingDirectory=%s\nExecStart=%s %s/client.py\nRestart=always\nRestartSec=10\n\n[Install]\nWantedBy=multi-user.target\n" "$CLIENT_INSTALL_DIR" "$PYTHON_EXEC" "$CLIENT_INSTALL_DIR" > "$CLIENT_SERVICE_FILE"; systemctl daemon-reload; systemctl enable "$CLIENT_SERVICE_NAME"; systemctl start "$CLIENT_SERVICE_NAME"; echo "客户端安装完成！"; sleep 2; systemctl status "$CLIENT_SERVICE_NAME" --no-pager; }
manage_client() { if ! check_client_installed; then echo "客户端未安装。"; return; fi; while true; do clear; echo "--- 客户端管理菜单 ---"; systemctl status $CLIENT_SERVICE_NAME --no-pager | grep "Active:"; echo "------------------------"; echo "1. 重启服务"; echo "2. 查看实时日志"; echo "3. 更新 client.py 脚本"; echo "4. 修改监听端口"; echo "5. 卸载客户端"; echo "0. 返回主菜单"; read -p "请输入选择: " choice; case "$choice" in 1) systemctl restart "$CLIENT_SERVICE_NAME"; echo "服务已重启。"; sleep 1; press_any_key ;; 2) journalctl -u "$CLIENT_SERVICE_NAME" -f ;; 3) update_client; press_any_key ;; 4) if ! command -v jq &> /dev/null; then if [ -f /etc/debian_version ]; then apt-get install -y jq; elif [ -f /etc/redhat-release ]; then yum install -y jq; fi; fi; current_port=$(jq '.client_port' "$CLIENT_CONFIG_FILE"); echo "当前端口: $current_port"; read -p "新端口: " new_port; if [[ "$new_port" =~ ^[0-9]+$ ]] && [ "$new_port" -ge 1024 ] && [ "$new_port" -le 65535 ]; then tmp_file=$(mktemp); jq --argjson p "$new_port" '.client_port = $p' "$CLIENT_CONFIG_FILE" > "$tmp_file"; mv "$tmp_file" "$CLIENT_CONFIG_FILE"; systemctl restart "$CLIENT_SERVICE_NAME"; echo "已修改。"; else echo "无效输入。"; fi; press_any_key ;; 5) read -p "确定卸载吗？[y/N]: " confirm; if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then systemctl stop "$CLIENT_SERVICE_NAME" 2>/dev/null || true; systemctl disable "$CLIENT_SERVICE_NAME" 2>/dev/null || true; rm -f "$CLIENT_SERVICE_FILE"; rm -rf "$CLIENT_INSTALL_DIR"; systemctl daemon-reload; echo "已卸载。"; press_any_key; return; fi ;; 0) return ;; *) echo "无效输入。"; sleep 1 ;; esac; done; }

# --- 主菜单 ---
main_menu() { while true; do clear; echo "==================================================="; echo "      Server / Client 统一安装管理脚本"; echo "==================================================="; echo; echo "请选择要对本机进行的操作:"; echo; echo "--- 安装选项 ---"; echo "1. 安装主控端 (Server)"; echo "2. 安装客户端 (Client)"; echo; echo "--- 管理选项 ---"; if check_server_installed; then echo -e "3. 管理已安装的主控端 \e[32m(已安装)\e[0m"; else echo -e "3. 管理已安装的主控端 \e[31m(未安装)\e[0m"; fi; if check_client_installed; then echo -e "4. 管理已安装的客户端 \e[32m(已安装)\e[0m"; else echo -e "4. 管理已安装的客户端 \e[31m(未安装)\e[0m"; fi; echo; echo "0. 退出脚本"; echo "---------------------------------------------------"; read -p "请输入您的选择: " choice; case "$choice" in 1) install_server; press_any_key ;; 2) install_client; press_any_key ;; 3) manage_server ;; 4) manage_client ;; 0) exit 0 ;; *) echo "无效输入，请重新选择。"; sleep 1 ;; esac; done; }

# --- 脚本入口 ---
main_menu
