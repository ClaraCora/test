# 文件名: database.py
import sqlite3
import json
from datetime import datetime

DATABASE_FILE = 'clients.db'

def get_db_connection():
    """创建并返回一个数据库连接"""
    conn = sqlite3.connect(DATABASE_FILE)
    # 让查询结果可以像字典一样通过列名访问
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """初始化数据库，创建 clients 表（如果不存在）"""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ip TEXT PRIMARY KEY,
            port INTEGER,
            client_key TEXT,
            last_report_data TEXT,
            last_report_time TEXT,
            remark TEXT
        )
    ''')
    conn.commit()
    conn.close()
    print("数据库已初始化。")

def save_report(ip, port, client_key, report_data):
    """
    保存或更新客户端的报告。
    使用 INSERT OR REPLACE 实现"upsert"逻辑。
    """
    conn = get_db_connection()
    
    # 获取当前时间并格式化
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # 将报告数据（字典）转换为JSON字符串以便存储
    report_json_str = json.dumps(report_data)
    
    # 使用参数化查询防止SQL注入
    # 如果IP已存在，REPLACE会替换整行，但我们只更新特定字段
    # 更稳妥的方式是先查，再决定INSERT或UPDATE
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM clients WHERE ip = ?", (ip,))
    existing_client = cursor.fetchone()

    if existing_client:
        # 更新现有记录
        cursor.execute('''
            UPDATE clients 
            SET port = ?, client_key = ?, last_report_data = ?, last_report_time = ?
            WHERE ip = ?
        ''', (port, client_key, report_json_str, now_str, ip))
    else:
        # 插入新记录
        cursor.execute('''
            INSERT INTO clients (ip, port, client_key, last_report_data, last_report_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, port, client_key, report_json_str, now_str))

    conn.commit()
    conn.close()

def get_all_clients():
    """获取所有客户端的最新信息，按时间倒序排列"""
    conn = get_db_connection()
    clients = conn.execute('SELECT * FROM clients ORDER BY last_report_time DESC').fetchall()
    conn.close()
    return clients

def get_client_by_ip(ip):
    """根据IP获取单个客户端的信息"""
    conn = get_db_connection()
    client = conn.execute('SELECT * FROM clients WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    return client

def update_remark(ip, remark):
    """更新指定IP客户端的备注名"""
    conn = get_db_connection()
    conn.execute('UPDATE clients SET remark = ? WHERE ip = ?', (remark, ip))
    conn.commit()
    conn.close()