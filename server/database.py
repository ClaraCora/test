# 文件名: database.py (增加 machine_id 字段和排序逻辑)
import sqlite3
import json
from datetime import datetime

DATABASE_FILE = 'clients.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    # 在 clients 表中增加一个 INTEGER 类型的 machine_id 字段
    conn.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ip TEXT PRIMARY KEY, 
            port INTEGER, 
            client_key TEXT,
            last_report_data TEXT, 
            last_report_time TEXT, 
            remark TEXT,
            machine_id INTEGER
        )
    ''')
    conn.commit(); conn.close()
    print("数据库已初始化。")

def save_report(ip, port, client_key, report_data):
    conn = get_db_connection()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    report_json_str = json.dumps(report_data)
    cursor = conn.cursor()
    cursor.execute("SELECT ip FROM clients WHERE ip = ?", (ip,))
    if cursor.fetchone():
        cursor.execute('''
            UPDATE clients SET port = ?, client_key = ?, last_report_data = ?, last_report_time = ?
            WHERE ip = ?
        ''', (port, client_key, report_json_str, now_str, ip))
    else:
        # 新插入的记录，machine_id 默认为 NULL
        cursor.execute('''
            INSERT INTO clients (ip, port, client_key, last_report_data, last_report_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, port, client_key, report_json_str, now_str))
    conn.commit(); conn.close()

def get_all_clients(sort_by='time'):
    """获取所有客户端信息，并支持按机器编号排序"""
    conn = get_db_connection()
    if sort_by == 'ip':
        query = 'SELECT * FROM clients ORDER BY ip ASC'
    elif sort_by == 'id':
        # 核心排序逻辑：将有编号的排在前面并按编号升序，无编号的排在后面
        query = 'SELECT * FROM clients ORDER BY machine_id IS NULL, machine_id ASC, ip ASC'
    else: # 默认按时间
        query = 'SELECT * FROM clients ORDER BY last_report_time DESC'
    clients = conn.execute(query).fetchall()
    conn.close()
    return clients

def get_client_by_ip(ip):
    conn = get_db_connection()
    client = conn.execute('SELECT * FROM clients WHERE ip = ?', (ip,)).fetchone()
    conn.close()
    return client

def update_remark(ip, remark):
    conn = get_db_connection()
    conn.execute('UPDATE clients SET remark = ? WHERE ip = ?', (remark, ip))
    conn.commit(); conn.close()

def update_machine_id(ip, machine_id):
    """新增：更新指定IP客户端的机器编号"""
    conn = get_db_connection()
    conn.execute('UPDATE clients SET machine_id = ? WHERE ip = ?', (machine_id, ip))
    conn.commit(); conn.close()

def delete_client_by_ip(ip):
    conn = get_db_connection()
    conn.execute('DELETE FROM clients WHERE ip = ?', (ip,))
    conn.commit(); conn.close()
