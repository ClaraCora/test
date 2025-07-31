# 文件名: database.py
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
    conn.execute('''
        CREATE TABLE IF NOT EXISTS clients (
            ip TEXT PRIMARY KEY, port INTEGER, client_key TEXT,
            last_report_data TEXT, last_report_time TEXT, remark TEXT
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
        cursor.execute('''
            INSERT INTO clients (ip, port, client_key, last_report_data, last_report_time)
            VALUES (?, ?, ?, ?, ?)
        ''', (ip, port, client_key, report_json_str, now_str))
    conn.commit(); conn.close()

def get_all_clients(sort_by='time'):
    """获取所有客户端信息，并支持排序"""
    conn = get_db_connection()
    if sort_by == 'ip':
        query = 'SELECT * FROM clients ORDER BY ip ASC'
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

def delete_client_by_ip(ip):
    """新增：根据IP删除客户端记录"""
    conn = get_db_connection()
    conn.execute('DELETE FROM clients WHERE ip = ?', (ip,))
    conn.commit(); conn.close()
