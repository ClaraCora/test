# 文件名: config.py
import json
import os
import uuid

CONFIG_FILE = 'server-config.json'

def load_config():
    """
    加载或创建主控端配置文件。
    如果文件不存在，则使用默认值创建它。
    """
    if not os.path.exists(CONFIG_FILE):
        print(f"配置文件 {CONFIG_FILE} 不存在，将使用默认值创建。")
        
        # 生成一个安全的随机密钥
        new_key = str(uuid.uuid4())
        
        default_config = {
            "SERVER_PORT": 28037,
            "SERVER_SECRET_KEY": new_key
        }
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=4)
            
        print(f"已生成新的配置文件。您的主控通讯密钥是: {new_key}")
        print("请确保在客户端安装脚本中填写此密钥。")
        return default_config
    else:
        with open(CONFIG_FILE, 'r') as f:
            print(f"从 {CONFIG_FILE} 加载配置。")
            return json.load(f)