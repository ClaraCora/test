# 文件名: config.py
import json
import os
import uuid

CONFIG_FILE = 'server-config.json'

def load_config():
    if not os.path.exists(CONFIG_FILE):
        print(f"配置文件 {CONFIG_FILE} 不存在，将使用默认值创建。")
        new_key = str(uuid.uuid4())
        default_config = {
            "SERVER_PORT": 28037,
            "SERVER_SECRET_KEY": new_key,
            "ADMIN_USER": "cc",
            "ADMIN_PASS": "cc" # 强烈建议首次启动后修改此密码
        }
        with open(CONFIG_FILE, 'w') as f:
            json.dump(default_config, f, indent=4)
        print(f"已生成新的配置文件。您的主控通讯密钥是: {new_key}")
        print("默认管理员用户名: admin, 密码: password。请及时修改配置文件！")
        return default_config
    else:
        with open(CONFIG_FILE, 'r') as f:
            print(f"从 {CONFIG_FILE} 加载配置。")
            config_data = json.load(f)
            # 兼容旧配置文件，如果缺少管理员账户则添加
            if 'ADMIN_USER' not in config_data:
                config_data['ADMIN_USER'] = 'admin'
                config_data['ADMIN_PASS'] = 'password'
                with open(CONFIG_FILE, 'w') as f:
                    json.dump(config_data, f, indent=4)
                print("已为旧配置文件添加默认管理员账户。")
            return config_data
