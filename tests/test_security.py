"""
测试文件：包含多种 AI 生成代码中常见的安全漏洞。
此文件用于验证 Code Sentry 的安全漏洞检测能力。
"""

import hashlib
import pickle
import random
import yaml
import sqlite3
from flask import Flask, request

app = Flask(__name__)

# === 安全漏洞 1：硬编码密钥 ===
OPENAI_API_KEY = "sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"
DB_PASSWORD = "admin123"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"

# === 安全漏洞 2：SQL 注入 ===
def get_user(user_id):
    conn = sqlite3.connect("users.db")
    # 字符串拼接，存在 SQL 注入
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor = conn.execute(query)
    return cursor.fetchall()

def search_users(name):
    conn = sqlite3.connect("users.db")
    # f-string 中的 SQL，存在注入
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return conn.execute(query).fetchall()

# === 安全漏洞 3：命令注入 ===
@app.route("/ping")
def ping():
    target = request.args.get("host")
    # shell=True + 用户输入 → 命令注入
    import subprocess
    result = subprocess.check_output(f"ping -c 1 {target}", shell=True)
    return result

# === 安全漏洞 4：弱加密 ===
def hash_password(password):
    # MD5 用于密码哈希
    return hashlib.md5(password.encode()).hexdigest()

def weak_encrypt(data, key):
    # SHA1 用于密码
    return hashlib.sha1(data + key).hexdigest()

# === 安全漏洞 5：路径遍历 ===
@app.route("/read")
def read_file():
    filename = request.args.get("file")
    # 用户输入直接拼接文件路径
    with open("/var/data/" + filename) as f:
        return f.read()

# === 安全漏洞 6：不安全反序列化 ===
def load_user_data(data):
    # pickle 反序列化可能导致代码执行
    return pickle.loads(data)

def load_config(yaml_str):
    # yaml.load 默认不安全
    return yaml.load(yaml_str)

# === 安全漏洞 7：XSS ===
@app.route("/greet")
def greet():
    name = request.args.get("name")
    # 用户输入直接写入 HTML
    return f"<h1>Hello, {name}!</h1>"

# === 安全漏洞 8：不安全随机数 ===
def generate_reset_token():
    # random 不适合生成安全令牌
    return ''.join(str(random.randint(0, 9)) for _ in range(32))
