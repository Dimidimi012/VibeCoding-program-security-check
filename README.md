<h1 align="center">
  <img src="vscode/images/icon.png" width="48" height="48" alt="">
  <br>
  Code Sentry
</h1>

<p align="center">
  <strong>AI 代码本地安检仪</strong>
  <br>
  检测中转站投毒 & AI 生成代码安全漏洞 · 完全本地 · 不上传云端
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/vscode-1.85+-blue.svg" alt="VS Code">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

---

## 为什么需要这个工具

AI 编码工具（Claude Code、Cursor、Copilot 等）生成的代码量快速增长，但安全审计几乎全靠开发者自觉。更危险的是，**第三方中转站可能在传输链路中注入恶意代码**——这是传统 SAST 工具不覆盖的威胁模型。

Code Sentry 在代码进入执行环境之前，做一道完全本地的安检。

### 两大检测维度

| 维度 | 目标 | 核心方法 |
|---|---|---|
| 🦠 **中转站投毒** | 检测传输链路中被注入的恶意代码 | 网络外联、命令执行、混淆特征、组合警报 |
| 🔒 **安全漏洞** | 检测 AI 生成代码中的固有漏洞 | OWASP Top 10 覆盖、硬编码密钥、注入类 |

---

## 项目结构

```
code-sentry/
├── code_sentry/          # Python 引擎核心
│   ├── cli.py            # CLI 入口
│   ├── engine.py         # 扫描引擎
│   ├── rules/
│   │   ├── base.py       # 数据模型
│   │   ├── poisoning.py  # 6 条投毒检测规则
│   │   └── security.py   # 8 条安全漏洞规则
│   ├── analyzers/
│   │   └── context.py    # 风险评分 + 组合警报
│   └── reporters/
│       └── terminal.py   # 终端报告输出
├── tests/                # 测试用例
├── vscode/               # VS Code 扩展
│   ├── src/              # TypeScript 源码
│   ├── out/              # 编译产物
│   └── package.json
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 快速开始

### 安装

```bash
git clone https://github.com/your-username/code-sentry.git
cd code-sentry
pip install -e .
```

依赖只有 `rich` 和 `click`（可选，未安装时自动降级为纯文本输出）。

### CLI 使用

```bash
# 扫描当前目录
code-sentry

# 扫描指定目录
code-sentry /path/to/project

# JSON 输出（可接入 CI/CD）
code-sentry --json

# 仅显示高危
code-sentry --severity high

# 仅看投毒
code-sentry --category poisoning
```

### VS Code 扩展

```
vscode/
├── install.bat           # Windows 一键安装
└── ...
```

1. 双击 `vscode/install.bat` 或手动复制到 `%USERPROFILE%\.vscode\extensions\hanako.code-sentry-0.1.0`
2. 重启 VS Code
3. 在设置中搜索 `codeSentry`，配置 Python 引擎路径
4. 保存文件时自动扫描

---

## 检测规则

### 🦠 投毒检测（6 条）

| ID | 规则 | 严重度 | 说明 |
|---|---|---|---|
| POI-001 | 异常网络外联 | 🔴 CRITICAL | 向外部服务器发起可疑连接 |
| POI-002 | 系统命令执行 | 🔴 CRITICAL | subprocess / exec / eval 调用 |
| POI-003 | 敏感文件读取 | 🟠 HIGH | SSH 密钥、AWS 凭证、环境变量 |
| POI-004 | 代码混淆特征 | 🔴 CRITICAL | base64 + eval 组合、高熵值字符串 |
| POI-005 | 依赖投毒 | 🟠 HIGH | curl\|bash 模式、非官方源安装 |
| POI-006 | 持久化与提权 | 🟠 HIGH | cron 注入、注册表修改、sudo 滥用 |

### 🔒 安全漏洞（8 条）

| ID | 规则 | 严重度 | 说明 |
|---|---|---|---|
| SEC-001 | 硬编码密钥/凭证 | 🔴 CRITICAL | API Key、Token、密码写死在代码中 |
| SEC-002 | SQL 注入 | 🔴 CRITICAL | 字符串拼接构建 SQL |
| SEC-003 | 命令注入 | 🔴 CRITICAL | shell=True + 动态参数 |
| SEC-004 | 弱加密/哈希 | 🟠 HIGH | MD5、SHA1、DES、ECB |
| SEC-005 | 路径遍历 | 🟠 HIGH | 用户输入拼接文件路径 |
| SEC-006 | 不安全反序列化 | 🔴 CRITICAL | pickle、yaml.load |
| SEC-007 | XSS 漏洞 | 🟠 HIGH | innerHTML、危险 DOM 操作 |
| SEC-008 | 不安全随机数 | 🟡 MEDIUM | random 用于安全场景 |

---

## 工作原理

```
用户代码 → 文件遍历 → 语言识别 → 正则匹配 → 上下文判断 → 风险评分 → 报告
                              ↓
                      14 条内置规则
                    (6 投毒 + 8 安全)
```

**四层检测管线：**

1. **正则匹配层** — 跨语言通用 pattern 匹配可疑代码模式
2. **上下文判断层** — 过滤误报：排除注释、示例代码、安全目标地址
3. **风险分析层** — 关联分析 + 特征叠加 + 位置异常检测
4. **报告输出层** — 彩色终端 / JSON / VS Code Problems 面板

### 组合警报（差异化能力）

单条规则可能误报，多条叠加是确定恶意行为的关键信号：

| 警报 | 触发条件 |
|---|---|
| 🔴 C2模式 | 网络外联 + 命令执行 |
| 🔴 隐蔽C2 | 网络外联 + 混淆编码 |
| 🔴 数据窃取 | 敏感文件 + 网络外联 |
| 🔴 APT驻留 | 持久化 + 命令执行 |
| 🔴 供应链攻击 | 依赖投毒 + 命令执行 |
| ⚠ 位置异常 | 文件底部集中出现高危特征 |

---

## 多语言支持

Python · JavaScript · TypeScript · Go · Java · Ruby · PHP · Rust · C · C++ · C# · Shell

---

## 退出码

| 码 | 含义 | CI/CD 行为 |
|---|---|---|
| 0 | 无发现 | 通过 ✓ |
| 1 | 存在 HIGH 级别发现 | 警告 ⚠ |
| 2 | 存在 CRITICAL 级别发现 | 阻断 ✗ |

---

## 开发

```bash
# 运行测试
cd tests
python -m code_sentry.cli test_poisoning.py
python -m code_sentry.cli test_security.py

# VS Code 扩展开发
cd vscode
npm install
npm run compile
```

---

## License

MIT
