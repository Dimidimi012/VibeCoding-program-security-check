"""
中转站投毒检测规则。

覆盖六大攻击面：
1. 异常网络外联 — 代码试图连接外部服务器
2. 系统命令执行 — 执行系统级命令
3. 敏感文件读取 — 读取密钥、配置、凭证文件
4. 代码混淆 — base64/hex 编码 + 动态执行
5. 依赖投毒 — 从非官方源安装依赖
6. 持久化与提权 — 写入启动项、提权操作
"""

import re
import os
import math
from code_sentry.rules.base import Rule, Severity, Category

# ── 公共辅助 ────────────────────────────────────────────

def _entropy(s: str) -> float:
    """计算字符串的香农熵"""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _is_likely_payload(s: str, min_entropy: float = 4.0, min_len: int = 40) -> bool:
    """判断字符串是否像编码后的 payload（高熵 + 一定长度）"""
    return len(s) >= min_len and _entropy(s) >= min_entropy


# ── 上下文判断函数 ────────────────────────────────────────

def _ctx_network(line: str, file_path: str) -> str | None:
    """网络外联上下文判断：排除明显的本地/测试连接"""
    line_lower = line.lower()
    # 允许的连接目标
    safe_hosts = [
        'localhost', '127.0.0.1', '0.0.0.0', '::1',
        'api.', 'pypi.org', 'npmjs.com', 'github.com',
        'googleapis.com', 'cdn.', 'static.',
    ]
    for host in safe_hosts:
        if host in line_lower:
            return None
    # 如果 URL 看起来像常见 API 路径，放行
    if re.search(r'https?://[^/\s]+/api/', line_lower):
        return None
    return "代码中包含对外网络请求，需确认目标地址是否可信"


def _ctx_command(line: str, file_path: str) -> str | None:
    """命令执行上下文判断"""
    line_stripped = line.strip()
    # 注释中的忽略
    if line_stripped.startswith('#') or line_stripped.startswith('//'):
        return None
    # 是否是动态拼接命令
    if '+' in line or 'f"' in line or 'f\'' in line or 'format(' in line or '${' in line:
        return "⚠ 命令中包含动态拼接，可能存在命令注入风险"
    # 检测到 exec/eval 等本身就是高风险
    if re.search(r'\beval\s*\(', line) or re.search(r'\bexec\s*\(', line):
        return "⚠ 使用 eval/exec 执行动态代码，这是投毒的常见手法"
    return "代码中执行了系统命令，请确认是否为项目所需"


def _ctx_sensitive_file(line: str, file_path: str) -> str | None:
    """敏感文件读取判断"""
    sensitive_paths = [
        r'/etc/(passwd|shadow|hosts|sudoers)',
        r'\.ssh/',
        r'\.aws/credentials',
        r'\.config/gcloud',
        r'\.kube/config',
        r'\.env($|[^a-zA-Z])',
        r'id_rsa',
        r'\.pem\b',
        r'\\Windows\\System32\\drivers\\etc',
    ]
    for sp in sensitive_paths:
        if re.search(sp, line, re.IGNORECASE):
            return f"检测到尝试访问敏感路径，可能用于信息窃取"
    # 如果代码读取了环境变量全量
    if re.search(r'os\.environ\b', line) and not re.search(r'os\.environ\[', line):
        return "全量读取环境变量，可能泄露密钥和配置"
    return None


def _ctx_obfuscation(line: str, file_path: str) -> str | None:
    """代码混淆检测"""
    # 检测 base64 字符串 + eval/exec 组合
    has_b64 = re.search(r'(?:b(?:ase)?64|atob|btoa)', line, re.IGNORECASE)
    has_exec = re.search(r'\b(?:eval|exec|execCommand)\s*\(', line)
    if has_b64 and has_exec:
        return "⚠ 检测到 base64 编码与动态执行组合，高度疑似混淆恶意代码"

    # 检测大段 base64 字符串
    b64_pattern = r'[\w+/=]{60,}'
    match = re.search(b64_pattern, line)
    if match and _is_likely_payload(match.group(), min_entropy=4.5, min_len=40):
        return "⚠ 发现高熵值长字符串，可能是编码后的恶意 payload"

    # 检测 hex 编码 + 执行
    has_hex = re.search(r'(?:0x[0-9a-fA-F]{20,}|\\\\x[0-9a-fA-F]{2})', line)
    if has_hex and has_exec:
        return "⚠ 检测到 hex 编码与动态执行组合，高度疑似 shellcode"

    return None


def _ctx_dependency(line: str, file_path: str) -> str | None:
    """依赖投毒检测"""
    basename = os.path.basename(file_path)

    # pip install 直接从未知 URL
    if re.search(r'pip\s+install.*(?:http://|https://)', line):
        return "⚠ 从非 PyPI 源安装包，可能被投毒"

    # npm install 从未知源
    if re.search(r'npm\s+install.*(?:http://|https://)', line):
        return "⚠ 从非 npm 源安装包，可能被投毒"

    # curl/wget 后紧跟 pip install 的脚本模式
    if re.search(r'(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)', line):
        return "⚠ 检测到 curl/wget 管道执行模式，这是投毒的经典手法"

    # go install 未知源
    if re.search(r'go\s+install\s+(?!golang\.org|pkg\.go\.dev)', line):
        return None  # Go 生态链比较安全

    return None


def _ctx_persistence(line: str, file_path: str) -> str | None:
    """持久化与提权检测"""
    # cron 写入
    if re.search(r'crontab\s+-', line) or re.search(r'/etc/cron', line):
        return "⚠ 检测到 crontab 写入操作，可能用于建立持久化"
    # 注册表操作 (Windows)
    if re.search(r'(?:reg\s+add|HKEY_|Set-ItemProperty.*Registry)', line, re.IGNORECASE):
        return "⚠ 检测到 Windows 注册表操作，可能用于建立持久化"
    # systemd 服务
    if re.search(r'(?:systemctl\s+enable|/etc/systemd/system)', line):
        return "⚠ 检测到 systemd 服务注册，可能用于建立持久化"
    # 自启动
    if re.search(r'(?:\.bashrc|\.zshrc|\.profile|Startup|启动)', line):
        return "检测到自启动文件写入"
    # sudo/setuid
    if re.search(r'\bsudo\b', line) and re.search(r'(?:chmod.*\+s|chown\s+root)', line):
        return "⚠ 检测到提权操作"
    return None


# ── 规则定义 ─────────────────────────────────────────────

POISONING_RULES: list[Rule] = [
    Rule(
        id="POI-001",
        name="异常网络外联",
        severity=Severity.CRITICAL,
        category=Category.POISONING,
        description="代码中包含向外部服务器的网络请求，投毒代码常通过此方式外泄数据或下载下一阶段 payload",
        recommendation="核实目标地址是否为项目必需的 API 端点。如在代码底部突兀出现，高度可疑",
        languages=["python", "javascript", "typescript", "go", "java", "ruby", "php", "rust"],
        patterns=[
            # Python
            r'\brequests\s*\.\s*(?:get|post|put|delete|patch|head|request)\s*\(',
            r'\bhttpx\s*\.\s*(?:get|post|put|delete)\s*\(',
            r'\burllib\.(?:request|opener)',
            r'\bsocket\.(?:socket|connect|create_connection)\s*\(',
            r'\bhttp\.client\b',
            r'\baiohttp\b',
            r'\basyncio\.open_connection\b',
            # JS/TS
            r'\bfetch\s*\(',
            r'\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(',
            r'\bXMLHttpRequest\b',
            r'\bhttp\s*\.\s*(?:request|get)\s*\(',
            r'\bsuperagent\b',
            # Go
            r'\bhttp\.(?:Get|Post|NewRequest)\s*\(',
            # Java
            r'\bHttpClient\b',
            r'\bOkHttpClient\b',
            r'\bRestTemplate\b',
            # Shell
            r'\b(curl|wget)\s+',
            # PHP
            r'\bfile_get_contents\s*\(\s*[\'"]https?://',
            r'\bcurl_init\s*\(',
        ],
        context_check=_ctx_network,
    ),

    Rule(
        id="POI-002",
        name="系统命令执行",
        severity=Severity.CRITICAL,
        category=Category.POISONING,
        description="代码中执行了系统级命令。投毒代码常通过此方式执行恶意操作",
        recommendation="确认该命令是否为项目功能所需。检查命令中是否有动态拼接的变量",
        languages=["python", "javascript", "typescript", "go", "java", "ruby", "php", "rust"],
        patterns=[
            # Python
            r'\bos\.system\s*\(',
            r'\bsubprocess\.(?:call|run|Popen|check_output|check_call)\s*\(',
            r'\beval\s*\(',
            r'\bexec\s*\(',
            r'\b__import__\s*\(\s*[\'"]os[\'"]\s*\)',
            # JS/TS
            r'\bchild_process\s*\.\s*(?:exec|spawn|fork|execSync|spawnSync)\s*\(',
            r'\bprocess\.(?:spawn|exec)\b',
            r'\beval\s*\(',
            r'\bFunction\s*\(\s*[\'"][^)]*[\'"]\s*\)\s*\(',  # new Function() 构造器
            # Go
            r'\bexec\.(?:Command|CommandContext)\s*\(',
            r'\bos\.Exec\b',
            # Java
            r'\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(',
            r'\bProcessBuilder\b',
            # Ruby
            r'\bsystem\s*\(',
            r'\bexec\s*\(',
            r'`[^`]+`',  # 反引号执行
            # PHP
            r'\b(?:exec|system|passthru|shell_exec|proc_open|popen)\s*\(',
        ],
        context_check=_ctx_command,
    ),

    Rule(
        id="POI-003",
        name="敏感文件读取",
        severity=Severity.HIGH,
        category=Category.POISONING,
        description="代码试图读取系统敏感文件或凭证存储路径",
        recommendation="确认文件读取操作是否有合理的业务需求",
        languages=["python", "javascript", "typescript", "go", "java", "ruby", "php", "rust"],
        patterns=[
            # 通用文件读取
            r'\bopen\s*\(\s*[\'"]/etc/',
            r'\bopen\s*\(\s*[\'"][~.]',
            r'\bopen\s*\(\s*[\'"]C:\\Users\\',
            r'\.(?:read|read_text|read_bytes|readFile|readFileSync)\s*\(',
            r'\bcat\s+/etc/',
            r'\bos\.path\.expanduser\s*\(',
            r'\bos\.environ\b',
            r'\bprocess\.env\b',
            r'\bgetenv\s*\(',
            r'\bSystem\.getenv\b',
        ],
        context_check=_ctx_sensitive_file,
    ),

    Rule(
        id="POI-004",
        name="代码混淆特征",
        severity=Severity.CRITICAL,
        category=Category.POISONING,
        description="发现编码/加密字符串与动态执行的组合模式，或高熵值可疑字符串",
        recommendation="这是投毒代码最显著的特征之一。请人工审查该段代码的来源和用途",
        languages=["python", "javascript", "typescript", "go", "java", "ruby", "php"],
        patterns=[
            # base64 + exec
            r'\b(?:b(?:ase)?64|atob|btoa)\b',
            r'\b(?:fromhex|hexlify|unhexlify)\b',
            r'\bcodecs\.decode\b',
            r'\bx03\b.*\bx[0-9a-f]{2}',
            # 高熵字符串 (30+ 字符的 base64 外观)
            r'[\w+/=]{50,}',
            r'\\\\x[0-9a-fA-F]{2}',
        ],
        context_check=_ctx_obfuscation,
    ),

    Rule(
        id="POI-005",
        name="依赖投毒",
        severity=Severity.HIGH,
        category=Category.POISONING,
        description="从非官方源安装依赖，或使用了 curl|bash 等高风险安装模式",
        recommendation="只从官方包管理源安装依赖。curl|bash 模式几乎可以确定是恶意行为",
        languages=["all"],
        patterns=[
            r'\b(?:curl|wget)\s+.*\|\s*(?:bash|sh|python|ruby|perl)',
            r'\bpip\s+install.*(?:http://|https://)(?!.*pypi\.org)',
            r'\bnpm\s+install.*(?:http://|https://)(?!.*(?:npmjs\.com|registry\.npmjs))',
            r'\b(?:easy_install|setup\.py)\b',
            r'\bgo\s+get\s+(?:http://|https://)(?!.*(?:golang\.org|pkg\.go\.dev|github\.com))',
            r'\bdocker\s+run.*\|\s*(?:bash|sh)',
        ],
        context_check=_ctx_dependency,
    ),

    Rule(
        id="POI-006",
        name="持久化与提权",
        severity=Severity.HIGH,
        category=Category.POISONING,
        description="代码试图建立持久化机制（cron/服务/启动项）或提升权限",
        recommendation="除非项目本身就是运维工具，否则这类操作极可能是恶意行为",
        languages=["python", "javascript", "typescript", "go", "java", "ruby", "php", "shell"],
        patterns=[
            # cron
            r'\bcrontab\b',
            r'/etc/cron\.(?:d|daily|hourly|monthly|weekly)',
            # systemd
            r'/etc/systemd/system',
            r'\bsystemctl\s+(?:enable|daemon-reload)',
            # 启动文件
            r'\.bashrc',
            r'\.zshrc',
            r'\.profile',
            r'~/.config/autostart',
            r'Startup\\\\',
            # 注册表
            r'HKEY_(?:CURRENT_USER|LOCAL_MACHINE)',
            r'reg\s+(?:add|import)',
            r'Set-ItemProperty.*Registry',
            # 提权
            r'\bsudo\b',
            r'\bchown\s+\w+\s*:',
            r'\bchmod\s+.*\+s\b',
            r'\bsetuid\b',
            r'\bSet-ExecutionPolicy\b',
            # 用户管理
            r'\buseradd\b',
            r'\badduser\b',
            r'\bnet\s+user\s+/add',
        ],
        context_check=_ctx_persistence,
    ),
]
