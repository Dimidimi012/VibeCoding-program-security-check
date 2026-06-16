"""
AI 生成代码的安全漏洞检测规则。

AI 代码常见的安全问题包括：
- 硬编码密钥、token、密码
- SQL 注入（字符串拼接）
- 命令注入（shell=True + 动态参数）
- 弱加密算法和哈希函数
- 路径遍历
- 不安全的反序列化
- 使用非加密安全的随机数
- XSS（Web 场景）
"""

import re
from code_sentry.rules.base import Rule, Severity, Category


def _ctx_hardcoded_secret(line: str, file_path: str) -> str | None:
    """硬编码密钥判断"""
    line_stripped = line.strip()
    if line_stripped.startswith('#') or line_stripped.startswith('//'):
        return None
    if line_stripped.startswith('"""') or line_stripped.startswith("'''"):
        return None
    if file_path.endswith(('.env.example', '.env.template', '.env.sample', 'README.md')):
        return None
    placeholder_patterns = [
        'your-api-key', 'your_token', 'YOUR_', 'TODO',
        '<your', '<token', 'placeholder', 'example',
        'xxxx', '****', '...', '<KEY>',
    ]
    for pp in placeholder_patterns:
        if pp.lower() in line_stripped.lower():
            return None
    return "代码中硬编码了凭证信息，请改用环境变量或密钥管理服务"


def _ctx_sql_injection(line: str, file_path: str) -> str | None:
    """SQL 注入判断"""
    has_sql = re.search(
        r'(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\s',
        line, re.IGNORECASE
    )
    if not has_sql:
        return None
    has_concat = (
        '+' in line or
        'f"' in line or "f'" in line or
        '.format(' in line or
        '%' in line or
        '${' in line
    )
    if has_concat:
        return "SQL 查询使用了字符串拼接，存在 SQL 注入风险。请使用参数化查询"
    return None


def _ctx_command_injection(line: str, file_path: str) -> str | None:
    """命令注入判断"""
    if re.search(r'shell\s*=\s*True', line):
        if '+' in line or 'f"' in line or "f'" in line or '.format(' in line:
            return "⚠ shell=True 配合动态参数使用，存在命令注入风险"
        return "使用了 shell=True，请确认命令参数是否安全"
    return None


def _ctx_weak_crypto(line: str, file_path: str) -> str | None:
    """弱加密检测"""
    if re.search(r'hashlib\.md5\b', line) and re.search(r'password|passwd|pwd|secret', line, re.IGNORECASE):
        return "MD5 用于密码哈希不安全，请使用 bcrypt/scrypt/argon2"
    if re.search(r'hashlib\.sha1\b', line) and re.search(r'password|passwd|pwd|secret', line, re.IGNORECASE):
        return "SHA1 用于密码哈希不安全，请使用 bcrypt/scrypt/argon2"
    return "使用了弱加密算法或弱哈希函数"


def _ctx_deserialization(line: str, file_path: str) -> str | None:
    """不安全反序列化"""
    if re.search(r'pickle\.(?:loads|load)\b', line):
        return "⚠ pickle 反序列化可导致任意代码执行，请使用 JSON 或安全的序列化方案"
    if re.search(r'yaml\.load\b(?!.*Loader=yaml\.(?:Safe|CSafe)Loader)', line):
        return "⚠ yaml.load() 默认不安全，请使用 yaml.safe_load() 或显式指定 SafeLoader"
    if re.search(r'marshal\.loads?\b', line):
        return "⚠ marshal 反序列化不安全，请使用 JSON"
    if re.search(r'JSON\.parse\b', line) and re.search(r'untrusted|user|request', line, re.IGNORECASE):
        return "JSON.parse 本身安全，但输入来自用户时需做 schema 校验"
    return "使用了不安全的反序列化方法，可能导致代码执行"


def _ctx_path_traversal(line: str, file_path: str) -> str | None:
    """路径遍历检测"""
    has_file_op = re.search(
        r'\b(?:open|read|write|readFile|writeFile|readFileSync|writeFileSync)\s*\(',
        line
    )
    if not has_file_op:
        return None
    has_user_input = re.search(
        r'(?:request\.|params\[|query\[|body\[|req\.|input\()|\$\{|%s|\.format\(',
        line
    )
    has_concat = '+' in line
    if has_user_input or has_concat:
        return "文件路径由用户输入拼接而成，存在路径遍历风险。请对路径做白名单校验"
    return None


def _ctx_xss(line: str, file_path: str) -> str | None:
    """XSS 检测"""
    # 检测危险 DOM 操作
    has_dom = re.search(
        r'(?:innerHTML|outerHTML|insertAdjacentHTML|document\.write|dangerouslySetInnerHTML'
        r'|v-html|ng-bind-html|render_template_string)',
        line
    )
    if has_dom:
        has_user_data = re.search(
            r'(?:request\.|params\[|query\[|body\[|req\.|input\()|\.value\b|\$\{|props\.|state\.|this\.state',
            line
        )
        if has_user_data:
            return "⚠ 用户数据被直接写入 HTML，存在 XSS 风险。请使用 textContent 或进行 HTML 转义"
        return "使用了不安全的 HTML 输出方法，请确认数据来源是否可信"

    # 检测服务端直接返回 HTML 拼接
    has_return_html = re.search(
        r'(?:return|response|send)\s+f[\'"][^\"\']*<[a-zA-Z]+\b[^\"\']*\{',
        line
    )
    if has_return_html:
        has_user = re.search(r'(?:request\.|params\[|query\[|body\[|req\.)', line)
        if has_user or '{' in line.split('return')[-1] if 'return' in line else True:
            return "⚠ 用户数据直接嵌入 HTML 响应，存在 XSS 风险。请使用模板引擎的自动转义"

    return None


def _ctx_insecure_random(line: str, file_path: str) -> str | None:
    """不安全随机数"""
    if re.search(r'\brandom\.(?:randint|random|choice|shuffle)\b', line):
        context = line.lower()
        if any(kw in context for kw in ['token', 'password', 'secret', 'key', 'auth', 'session']):
            return "random 模块不适用于安全场景，请使用 secrets 模块"
    if re.search(r'\bMath\.random\b', line):
        context = line.lower()
        if any(kw in context for kw in ['token', 'password', 'secret', 'key', 'auth']):
            return "Math.random() 不是密码学安全的随机源，请使用 crypto.getRandomValues()"
    return "使用了非密码学安全的随机数生成器，在安全场景中可能被预测"


# ── 规则定义 ─────────────────────────────────────────────

SECURITY_RULES: list[Rule] = [
    Rule(
        id="SEC-001",
        name="硬编码密钥/凭证",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        description="代码中硬编码了 API Key、Token、密码等敏感凭证。AI 常从训练数据中复制这种模式",
        recommendation="使用环境变量、密钥管理服务（如 HashiCorp Vault、AWS Secrets Manager）或 .env 文件存储凭证",
        languages=["all"],
        patterns=[
            r'(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*[\'"][\w\-\.~+/=]{16,}[\'"]',
            r'(?:AKIA|ASIA)[A-Z0-9]{16}',
            r'(?:gh[ps]_[A-Za-z0-9]{36}|github[_-]?token\s*[:=]\s*[\'"]\w{30,}[\'"])',
            r'(?:token|secret|auth_token|access_token)\s*[:=]\s*[\'"][\w\-\.~+/=]{16,}[\'"]',
            r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----',
            r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+',
            r'(?:sk-[A-Za-z0-9]{32,})',
            r'(?:xox[bps]-[A-Za-z0-9\-]+)',
            r'(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}',
            r'(?:password|passwd|pwd)\s*[:=]\s*[\'"][^\'"]{4,}[\'"]',
        ],
        context_check=_ctx_hardcoded_secret,
    ),

    Rule(
        id="SEC-002",
        name="SQL 注入",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        description="SQL 查询使用字符串拼接而非参数化查询。AI 生成的代码常出现这种模式",
        recommendation="使用参数化查询或 ORM：Python 用 ? 占位符；JS 用 $1；Java 用 PreparedStatement",
        languages=["python", "javascript", "typescript", "java", "go", "php", "ruby"],
        patterns=[
            # 直接在 execute 中拼接
            r'(?:execute|cursor\.execute|rawQuery|query)\s*\(\s*(?:f"|f\'|\w+\s*\+)',
            # 变量赋值时 SQL 拼接（f-string 和 + 拼接）
            r'\w+\s*=\s*(?:f"|f\')[\w\s,.*\'\"=]*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
            r'\w+\s*=\s*[\"\'][\w\s,.*]+[\"\']\s*\+.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
            # .format() 拼接
            r'\.format\s*\(.*\).*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
            # % 格式化拼接
            r'[\"\']\s*%\s*\w+.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
            r'[\"\']\s*%\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b',
        ],
        context_check=_ctx_sql_injection,
    ),

    Rule(
        id="SEC-003",
        name="命令注入",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        description="系统命令执行使用了 shell=True 且包含动态参数，或使用了 eval/exec",
        recommendation="避免使用 shell=True。用 subprocess.run([...]) 列表形式传参，或使用 shlex.quote() 转义",
        languages=["python", "javascript", "typescript", "ruby", "php"],
        patterns=[
            r'shell\s*=\s*True',
            r'\bchild_process\s*\.\s*exec\s*\(\s*\w+\s*\+',
            r'\bchild_process\s*\.\s*exec\s*\(\s*`[^`]*\$\{',
            r'\beval\s*\(\s*\w+\s*\+',
            r'\bexec\s*\(\s*[\'"]\s*\+',
        ],
        context_check=_ctx_command_injection,
    ),

    Rule(
        id="SEC-004",
        name="弱加密/哈希算法",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        description="使用了已知不安全的加密算法或哈希函数（MD5、SHA1、DES、RC4 等）",
        recommendation="哈希用 SHA-256/512 或 bcrypt/scrypt/argon2。对称加密用 AES-256-GCM。禁止使用 MD5/SHA1 处理密码",
        languages=["python", "javascript", "typescript", "java", "go", "php"],
        patterns=[
            r'\bhashlib\.md5\b',
            r'\bhashlib\.sha1\b',
            r'\bCrypto\.Cipher\.DES\b',
            r'\bCrypto\.Cipher\.ARC4\b',
            r'\bMessageDigest\.getInstance\s*\(\s*"MD5',
            r'\bMessageDigest\.getInstance\s*\(\s*"SHA-?1',
            r'\bcrypto\.createHash\s*\(\s*[\'"]md5[\'"]',
            r'\bcrypto\.createHash\s*\(\s*[\'"]sha1[\'"]',
            r'\b(?:md5|sha1)\s*\(',
            r'ECB\b',
        ],
        context_check=_ctx_weak_crypto,
    ),

    Rule(
        id="SEC-005",
        name="路径遍历",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        description="文件路径由用户输入拼接而成，攻击者可通过 ../ 访问任意文件",
        recommendation="使用白名单校验路径，或用 os.path.realpath() + 前缀检查确保路径在允许范围内",
        languages=["python", "javascript", "typescript", "java", "go", "php"],
        patterns=[
            # open/read 函数中使用变量拼接
            r'\bopen\s*\(\s*\w+\s*\+',
            r'\bopen\s*\(\s*f[\'"]',
            r'\bopen\s*\(\s*[\'"][^\'"]*[\'"]\s*\+',
            # JS/TS
            r'\breadFile(?:Sync)?\s*\(\s*\w+\s*\+',
            r'\breadFile(?:Sync)?\s*\(\s*`[^`]*\$\{',
            r'\bfs\.(?:readFile|writeFile)\s*\(',
            # 通用文件操作拼接
            r'\b(?:read|write)\s*\(\s*\w+\s*\+',
        ],
        context_check=_ctx_path_traversal,
    ),

    Rule(
        id="SEC-006",
        name="不安全反序列化",
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        description="使用了不安全的反序列化方法，攻击者可构造恶意数据实现代码执行",
        recommendation="Python 用 json.loads() 替代 pickle；YAML 用 yaml.safe_load()。JavaScript 对用户数据进行 schema 校验",
        languages=["python", "javascript", "typescript", "java", "ruby", "php"],
        patterns=[
            r'\bpickle\.(?:loads|load)\s*\(',
            r'\byaml\.load\s*\(',
            r'\bmarshal\.loads?\s*\(',
            r'\bdill\.loads?\s*\(',
            r'\bnew\s+Function\s*\(',
            r'\bObjectInputStream\b',
            r'\bunserialize\s*\(',
        ],
        context_check=_ctx_deserialization,
    ),

    Rule(
        id="SEC-007",
        name="XSS 漏洞",
        severity=Severity.HIGH,
        category=Category.SECURITY,
        description="用户输入被直接写入 HTML DOM，可能导致跨站脚本攻击",
        recommendation="使用 textContent 代替 innerHTML，或使用 DOMPurify 等库对内容做净化。React 中避免 dangerouslySetInnerHTML",
        languages=["javascript", "typescript", "php", "ruby", "python"],
        patterns=[
            r'\.innerHTML\s*=',
            r'\.outerHTML\s*=',
            r'\.insertAdjacentHTML\s*\(',
            r'\bdocument\.write\s*\(',
            r'\bdangerouslySetInnerHTML\b',
            r'\bv-html\b',
            r'\bng-bind-html\b',
            r'\becho\s+\$_GET',
            r'\becho\s+\$_POST',
            r'\becho\s+\$_REQUEST',
            # 服务端返回 HTML 拼接
            r'\breturn\s+f[\'"][^\"\']*<[a-zA-Z]+\b[^\"\']*\{',
            r'\brender_template_string\b',
        ],
        context_check=_ctx_xss,
    ),

    Rule(
        id="SEC-008",
        name="不安全随机数生成",
        severity=Severity.MEDIUM,
        category=Category.SECURITY,
        description="在安全场景中使用了非密码学安全的随机数生成器",
        recommendation="Python 用 secrets 模块；JS 用 crypto.getRandomValues()；Java 用 SecureRandom",
        languages=["python", "javascript", "typescript", "java"],
        patterns=[
            r'\brandom\.(?:randint|random|choice|shuffle)\b',
            r'\bMath\.random\b',
            r'\bnew\s+Random\s*\(',
            r'\bmt_rand\b',
            r'\brand\s*\(',
        ],
        context_check=_ctx_insecure_random,
    ),
]
