"""
深度分析数据模型。

定义调用图、污点追踪、攻击链的核心数据结构。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SymbolKind(str, Enum):
    FUNCTION = "function"
    METHOD = "method"
    VARIABLE = "variable"
    IMPORT = "import"
    CLASS = "class"
    PARAMETER = "parameter"


class NodeType(str, Enum):
    """AST 节点类型（统一抽象）"""
    FUNCTION_DEF = "function_def"
    FUNCTION_CALL = "function_call"
    ASSIGNMENT = "assignment"
    IMPORT = "import"
    STRING = "string"
    BINARY_OP = "binary_op"  # +, -, etc
    ATTRIBUTE = "attribute"  # obj.attr


# ── 污点追踪的类型标记 ──────────────────────────────────

class TaintSource(str, Enum):
    """污点来源：不可信数据从哪里进入"""
    HTTP_PARAM = "http_param"       # request.args, req.query
    HTTP_BODY = "http_body"         # request.json, req.body
    FILE_READ = "file_read"         # open(), fs.readFile
    ENV_READ = "env_read"           # os.environ, process.env
    STDIN = "stdin"                 # input(), readline
    NETWORK_RECV = "network_recv"   # socket.recv, http response
    CLI_ARG = "cli_arg"             # sys.argv, process.argv


class TaintSink(str, Enum):
    """污点汇：危险操作"""
    COMMAND_EXEC = "command_exec"       # os.system, subprocess, exec()
    CODE_EXEC = "code_exec"             # eval, exec, Function()
    FILE_WRITE = "file_write"           # open('w'), fs.writeFile
    NETWORK_SEND = "network_send"       # requests.post, socket.send
    SQL_EXEC = "sql_exec"               # cursor.execute, query
    DESERIALIZE = "deserialize"         # pickle.load, yaml.load
    HTML_OUTPUT = "html_output"         # innerHTML, render_template


# ── 攻击链步骤类型 ──────────────────────────────────────

class ChainStepType(str, Enum):
    SOURCE = "source"       # 获取载荷/数据
    TRANSFORM = "transform" # 解码/解密/解压
    SINK = "sink"           # 执行/外发/持久化
    PRIVILEGE = "privilege" # 提权/绕过


# ── 核心数据结构 ────────────────────────────────────────


@dataclass
class Location:
    """代码位置"""
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 0
    col_end: int = 0


@dataclass
class Symbol:
    """符号表条目"""
    name: str
    kind: SymbolKind
    location: Location
    parent: str | None = None  # 所属函数/类
    type_hint: str = ""


@dataclass
class CallEdge:
    """调用图中的一条边"""
    caller: str       # 调用者函数名
    callee: str       # 被调用函数名
    location: Location
    arguments: list[str] = field(default_factory=list)


@dataclass
class TaintNode:
    """污点路径上的一个节点"""
    symbol: Symbol
    taint_type: str  # source/sink/sanitizer/transformer
    note: str = ""


@dataclass
class TaintPath:
    """一条完整的污点路径：Source → ... → Sink"""
    source: TaintNode
    sink: TaintNode
    intermediate: list[TaintNode] = field(default_factory=list)
    confidence: float = 1.0  # 0-1，置信度
    source_type: str = ""
    sink_type: str = ""


@dataclass
class AttackChainMatch:
    """检测到的攻击链"""
    chain_name: str
    severity: str  # critical / high / medium
    description: str
    matched_paths: list[TaintPath] = field(default_factory=list)
    confidence: float = 0.0
    summary: str = ""


@dataclass
class DeepAnalysisResult:
    """深度分析完整结果"""
    file_path: str
    language: str
    symbols: list[Symbol] = field(default_factory=list)
    call_graph: list[CallEdge] = field(default_factory=list)
    taint_paths: list[TaintPath] = field(default_factory=list)
    attack_chains: list[AttackChainMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Source/Sink 特征库 ──────────────────────────────────

# 多语言的 Source 特征
SOURCE_PATTERNS: dict[str, list[dict]] = {
    "python": [
        # HTTP 框架
        {"pattern": "request.args.get", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.form.get", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.json", "type": TaintSource.HTTP_BODY},
        {"pattern": "request.get_json", "type": TaintSource.HTTP_BODY},
        {"pattern": "request.data", "type": TaintSource.HTTP_BODY},
        # Django
        {"pattern": "request.GET.get", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.POST.get", "type": TaintSource.HTTP_PARAM},
        # 文件
        {"pattern": "open", "type": TaintSource.FILE_READ},
        {"pattern": "Path.read_text", "type": TaintSource.FILE_READ},
        # 环境
        {"pattern": "os.environ", "type": TaintSource.ENV_READ},
        {"pattern": "os.getenv", "type": TaintSource.ENV_READ},
        # 标准输入
        {"pattern": "input", "type": TaintSource.STDIN},
        {"pattern": "sys.stdin.read", "type": TaintSource.STDIN},
        # CLI
        {"pattern": "sys.argv", "type": TaintSource.CLI_ARG},
        # 网络
        {"pattern": "socket.recv", "type": TaintSource.NETWORK_RECV},
        {"pattern": "requests.get", "type": TaintSource.NETWORK_RECV},
    ],
    "javascript": [
        {"pattern": "req.query", "type": TaintSource.HTTP_PARAM},
        {"pattern": "req.params", "type": TaintSource.HTTP_PARAM},
        {"pattern": "req.body", "type": TaintSource.HTTP_BODY},
        {"pattern": "req.cookies", "type": TaintSource.HTTP_PARAM},
        {"pattern": "process.env", "type": TaintSource.ENV_READ},
        {"pattern": "process.argv", "type": TaintSource.CLI_ARG},
        {"pattern": "fs.readFile", "type": TaintSource.FILE_READ},
        {"pattern": "fs.readFileSync", "type": TaintSource.FILE_READ},
        {"pattern": "window.location", "type": TaintSource.HTTP_PARAM},
        {"pattern": "document.cookie", "type": TaintSource.HTTP_PARAM},
    ],
    "go": [
        {"pattern": "r.URL.Query().Get", "type": TaintSource.HTTP_PARAM},
        {"pattern": "r.FormValue", "type": TaintSource.HTTP_PARAM},
        {"pattern": "r.PostFormValue", "type": TaintSource.HTTP_PARAM},
        {"pattern": "r.Body", "type": TaintSource.HTTP_BODY},
        {"pattern": "r.Header.Get", "type": TaintSource.HTTP_PARAM},
        {"pattern": "os.Getenv", "type": TaintSource.ENV_READ},
        {"pattern": "os.Args", "type": TaintSource.CLI_ARG},
        {"pattern": "flag.Args", "type": TaintSource.CLI_ARG},
        {"pattern": "os.ReadFile", "type": TaintSource.FILE_READ},
        {"pattern": "ioutil.ReadFile", "type": TaintSource.FILE_READ},
        {"pattern": "bufio.NewReader", "type": TaintSource.STDIN},
        {"pattern": "fmt.Scan", "type": TaintSource.STDIN},
        {"pattern": "http.Get", "type": TaintSource.NETWORK_RECV},
    ],
    "java": [
        {"pattern": "request.getParameter", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.getHeader", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.getInputStream", "type": TaintSource.HTTP_BODY},
        {"pattern": "request.getReader", "type": TaintSource.HTTP_BODY},
        {"pattern": "request.getQueryString", "type": TaintSource.HTTP_PARAM},
        {"pattern": "System.getenv", "type": TaintSource.ENV_READ},
        {"pattern": "System.getProperty", "type": TaintSource.ENV_READ},
        {"pattern": "args[", "type": TaintSource.CLI_ARG},
        {"pattern": "new Scanner(System.in)", "type": TaintSource.STDIN},
        {"pattern": "Files.readAllBytes", "type": TaintSource.FILE_READ},
        {"pattern": "FileInputStream", "type": TaintSource.FILE_READ},
        {"pattern": "BufferedReader", "type": TaintSource.FILE_READ},
    ],
    "ruby": [
        {"pattern": "params[", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.params", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.env", "type": TaintSource.HTTP_PARAM},
        {"pattern": "request.body", "type": TaintSource.HTTP_BODY},
        {"pattern": "ENV[", "type": TaintSource.ENV_READ},
        {"pattern": "ARGV", "type": TaintSource.CLI_ARG},
        {"pattern": "File.read", "type": TaintSource.FILE_READ},
        {"pattern": "File.open", "type": TaintSource.FILE_READ},
        {"pattern": "IO.read", "type": TaintSource.FILE_READ},
        {"pattern": "gets", "type": TaintSource.STDIN},
        {"pattern": "STDIN.gets", "type": TaintSource.STDIN},
        {"pattern": "Net::HTTP.get", "type": TaintSource.NETWORK_RECV},
    ],
    "php": [
        {"pattern": "$_GET", "type": TaintSource.HTTP_PARAM},
        {"pattern": "$_POST", "type": TaintSource.HTTP_PARAM},
        {"pattern": "$_REQUEST", "type": TaintSource.HTTP_PARAM},
        {"pattern": "$_SERVER", "type": TaintSource.HTTP_PARAM},
        {"pattern": "$_COOKIE", "type": TaintSource.HTTP_PARAM},
        {"pattern": "$_FILES", "type": TaintSource.HTTP_BODY},
        {"pattern": "file_get_contents", "type": TaintSource.FILE_READ},
        {"pattern": "fread", "type": TaintSource.FILE_READ},
        {"pattern": "getenv", "type": TaintSource.ENV_READ},
        {"pattern": "$_ENV", "type": TaintSource.ENV_READ},
        {"pattern": "$argv", "type": TaintSource.CLI_ARG},
        {"pattern": "php://input", "type": TaintSource.HTTP_BODY},
        {"pattern": "curl_exec", "type": TaintSource.NETWORK_RECV},
    ],
    "rust": [
        {"pattern": "std::env::args", "type": TaintSource.CLI_ARG},
        {"pattern": "std::env::var", "type": TaintSource.ENV_READ},
        {"pattern": "std::fs::read", "type": TaintSource.FILE_READ},
        {"pattern": "std::fs::read_to_string", "type": TaintSource.FILE_READ},
        {"pattern": "std::io::stdin().read_line", "type": TaintSource.STDIN},
        {"pattern": "reqwest::get", "type": TaintSource.NETWORK_RECV},
        {"pattern": "warp::query", "type": TaintSource.HTTP_PARAM},
        {"pattern": "actix_web::web::Query", "type": TaintSource.HTTP_PARAM},
    ],
    "c": [
        {"pattern": "fopen", "type": TaintSource.FILE_READ},
        {"pattern": "fread", "type": TaintSource.FILE_READ},
        {"pattern": "read(", "type": TaintSource.FILE_READ},
        {"pattern": "getenv", "type": TaintSource.ENV_READ},
        {"pattern": "argv", "type": TaintSource.CLI_ARG},
        {"pattern": "scanf", "type": TaintSource.STDIN},
        {"pattern": "fgets", "type": TaintSource.STDIN},
        {"pattern": "gets(", "type": TaintSource.STDIN},
        {"pattern": "recv(", "type": TaintSource.NETWORK_RECV},
        {"pattern": "recvfrom", "type": TaintSource.NETWORK_RECV},
    ],
    "csharp": [
        {"pattern": "Request.QueryString", "type": TaintSource.HTTP_PARAM},
        {"pattern": "Request.Form", "type": TaintSource.HTTP_PARAM},
        {"pattern": "Request.Params", "type": TaintSource.HTTP_PARAM},
        {"pattern": "HttpContext.Request", "type": TaintSource.HTTP_PARAM},
        {"pattern": "Console.ReadLine", "type": TaintSource.STDIN},
        {"pattern": "Environment.GetEnvironmentVariable", "type": TaintSource.ENV_READ},
        {"pattern": "File.ReadAllBytes", "type": TaintSource.FILE_READ},
        {"pattern": "File.ReadAllText", "type": TaintSource.FILE_READ},
        {"pattern": "Environment.GetCommandLineArgs", "type": TaintSource.CLI_ARG},
        {"pattern": "HttpClient.GetAsync", "type": TaintSource.NETWORK_RECV},
    ],
    "shell": [
        {"pattern": "$1", "type": TaintSource.CLI_ARG},
        {"pattern": "$@", "type": TaintSource.CLI_ARG},
        {"pattern": "$HOME", "type": TaintSource.ENV_READ},
        {"pattern": "$USER", "type": TaintSource.ENV_READ},
        {"pattern": "read ", "type": TaintSource.STDIN},
        {"pattern": "$(curl ", "type": TaintSource.NETWORK_RECV},
        {"pattern": "$(wget ", "type": TaintSource.NETWORK_RECV},
    ],
}

# 多语言的 Sink 特征
SINK_PATTERNS: dict[str, list[dict]] = {
    "python": [
        {"pattern": "os.system", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "subprocess.call", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "subprocess.run", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "subprocess.Popen", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "subprocess.check_output", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "subprocess.check_call", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "eval", "type": TaintSink.CODE_EXEC},
        {"pattern": "exec", "type": TaintSink.CODE_EXEC},
        {"pattern": "compile", "type": TaintSink.CODE_EXEC},
        {"pattern": "pickle.load", "type": TaintSink.DESERIALIZE},
        {"pattern": "pickle.loads", "type": TaintSink.DESERIALIZE},
        {"pattern": "yaml.load", "type": TaintSink.DESERIALIZE},
        {"pattern": "marshal.loads", "type": TaintSink.DESERIALIZE},
        {"pattern": "cursor.execute", "type": TaintSink.SQL_EXEC},
        {"pattern": "connection.execute", "type": TaintSink.SQL_EXEC},
        {"pattern": "requests.post", "type": TaintSink.NETWORK_SEND},
        {"pattern": "requests.put", "type": TaintSink.NETWORK_SEND},
        {"pattern": "socket.send", "type": TaintSink.NETWORK_SEND},
        {"pattern": "open.*w", "type": TaintSink.FILE_WRITE},
    ],
    "javascript": [
        {"pattern": "child_process.exec", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "child_process.spawn", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "child_process.execSync", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "exec(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "spawn(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "eval", "type": TaintSink.CODE_EXEC},
        {"pattern": "Function(", "type": TaintSink.CODE_EXEC},
        {"pattern": "new Function", "type": TaintSink.CODE_EXEC},
        {"pattern": "setTimeout(", "type": TaintSink.CODE_EXEC},
        {"pattern": "setInterval(", "type": TaintSink.CODE_EXEC},
        {"pattern": "innerHTML", "type": TaintSink.HTML_OUTPUT},
        {"pattern": "dangerouslySetInnerHTML", "type": TaintSink.HTML_OUTPUT},
        {"pattern": "document.write", "type": TaintSink.HTML_OUTPUT},
        {"pattern": "fetch", "type": TaintSink.NETWORK_SEND},
        {"pattern": "axios.post", "type": TaintSink.NETWORK_SEND},
        {"pattern": "axios.put", "type": TaintSink.NETWORK_SEND},
        {"pattern": "XMLHttpRequest", "type": TaintSink.NETWORK_SEND},
    ],
    "go": [
        {"pattern": "exec.Command", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "os.StartProcess", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "syscall.Exec", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "db.Query", "type": TaintSink.SQL_EXEC},
        {"pattern": "db.Exec", "type": TaintSink.SQL_EXEC},
        {"pattern": "db.QueryRow", "type": TaintSink.SQL_EXEC},
        {"pattern": "json.Unmarshal", "type": TaintSink.DESERIALIZE},
        {"pattern": "yaml.Unmarshal", "type": TaintSink.DESERIALIZE},
        {"pattern": "gob.NewDecoder", "type": TaintSink.DESERIALIZE},
        {"pattern": "http.Post", "type": TaintSink.NETWORK_SEND},
        {"pattern": "http.Get", "type": TaintSink.NETWORK_SEND},
        {"pattern": "net.Dial", "type": TaintSink.NETWORK_SEND},
        {"pattern": "os.WriteFile", "type": TaintSink.FILE_WRITE},
        {"pattern": "ioutil.WriteFile", "type": TaintSink.FILE_WRITE},
        {"pattern": "template.HTML", "type": TaintSink.HTML_OUTPUT},
    ],
    "java": [
        {"pattern": "Runtime.getRuntime().exec", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "ProcessBuilder", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "ProcessBuilder.start", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "Statement.execute", "type": TaintSink.SQL_EXEC},
        {"pattern": "Statement.executeQuery", "type": TaintSink.SQL_EXEC},
        {"pattern": "PreparedStatement", "type": TaintSink.SQL_EXEC},
        {"pattern": "createStatement", "type": TaintSink.SQL_EXEC},
        {"pattern": "ObjectInputStream", "type": TaintSink.DESERIALIZE},
        {"pattern": "readObject", "type": TaintSink.DESERIALIZE},
        {"pattern": "XMLDecoder", "type": TaintSink.DESERIALIZE},
        {"pattern": "ScriptEngine.eval", "type": TaintSink.CODE_EXEC},
        {"pattern": "new URL", "type": TaintSink.NETWORK_SEND},
        {"pattern": "HttpURLConnection", "type": TaintSink.NETWORK_SEND},
        {"pattern": "Socket", "type": TaintSink.NETWORK_SEND},
        {"pattern": "FileWriter", "type": TaintSink.FILE_WRITE},
        {"pattern": "FileOutputStream", "type": TaintSink.FILE_WRITE},
    ],
    "ruby": [
        {"pattern": "system(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "exec(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "spawn(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "%x(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "`", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "eval(", "type": TaintSink.CODE_EXEC},
        {"pattern": "send(", "type": TaintSink.CODE_EXEC},
        {"pattern": "instance_eval", "type": TaintSink.CODE_EXEC},
        {"pattern": "class_eval", "type": TaintSink.CODE_EXEC},
        {"pattern": "YAML.load", "type": TaintSink.DESERIALIZE},
        {"pattern": "Marshal.load", "type": TaintSink.DESERIALIZE},
        {"pattern": "Net::HTTP", "type": TaintSink.NETWORK_SEND},
        {"pattern": "RestClient.post", "type": TaintSink.NETWORK_SEND},
        {"pattern": "File.write", "type": TaintSink.FILE_WRITE},
    ],
    "php": [
        {"pattern": "exec(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "system(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "shell_exec(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "passthru(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "proc_open(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "popen(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "eval(", "type": TaintSink.CODE_EXEC},
        {"pattern": "assert(", "type": TaintSink.CODE_EXEC},
        {"pattern": "create_function", "type": TaintSink.CODE_EXEC},
        {"pattern": "mysql_query(", "type": TaintSink.SQL_EXEC},
        {"pattern": "mysqli_query(", "type": TaintSink.SQL_EXEC},
        {"pattern": "pg_query(", "type": TaintSink.SQL_EXEC},
        {"pattern": "unserialize(", "type": TaintSink.DESERIALIZE},
        {"pattern": "include(", "type": TaintSink.CODE_EXEC},
        {"pattern": "require(", "type": TaintSink.CODE_EXEC},
        {"pattern": "curl_exec", "type": TaintSink.NETWORK_SEND},
        {"pattern": "file_put_contents", "type": TaintSink.FILE_WRITE},
        {"pattern": "header(", "type": TaintSink.HTML_OUTPUT},
    ],
    "rust": [
        {"pattern": "std::process::Command::new", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "Command::new", "type": TaintSink.COMMAND_EXEC},
        {"pattern": ".output()", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "std::process::Command::output", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "serde_json::from_str", "type": TaintSink.DESERIALIZE},
        {"pattern": "serde_yaml::from_str", "type": TaintSink.DESERIALIZE},
        {"pattern": "std::net::TcpStream::connect", "type": TaintSink.NETWORK_SEND},
        {"pattern": "reqwest::Client.post", "type": TaintSink.NETWORK_SEND},
        {"pattern": "std::fs::write", "type": TaintSink.FILE_WRITE},
        {"pattern": "unsafe", "type": TaintSink.CODE_EXEC},
    ],
    "c": [
        {"pattern": "system(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "popen(", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "exec", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "dlopen", "type": TaintSink.CODE_EXEC},
        {"pattern": "dlsym", "type": TaintSink.CODE_EXEC},
        {"pattern": "strcpy(", "type": TaintSink.CODE_EXEC},
        {"pattern": "strcat(", "type": TaintSink.CODE_EXEC},
        {"pattern": "sprintf(", "type": TaintSink.CODE_EXEC},
        {"pattern": "send(", "type": TaintSink.NETWORK_SEND},
        {"pattern": "sendto(", "type": TaintSink.NETWORK_SEND},
        {"pattern": "fprintf", "type": TaintSink.FILE_WRITE},
        {"pattern": "fwrite", "type": TaintSink.FILE_WRITE},
        {"pattern": "write(", "type": TaintSink.FILE_WRITE},
    ],
    "csharp": [
        {"pattern": "Process.Start", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "Process.StartInfo", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "SqlCommand", "type": TaintSink.SQL_EXEC},
        {"pattern": "SqlDataAdapter", "type": TaintSink.SQL_EXEC},
        {"pattern": "ExecuteNonQuery", "type": TaintSink.SQL_EXEC},
        {"pattern": "ExecuteReader", "type": TaintSink.SQL_EXEC},
        {"pattern": "JavaScriptSerializer.Deserialize", "type": TaintSink.DESERIALIZE},
        {"pattern": "BinaryFormatter.Deserialize", "type": TaintSink.DESERIALIZE},
        {"pattern": "XmlSerializer.Deserialize", "type": TaintSink.DESERIALIZE},
        {"pattern": "Assembly.Load", "type": TaintSink.CODE_EXEC},
        {"pattern": "WebClient.DownloadString", "type": TaintSink.NETWORK_SEND},
        {"pattern": "HttpClient.PostAsync", "type": TaintSink.NETWORK_SEND},
        {"pattern": "HttpClient.PutAsync", "type": TaintSink.NETWORK_SEND},
        {"pattern": "File.WriteAllBytes", "type": TaintSink.FILE_WRITE},
        {"pattern": "File.WriteAllText", "type": TaintSink.FILE_WRITE},
    ],
    "shell": [
        {"pattern": "eval ", "type": TaintSink.CODE_EXEC},
        {"pattern": "curl ", "type": TaintSink.NETWORK_SEND},
        {"pattern": "wget ", "type": TaintSink.NETWORK_SEND},
        {"pattern": "curl.*|.*sh", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "wget.*|.*sh", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "nc ", "type": TaintSink.NETWORK_SEND},
        {"pattern": "> /etc/", "type": TaintSink.FILE_WRITE},
        {"pattern": "source ", "type": TaintSink.CODE_EXEC},
        {"pattern": "chmod +s", "type": TaintSink.COMMAND_EXEC},
        {"pattern": "chown ", "type": TaintSink.COMMAND_EXEC},
    ],
}

# ── 攻击链定义 ──────────────────────────────────────────

ATTACK_CHAIN_DEFINITIONS: list[dict] = [
    {
        "name": "Download & Execute",
        "description": "从网络下载内容后解码并执行，这是远控木马和供应链攻击的核心手法",
        "severity": "critical",
        "steps": [
            {"type": "source", "source_types": ["network_recv", "http_param", "file_read"]},
            {"type": "transform", "keywords": ["decode", "base64", "b64decode", "fromhex", "atob", "decrypt", "decompress", "unzip"]},
            {"type": "sink", "sink_types": ["command_exec", "code_exec", "deserialize"]},
        ],
    },
    {
        "name": "Credential Theft & Exfil",
        "description": "读取敏感凭证文件或环境变量后通过网络外发",
        "severity": "critical",
        "steps": [
            {"type": "source", "source_types": ["env_read", "file_read"], "keywords": ["password", "secret", "token", "key", "credential", ".env", ".ssh", ".aws"]},
            {"type": "sink", "sink_types": ["network_send"]},
        ],
    },
    {
        "name": "Persistence via Scheduled Task",
        "description": "在系统中建立持久化机制，确保恶意代码在重启后继续运行",
        "severity": "critical",
        "steps": [
            {"type": "source", "source_types": ["file_read", "network_recv"]},
            {"type": "sink", "sink_types": ["file_write"], "keywords": ["cron", "systemd", "launchd", "Startup", "registry", "bashrc", "profile", "autostart"]},
        ],
    },
    {
        "name": "Privilege Escalation",
        "description": "尝试提升权限以获取更高级别的系统访问",
        "severity": "high",
        "steps": [
            {"type": "transform", "keywords": ["sudo", "chmod", "setuid", "SeImpersonatePrivilege", "runas"]},
            {"type": "sink", "sink_types": ["command_exec", "file_write"]},
        ],
    },
    {
        "name": "Data Exfiltration",
        "description": "将本地数据编码后通过网络发送到外部",
        "severity": "high",
        "steps": [
            {"type": "source", "source_types": ["file_read", "env_read"]},
            {"type": "transform", "keywords": ["encode", "base64", "b64encode", "btoa", "encrypt", "compress", "zip"]},
            {"type": "sink", "sink_types": ["network_send"]},
        ],
    },
    {
        "name": "Dynamic Code Injection",
        "description": "动态构造代码并执行，常见于混淆恶意软件",
        "severity": "critical",
        "steps": [
            {"type": "source", "source_types": ["network_recv", "http_param", "file_read"]},
            {"type": "transform", "keywords": ["decode", "base64", "eval", "compile", "exec"]},
            {"type": "sink", "sink_types": ["code_exec"]},
        ],
    },
]
