"""
统一 AST 节点模型。

无论底层解析器是 Python ast 模块还是 tree-sitter，
都输出这套统一的节点类型，供污点追踪和攻击链检测消费。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class UnifiedNodeType(str, Enum):
    """统一 AST 节点类型"""
    # 声明
    FUNCTION_DEF = "function_def"
    CLASS_DEF = "class_def"
    VARIABLE_DECL = "variable_decl"
    PARAMETER = "parameter"
    IMPORT = "import"

    # 表达式
    CALL = "call"
    ASSIGNMENT = "assignment"
    BINARY_OP = "binary_op"
    ATTRIBUTE_ACCESS = "attribute_access"
    SUBSCRIPT = "subscript"

    # 字面量
    STRING = "string"
    NUMBER = "number"
    LIST = "list"
    DICT = "dict"

    # 引用
    IDENTIFIER = "identifier"

    # 控制流
    IF_STMT = "if_stmt"
    FOR_STMT = "for_stmt"
    WHILE_STMT = "while_stmt"
    RETURN = "return"
    TRY_STMT = "try_stmt"


@dataclass
class UnifiedLocation:
    """统一位置信息"""
    file_path: str
    line_start: int
    line_end: int
    col_start: int = 0
    col_end: int = 0


@dataclass
class UnifiedNode:
    """统一 AST 节点"""
    type: UnifiedNodeType
    name: str = ""                          # 函数名、变量名等
    value: str = ""                         # 字面量值、运算符等
    location: UnifiedLocation | None = None
    children: list['UnifiedNode'] = field(default_factory=list)
    attributes: dict[str, Any] = field(default_factory=dict)
    source_code: str = ""                   # 原始源代码片段

    def find_all(self, node_type: UnifiedNodeType) -> list['UnifiedNode']:
        """递归查找所有指定类型的子节点"""
        results = []
        if self.type == node_type:
            results.append(self)
        for child in self.children:
            results.extend(child.find_all(node_type))
        return results

    def find_first(self, node_type: UnifiedNodeType) -> 'UnifiedNode | None':
        """递归查找第一个指定类型的子节点"""
        if self.type == node_type:
            return self
        for child in self.children:
            found = child.find_first(node_type)
            if found:
                return found
        return None

    def walk(self):
        """深度优先遍历所有节点"""
        yield self
        for child in self.children:
            yield from child.walk()

    def to_dict(self, max_depth: int = 3) -> dict:
        """转为可序列化的字典（调试用）"""
        d = {'type': self.type.value, 'name': self.name, 'value': self.value}
        if self.location:
            d['line'] = self.location.line_start
        if max_depth > 0 and self.children:
            d['children'] = [c.to_dict(max_depth - 1) for c in self.children[:20]]
        return d


@dataclass
class ParseResult:
    """解析结果"""
    file_path: str
    language: str
    root: UnifiedNode | None = None
    errors: list[str] = field(default_factory=list)
    functions: list[dict] = field(default_factory=list)   # {name, params, line_start, line_end}
    calls: list[dict] = field(default_factory=list)       # {caller, callee, arguments, line}
    imports: list[str] = field(default_factory=list)


# ── 语言配置 ──────────────────────────────────────────────

# 支持的语言及其文件扩展名
LANGUAGE_EXTENSIONS: dict[str, list[str]] = {
    'python': ['.py', '.pyw', '.pyx', '.pxd'],
    'javascript': ['.js', '.mjs', '.cjs', '.jsx'],
    'typescript': ['.ts', '.tsx'],
    'go': ['.go'],
    'java': ['.java', '.kt', '.kts'],
    'ruby': ['.rb'],
    'php': ['.php', '.phtml'],
    'rust': ['.rs'],
    'c': ['.c', '.h'],
    'cpp': ['.cpp', '.cc', '.cxx', '.hpp'],
    'csharp': ['.cs'],
    'bash': ['.sh', '.bash', '.zsh'],
}


def get_language(file_path: str) -> str | None:
    """根据文件扩展名推断语言"""
    import os
    _, ext = os.path.splitext(file_path.lower())
    for lang, exts in LANGUAGE_EXTENSIONS.items():
        if ext in exts:
            return lang
    # Dockerfile / 特殊文件名
    basename = os.path.basename(file_path.lower())
    if basename.startswith('dockerfile'):
        return 'dockerfile'
    return None
