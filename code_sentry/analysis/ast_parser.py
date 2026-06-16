"""
AST 解析器：将源代码解析为统一的抽象语法树，提取符号和调用关系。

Python 使用内置 ast 模块（零依赖，高精度）。
其他语言使用 tree-sitter（可选，需安装 tree-sitter 和对应语言包）。
"""

import ast
import os
from code_sentry.analysis.models import (
    Symbol, SymbolKind, CallEdge, Location, TaintSource, TaintSink,
    SOURCE_PATTERNS, SINK_PATTERNS, DeepAnalysisResult,
)


class ASTParseError(Exception):
    """AST 解析错误"""
    pass


# ── Python AST 解析器 ────────────────────────────────────


class PythonAnalyzer(ast.NodeVisitor):
    """遍历 Python AST，提取符号和调用关系"""

    def __init__(self, file_path: str, source_code: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.symbols: list[Symbol] = []
        self.call_edges: list[CallEdge] = []
        self.current_function: str | None = None
        self.current_class: str | None = None
        # 变量追踪：变量名 → 最近的赋值来源
        self.var_sources: dict[str, list[str]] = {}
        self.errors: list[str] = []

    def _loc(self, node: ast.AST) -> Location:
        """提取 AST 节点的位置信息"""
        return Location(
            file_path=self.file_path,
            line_start=getattr(node, 'lineno', 1),
            line_end=getattr(node, 'end_lineno', getattr(node, 'lineno', 1)),
            col_start=getattr(node, 'col_offset', 0),
            col_end=getattr(node, 'end_col_offset', getattr(node, 'col_offset', 0) + 1),
        )

    def _get_source(self, node: ast.AST) -> str:
        """获取节点对应的源代码片段"""
        try:
            start_line = getattr(node, 'lineno', 1) - 1
            end_line = getattr(node, 'end_lineno', start_line + 1)
            return '\n'.join(self.source_lines[start_line:end_line])
        except (IndexError, AttributeError):
            return ""

    def visit_FunctionDef(self, node: ast.FunctionDef):
        """函数定义"""
        prev_func = self.current_function
        self.current_function = node.name

        self.symbols.append(Symbol(
            name=node.name,
            kind=SymbolKind.FUNCTION,
            location=self._loc(node),
            parent=self.current_class,
        ))

        # 记录参数（潜在污点来源）
        for arg in node.args.args:
            self.symbols.append(Symbol(
                name=arg.arg,
                kind=SymbolKind.PARAMETER,
                location=self._loc(arg),
                parent=node.name,
            ))

        self.generic_visit(node)
        self.current_function = prev_func

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef):
        prev_class = self.current_class
        self.current_class = node.name
        self.symbols.append(Symbol(
            name=node.name,
            kind=SymbolKind.CLASS,
            location=self._loc(node),
        ))
        self.generic_visit(node)
        self.current_class = prev_class

    def visit_Call(self, node: ast.Call):
        """函数调用"""
        # 提取被调用函数名
        callee_name = self._resolve_callable(node.func)

        if callee_name and self.current_function:
            # 记录调用边
            self.call_edges.append(CallEdge(
                caller=self.current_function,
                callee=callee_name,
                location=self._loc(node),
                arguments=[self._get_source(a) for a in node.args],
            ))

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        """变量赋值 — 追踪数据流"""
        value_source = self._get_source(node.value)

        for target in node.targets:
            target_name = self._resolve_name(target)
            if target_name:
                self.symbols.append(Symbol(
                    name=target_name,
                    kind=SymbolKind.VARIABLE,
                    location=self._loc(node),
                    parent=self.current_function,
                ))

                # 记录变量来源
                if target_name not in self.var_sources:
                    self.var_sources[target_name] = []
                self.var_sources[target_name].append(value_source)

        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        """类型注解赋值"""
        if node.target:
            target_name = self._resolve_name(node.target)
            if target_name and node.value:
                self.symbols.append(Symbol(
                    name=target_name,
                    kind=SymbolKind.VARIABLE,
                    location=self._loc(node),
                    parent=self.current_function,
                ))
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            self.symbols.append(Symbol(
                name=alias.name,
                kind=SymbolKind.IMPORT,
                location=self._loc(node),
            ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for alias in node.names:
            full_name = f"{node.module}.{alias.name}" if node.module else alias.name
            self.symbols.append(Symbol(
                name=full_name,
                kind=SymbolKind.IMPORT,
                location=self._loc(node),
            ))
        self.generic_visit(node)

    def _resolve_callable(self, node: ast.AST) -> str | None:
        """解析被调用对象的名称"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            obj = self._resolve_callable(node.value)
            if obj:
                return f"{obj}.{node.attr}"
            return node.attr
        elif isinstance(node, ast.Subscript):
            return self._resolve_callable(node.value)
        return None

    def _resolve_name(self, node: ast.AST) -> str | None:
        """解析变量名"""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return self._resolve_callable(node)
        return None

    def analyze(self) -> DeepAnalysisResult:
        """执行完整分析"""
        return DeepAnalysisResult(
            file_path=self.file_path,
            language="python",
            symbols=self.symbols,
            call_graph=self.call_edges,
        )


# ── 通用解析入口 ────────────────────────────────────────


_LANGUAGE_PARSERS = {
    '.py': 'python',
    '.pyw': 'python',
    '.pyx': 'python',
}


def parse_file(file_path: str) -> DeepAnalysisResult:
    """解析单个文件，返回深度分析结果"""
    _, ext = os.path.splitext(file_path)
    lang = _LANGUAGE_PARSERS.get(ext.lower())

    if lang != 'python':
        return DeepAnalysisResult(
            file_path=file_path,
            language=lang or 'unknown',
            errors=['不支持的语言（深度分析目前仅支持 Python，tree-sitter 支持正在开发中）'],
        )

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return DeepAnalysisResult(
            file_path=file_path,
            language='python',
            errors=[f'文件读取失败: {e}'],
        )

    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError as e:
        return DeepAnalysisResult(
            file_path=file_path,
            language='python',
            errors=[f'语法错误: {e}'],
        )

    analyzer = PythonAnalyzer(file_path, source_code)
    analyzer.visit(tree)
    result = analyzer.analyze()
    result.errors = analyzer.errors

    return result


def is_supported(file_path: str) -> bool:
    """检查文件是否支持深度分析"""
    _, ext = os.path.splitext(file_path)
    return ext.lower() in _LANGUAGE_PARSERS
