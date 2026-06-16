"""
Python AST 解析器：使用内置 ast 模块，输出统一 AST 节点。
零外部依赖，始终可用。
"""

import ast
from code_sentry.analysis.ast_nodes import (
    UnifiedNode, UnifiedNodeType, UnifiedLocation, ParseResult,
)


class PythonToUnified(ast.NodeVisitor):
    """将 Python AST 转换为统一 AST"""

    def __init__(self, file_path: str, source_lines: list[str]):
        self.file_path = file_path
        self.source_lines = source_lines
        self.current_function: str | None = None
        self.functions: list[dict] = []
        self.calls: list[dict] = []
        self.imports: list[str] = []

    def _loc(self, node: ast.AST) -> UnifiedLocation:
        return UnifiedLocation(
            file_path=self.file_path,
            line_start=getattr(node, 'lineno', 1),
            line_end=getattr(node, 'end_lineno', getattr(node, 'lineno', 1)),
            col_start=getattr(node, 'col_offset', 0),
            col_end=getattr(node, 'end_col_offset', getattr(node, 'col_offset', 0)),
        )

    def _source(self, node: ast.AST) -> str:
        try:
            sl = getattr(node, 'lineno', 1) - 1
            el = getattr(node, 'end_lineno', sl + 1)
            return '\n'.join(self.source_lines[sl:el])
        except (IndexError, AttributeError):
            return ""

    # ── 声明类 ──

    def visit_FunctionDef(self, node: ast.FunctionDef) -> UnifiedNode:
        prev = self.current_function
        self.current_function = node.name

        # 记录函数信息
        self.functions.append({
            'name': node.name,
            'params': [a.arg for a in node.args.args],
            'line_start': node.lineno,
            'line_end': getattr(node, 'end_lineno', node.lineno),
        })

        # 递归处理函数体
        body_nodes = []
        for stmt in node.body:
            child = self.visit(stmt)
            if child:
                body_nodes.append(child)

        self.current_function = prev

        return UnifiedNode(
            type=UnifiedNodeType.FUNCTION_DEF,
            name=node.name,
            location=self._loc(node),
            children=body_nodes,
            source_code=self._source(node),
        )

    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> UnifiedNode:
        body_nodes = []
        for stmt in node.body:
            child = self.visit(stmt)
            if child:
                body_nodes.append(child)

        return UnifiedNode(
            type=UnifiedNodeType.CLASS_DEF,
            name=node.name,
            location=self._loc(node),
            children=body_nodes,
        )

    # ── 表达式类 ──

    def visit_Call(self, node: ast.Call) -> UnifiedNode:
        # 解析被调用函数名
        func_name = self._name_of(node.func)

        # 记录调用关系
        if self.current_function:
            self.calls.append({
                'caller': self.current_function,
                'callee': func_name,
                'arguments': [self._source(a) for a in node.args],
                'line': node.lineno,
            })

        # 递归处理参数
        arg_nodes = []
        for arg in node.args:
            child = self.visit(arg)
            if child:
                arg_nodes.append(child)

        for kw in node.keywords:
            child = self.visit(kw.value)
            if child:
                arg_nodes.append(child)

        return UnifiedNode(
            type=UnifiedNodeType.CALL,
            name=func_name,
            location=self._loc(node),
            children=arg_nodes,
            source_code=self._source(node),
        )

    def visit_Assign(self, node: ast.Assign) -> UnifiedNode:
        value_node = self.visit(node.value) if node.value else None
        target_names = [self._name_of(t) for t in node.targets]

        children = []
        if value_node:
            children.append(value_node)

        return UnifiedNode(
            type=UnifiedNodeType.ASSIGNMENT,
            name=target_names[0] if target_names else '',
            location=self._loc(node),
            children=children,
            source_code=self._source(node),
            attributes={'target_names': target_names},
        )

    def visit_AnnAssign(self, node: ast.AnnAssign) -> UnifiedNode:
        name = self._name_of(node.target) if node.target else ''
        val_node = self.visit(node.value) if node.value else None
        return UnifiedNode(
            type=UnifiedNodeType.ASSIGNMENT,
            name=name,
            location=self._loc(node),
            children=[val_node] if val_node else [],
        )

    def visit_Name(self, node: ast.Name) -> UnifiedNode:
        return UnifiedNode(
            type=UnifiedNodeType.IDENTIFIER,
            name=node.id,
            location=self._loc(node),
        )

    def visit_Attribute(self, node: ast.Attribute) -> UnifiedNode:
        obj = self.visit(node.value) if node.value else None
        return UnifiedNode(
            type=UnifiedNodeType.ATTRIBUTE_ACCESS,
            name=node.attr,
            location=self._loc(node),
            children=[obj] if obj else [],
            attributes={'full_name': self._name_of(node)},
        )

    def visit_Subscript(self, node: ast.Subscript) -> UnifiedNode:
        obj = self.visit(node.value) if node.value else None
        return UnifiedNode(
            type=UnifiedNodeType.SUBSCRIPT,
            name=self._name_of(node.value) if node.value else '',
            location=self._loc(node),
            children=[obj] if obj else [],
        )

    def visit_BinOp(self, node: ast.BinOp) -> UnifiedNode:
        left = self.visit(node.left) if node.left else None
        right = self.visit(node.right) if node.right else None
        return UnifiedNode(
            type=UnifiedNodeType.BINARY_OP,
            value=type(node.op).__name__,
            location=self._loc(node),
            children=[n for n in [left, right] if n],
        )

    # ── 字面量类 ──

    def visit_Constant(self, node: ast.Constant) -> UnifiedNode:
        if isinstance(node.value, str):
            return UnifiedNode(
                type=UnifiedNodeType.STRING,
                value=node.value,
                location=self._loc(node),
            )
        return UnifiedNode(
            type=UnifiedNodeType.NUMBER if isinstance(node.value, (int, float)) else UnifiedNodeType.STRING,
            value=str(node.value),
            location=self._loc(node),
        )

    def visit_List(self, node: ast.List) -> UnifiedNode:
        children = [self.visit(e) for e in node.elts if e]
        return UnifiedNode(
            type=UnifiedNodeType.LIST,
            location=self._loc(node),
            children=[c for c in children if c],
        )

    def visit_Dict(self, node: ast.Dict) -> UnifiedNode:
        children = []
        for k, v in zip(node.keys, node.values):
            if k:
                children.append(self.visit(k))
            if v:
                children.append(self.visit(v))
        return UnifiedNode(
            type=UnifiedNodeType.DICT,
            location=self._loc(node),
            children=[c for c in children if c],
        )

    # ── Import 类 ──

    def visit_Import(self, node: ast.Import) -> UnifiedNode:
        names = [a.name for a in node.names]
        self.imports.extend(names)
        return UnifiedNode(
            type=UnifiedNodeType.IMPORT,
            name=','.join(names),
            location=self._loc(node),
        )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> UnifiedNode:
        module = node.module or ''
        names = [f"{module}.{a.name}" for a in node.names]
        self.imports.extend(names)
        return UnifiedNode(
            type=UnifiedNodeType.IMPORT,
            name=','.join(names),
            location=self._loc(node),
        )

    # ── 通用回退 ──

    def generic_visit(self, node: ast.AST) -> UnifiedNode | None:
        children = []
        for field_name, value in ast.iter_fields(node):
            if isinstance(value, ast.AST):
                child = self.visit(value)
                if child:
                    children.append(child)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, ast.AST):
                        child = self.visit(item)
                        if child:
                            children.append(child)

        if children:
            return UnifiedNode(
                type=UnifiedNodeType.IDENTIFIER,
                location=self._loc(node),
                children=children,
            )
        return None

    # ── 辅助方法 ──

    def _name_of(self, node: ast.AST) -> str:
        """递归解析节点的完整名称"""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return f"{self._name_of(node.value)}.{node.attr}"
        if isinstance(node, ast.Subscript):
            return self._name_of(node.value)
        if isinstance(node, ast.Call):
            return self._name_of(node.func)
        if isinstance(node, ast.Constant):
            return repr(node.value)
        return ''


def parse_python(file_path: str, source_code: str) -> ParseResult:
    """解析 Python 源代码"""
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError as e:
        return ParseResult(
            file_path=file_path,
            language='python',
            errors=[f'Syntax error: {e}'],
        )

    source_lines = source_code.splitlines()
    converter = PythonToUnified(file_path, source_lines)
    root = converter.visit(tree)

    return ParseResult(
        file_path=file_path,
        language='python',
        root=root,
        functions=converter.functions,
        calls=converter.calls,
        imports=converter.imports,
    )
