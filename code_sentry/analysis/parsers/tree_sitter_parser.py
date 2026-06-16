"""
Tree-sitter 多语言解析器。

支持 JavaScript, TypeScript, Go, Java, Ruby, PHP, Rust, C, C++, C#, Bash。
依赖: pip install tree-sitter tree-sitter-languages

如果 tree-sitter 未安装，解析器返回空结果而不是报错。
"""

from code_sentry.analysis.ast_nodes import (
    UnifiedNode, UnifiedNodeType, UnifiedLocation, ParseResult,
)

# 尝试导入 tree-sitter
_TREE_SITTER_AVAILABLE = False
_TREE_SITTER_LANGS = {}

try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjs
    import tree_sitter_typescript as tsts
    _TREE_SITTER_AVAILABLE = True
    _TREE_SITTER_LANGS = {
        'python': tspython.language(),
        'javascript': tsjs.language(),
        'typescript': tsts.language_typescript(),
        'tsx': tsts.language_tsx(),
    }
except ImportError:
    pass

# 尝试 tree-sitter-languages（备用方案）
if not _TREE_SITTER_AVAILABLE:
    try:
        import tree_sitter_languages
        _TREE_SITTER_AVAILABLE = True
        _TREE_SITTER_LANGS = {
            'python': tree_sitter_languages.get_language('python'),
            'javascript': tree_sitter_languages.get_language('javascript'),
            'typescript': tree_sitter_languages.get_language('typescript'),
            'tsx': tree_sitter_languages.get_language('tsx'),
            'go': tree_sitter_languages.get_language('go'),
            'java': tree_sitter_languages.get_language('java'),
            'ruby': tree_sitter_languages.get_language('ruby'),
            'php': tree_sitter_languages.get_language('php'),
            'rust': tree_sitter_languages.get_language('rust'),
            'c': tree_sitter_languages.get_language('c'),
            'cpp': tree_sitter_languages.get_language('cpp'),
            'csharp': tree_sitter_languages.get_language('c_sharp'),
            'bash': tree_sitter_languages.get_language('bash'),
        }
    except ImportError:
        _TREE_SITTER_AVAILABLE = False

# tree-sitter 核心
_TREE_SITTER_CORE = False
_Parser = None
try:
    from tree_sitter import Language, Parser
    _TREE_SITTER_CORE = True
    _Parser = Parser
except ImportError:
    pass

_TREE_SITTER_AVAILABLE = _TREE_SITTER_AVAILABLE and _TREE_SITTER_CORE


# ── 语言到 tree-sitter 语言的映射 ────────────────────────

_LANG_MAP_TS = {
    'python': 'python',
    'javascript': 'javascript',
    'js': 'javascript',
    'typescript': 'typescript',
    'ts': 'typescript',
    'tsx': 'tsx',
    'go': 'go',
    'java': 'java',
    'ruby': 'ruby',
    'php': 'php',
    'rust': 'rust',
    'c': 'c',
    'cpp': 'cpp',
    'csharp': 'csharp',
    'bash': 'bash',
}

# ── 节点类型映射：tree-sitter → UnifiedNodeType ──────────

# 各语言函数定义节点类型
_FUNC_DEF_TYPES = {
    'python': {'function_definition'},
    'javascript': {'function_declaration', 'function_expression', 'arrow_function', 'method_definition'},
    'typescript': {'function_declaration', 'function_expression', 'arrow_function', 'method_definition'},
    'tsx': {'function_declaration', 'function_expression', 'arrow_function', 'method_definition'},
    'go': {'function_declaration', 'method_declaration'},
    'java': {'method_declaration', 'constructor_declaration'},
    'ruby': {'method', 'singleton_method'},
    'php': {'function_definition', 'method_declaration'},
    'rust': {'function_item', 'function_signature_item'},
    'c': {'function_definition'},
    'cpp': {'function_definition'},
    'csharp': {'method_declaration'},
    'bash': {'function_definition'},
}

# 调用表达式
_CALL_TYPES = {
    'python': {'call'},
    'javascript': {'call_expression'},
    'typescript': {'call_expression'},
    'tsx': {'call_expression'},
    'go': {'call_expression'},
    'java': {'method_invocation'},
    'ruby': {'call', 'method_call'},
    'php': {'function_call_expression', 'method_call_expression'},
    'rust': {'call_expression', 'method_call_expression'},
    'c': {'call_expression'},
    'cpp': {'call_expression'},
    'csharp': {'invocation_expression'},
    'bash': {'command', 'command_substitution'},
}

# 赋值
_ASSIGN_TYPES = {
    'python': {'assignment', 'augmented_assignment'},
    'javascript': {'assignment_expression', 'variable_declarator'},
    'typescript': {'assignment_expression', 'variable_declarator'},
    'tsx': {'assignment_expression', 'variable_declarator'},
    'go': {'assignment_statement', 'short_var_declaration'},
    'java': {'assignment_expression', 'variable_declarator'},
    'ruby': {'assignment'},
    'php': {'assignment_expression'},
    'rust': {'let_declaration', 'assignment_expression'},
    'c': {'assignment_expression', 'init_declarator'},
    'cpp': {'assignment_expression', 'init_declarator'},
    'csharp': {'assignment_expression', 'variable_declarator'},
    'bash': {'variable_assignment'},
}

# 标识符
_IDENT_TYPES = {
    'python': {'identifier'},
    'javascript': {'identifier'},
    'typescript': {'identifier'},
    'tsx': {'identifier'},
    'go': {'identifier'},
    'java': {'identifier'},
    'ruby': {'identifier'},
    'php': {'name', 'variable_name'},
    'rust': {'identifier'},
    'c': {'identifier'},
    'cpp': {'identifier'},
    'csharp': {'identifier'},
    'bash': {'word', 'variable_name'},
}

# 字符串
_STRING_TYPES = {
    'python': {'string'},
    'javascript': {'string', 'template_string'},
    'typescript': {'string', 'template_string'},
    'tsx': {'string', 'template_string'},
    'go': {'interpreted_string_literal', 'raw_string_literal'},
    'java': {'string_literal'},
    'ruby': {'string', 'string_content'},
    'php': {'string'},
    'rust': {'string_literal'},
    'c': {'string_literal'},
    'cpp': {'string_literal'},
    'csharp': {'string_literal'},
    'bash': {'string', 'raw_string'},
}

# import
_IMPORT_TYPES = {
    'python': {'import_statement', 'import_from_statement'},
    'javascript': {'import_statement', 'import'},
    'typescript': {'import_statement', 'import'},
    'tsx': {'import_statement', 'import'},
    'go': {'import_declaration'},
    'java': {'import_declaration'},
    'ruby': {'require', 'require_relative'},
    'php': {'require_once', 'include_once', 'use_declaration'},
    'rust': {'use_declaration'},
    'c': {'preproc_include'},
    'cpp': {'preproc_include'},
    'csharp': {'using_directive'},
    'bash': {'source', 'dot'},
}


class TreeSitterParser:
    """通用 tree-sitter 多语言解析器"""

    def __init__(self):
        self._parsers: dict[str, Parser] = {}

    def _get_parser(self, lang: str) -> Parser | None:
        """获取或创建语言解析器"""
        if lang not in self._parsers:
            ts_lang_key = _LANG_MAP_TS.get(lang, lang)
            ts_lang = _TREE_SITTER_LANGS.get(ts_lang_key)
            if not ts_lang:
                return None
            parser = _Parser()
            parser.set_language(ts_lang)
            self._parsers[lang] = parser
        return self._parsers[lang]

    def parse(self, file_path: str, source_code: bytes, lang: str) -> ParseResult:
        """解析源代码"""
        parser = self._get_parser(lang)
        if not parser:
            return ParseResult(
                file_path=file_path,
                language=lang,
                errors=[f'不支持的 tree-sitter 语言: {lang}'],
            )

        tree = parser.parse(source_code)
        root_node = tree.root_node
        source_str = source_code.decode('utf-8', errors='ignore')

        converter = TSToUnified(file_path, source_str, lang)
        unified_root = converter.convert(root_node)

        return ParseResult(
            file_path=file_path,
            language=lang,
            root=unified_root,
            functions=converter.functions,
            calls=converter.calls,
            imports=converter.imports,
        )


class TSToUnified:
    """Tree-sitter CST → 统一 AST"""

    def __init__(self, file_path: str, source_code: str, lang: str):
        self.file_path = file_path
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.lang = lang
        self.current_function: str | None = None
        self.functions: list[dict] = []
        self.calls: list[dict] = []
        self.imports: list[str] = []

    def convert(self, node) -> UnifiedNode:
        """主转换入口"""
        return self._convert_node(node)

    def _convert_node(self, node) -> UnifiedNode:
        """递归转换 tree-sitter 节点"""
        node_type = node.type

        # 函数定义
        if node_type in _FUNC_DEF_TYPES.get(self.lang, set()):
            return self._handle_function_def(node)

        # 函数调用
        if node_type in _CALL_TYPES.get(self.lang, set()):
            return self._handle_call(node)

        # 赋值
        if node_type in _ASSIGN_TYPES.get(self.lang, set()):
            return self._handle_assignment(node)

        # 字符串
        if node_type in _STRING_TYPES.get(self.lang, set()):
            return self._handle_string(node)

        # import
        if node_type in _IMPORT_TYPES.get(self.lang, set()):
            return self._handle_import(node)

        # 默认：递归处理子节点
        children = [self._convert_node(c) for c in node.children]
        children = [c for c in children if c is not None]

        # 标识符
        if node_type in _IDENT_TYPES.get(self.lang, set()):
            text = self._text(node)
            return UnifiedNode(
                type=UnifiedNodeType.IDENTIFIER,
                name=text,
                location=self._loc(node),
                children=children,
            )

        if children:
            return UnifiedNode(
                type=UnifiedNodeType.IDENTIFIER,
                location=self._loc(node),
                children=children,
            )
        return None

    def _handle_function_def(self, node) -> UnifiedNode:
        """处理函数/方法定义"""
        name_node = node.child_by_field_name('name')
        name = self._text(name_node) if name_node else 'anonymous'

        params_node = node.child_by_field_name('parameters')
        body_node = node.child_by_field_name('body')

        children = []
        if body_node:
            for c in body_node.children:
                child = self._convert_node(c)
                if child:
                    children.append(child)

        self.functions.append({
            'name': name,
            'params': [],
            'line_start': node.start_point[0] + 1,
            'line_end': node.end_point[0] + 1,
        })

        return UnifiedNode(
            type=UnifiedNodeType.FUNCTION_DEF,
            name=name,
            location=self._loc(node),
            children=children,
            source_code=self._text(node),
        )

    def _handle_call(self, node) -> UnifiedNode:
        """处理函数/方法调用"""
        func_node = node.child_by_field_name('function')
        func_name = self._text(func_node) if func_node else ''

        args_node = node.child_by_field_name('arguments')
        arg_children = []
        if args_node:
            for c in args_node.children:
                child = self._convert_node(c)
                if child:
                    arg_children.append(child)

        # 简化函数名（去掉括号内容）
        simple_name = func_name.split('(')[0].strip()

        if self.current_function:
            self.calls.append({
                'caller': self.current_function,
                'callee': simple_name,
                'arguments': [],
                'line': node.start_point[0] + 1,
            })

        return UnifiedNode(
            type=UnifiedNodeType.CALL,
            name=simple_name,
            location=self._loc(node),
            children=arg_children,
            source_code=self._text(node),
        )

    def _handle_assignment(self, node) -> UnifiedNode:
        """处理赋值"""
        left_node = node.child_by_field_name('left')
        right_node = node.child_by_field_name('right')
        value_node = node.child_by_field_name('value')

        target = left_node or value_node
        source = right_node

        target_name = self._text(target) if target else ''
        children = []
        if source:
            child = self._convert_node(source)
            if child:
                children.append(child)

        return UnifiedNode(
            type=UnifiedNodeType.ASSIGNMENT,
            name=target_name,
            location=self._loc(node),
            children=children,
            source_code=self._text(node),
            attributes={'target_names': [target_name]},
        )

    def _handle_string(self, node) -> UnifiedNode:
        return UnifiedNode(
            type=UnifiedNodeType.STRING,
            value=self._text(node),
            location=self._loc(node),
        )

    def _handle_import(self, node) -> UnifiedNode:
        text = self._text(node)
        self.imports.append(text)
        return UnifiedNode(
            type=UnifiedNodeType.IMPORT,
            name=text[:80],
            location=self._loc(node),
        )

    def _loc(self, node) -> UnifiedLocation:
        return UnifiedLocation(
            file_path=self.file_path,
            line_start=node.start_point[0] + 1,
            line_end=node.end_point[0] + 1,
            col_start=node.start_point[1],
            col_end=node.end_point[1],
        )

    def _text(self, node) -> str:
        """获取节点的源代码文本"""
        if node is None:
            return ''
        try:
            start_byte = node.start_byte
            end_byte = node.end_byte
            return self.source_code[start_byte:end_byte]
        except (IndexError, AttributeError):
            return node.text.decode('utf-8', errors='ignore') if hasattr(node, 'text') else ''


# ── 公共接口 ──────────────────────────────────────────────

def is_available() -> bool:
    """检查 tree-sitter 是否可用"""
    return _TREE_SITTER_AVAILABLE


def get_supported_languages() -> list[str]:
    """获取 tree-sitter 支持的语言列表"""
    return list(_LANG_MAP_TS.keys())


def parse_with_tree_sitter(file_path: str, lang: str) -> ParseResult:
    """使用 tree-sitter 解析文件"""
    if not _TREE_SITTER_AVAILABLE:
        return ParseResult(
            file_path=file_path,
            language=lang,
            errors=['tree-sitter 未安装。请运行: pip install tree-sitter tree-sitter-languages'],
        )

    try:
        with open(file_path, 'rb') as f:
            source_bytes = f.read()
    except OSError as e:
        return ParseResult(file_path=file_path, language=lang, errors=[f'文件读取失败: {e}'])

    parser = TreeSitterParser()
    return parser.parse(file_path, source_bytes, lang)
