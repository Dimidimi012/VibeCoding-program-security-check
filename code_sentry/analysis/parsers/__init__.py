"""
解析器层：根据语言自动选择 Python ast 或 tree-sitter 后端。
"""

from code_sentry.analysis.parsers.python_parser import parse_python
from code_sentry.analysis.parsers.tree_sitter_parser import (
    parse_with_tree_sitter,
    is_available as tree_sitter_available,
    get_supported_languages as tree_sitter_languages,
)
from code_sentry.analysis.ast_nodes import ParseResult, get_language

# Python 原生支持（始终可用）
_BUILTIN_LANGS = {'python'}

# tree-sitter 支持的语言（需要安装）
_TREE_SITTER_LANGS = set(tree_sitter_languages()) if tree_sitter_available() else set()

# 所有支持深度分析的语言
SUPPORTED_LANGUAGES = _BUILTIN_LANGS | _TREE_SITTER_LANGS


def parse_file(file_path: str) -> ParseResult:
    """解析单个文件，自动选择解析器后端"""
    lang = get_language(file_path)
    if not lang:
        return ParseResult(
            file_path=file_path,
            language='unknown',
            errors=[f'不支持的语言: {file_path}'],
        )

    # Python: 使用内置 ast（更快更精确）
    if lang == 'python':
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                source = f.read()
        except OSError as e:
            return ParseResult(file_path=file_path, language='python', errors=[str(e)])
        return parse_python(file_path, source)

    # 其他语言: 使用 tree-sitter
    if tree_sitter_available():
        return parse_with_tree_sitter(file_path, lang)

    return ParseResult(
        file_path=file_path,
        language=lang,
        errors=[f'tree-sitter 未安装。深度分析仅支持 Python。\n请运行: pip install tree-sitter tree-sitter-languages'],
    )


def is_supported(file_path: str) -> bool:
    """检查文件是否支持深度分析"""
    lang = get_language(file_path)
    if not lang:
        return False
    return lang in SUPPORTED_LANGUAGES
