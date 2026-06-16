"""
AST 解析入口：自动分发到 Python ast 或 tree-sitter 后端。

使用方式：
    from code_sentry.analysis.ast_parser import parse_file, is_supported
    result = parse_file("path/to/file.py")
"""

from code_sentry.analysis.parsers import parse_file, is_supported

# 重新导出以保持向后兼容
__all__ = ['parse_file', 'is_supported']
