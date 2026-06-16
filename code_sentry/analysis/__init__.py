"""
深度分析模块：AST 解析 → 调用图 → 污点追踪 → 攻击链检测。

使用方式：
    from code_sentry.analysis import deep_scan
    result = deep_scan("path/to/file.py")

多语言支持：
    Python: 内置 ast 模块（始终可用）
    其他语言: tree-sitter（需 pip install tree-sitter tree-sitter-languages）
"""

from code_sentry.analysis.models import (
    DeepAnalysisResult, AttackChainMatch, TaintPath,
    Symbol, SymbolKind, CallEdge, Location,
)
from code_sentry.analysis.parsers import parse_file as parse_file_new, is_supported
from code_sentry.analysis.taint_tracker import run_taint_analysis
from code_sentry.analysis.chain_detector import detect_chains
from code_sentry.analysis.ast_nodes import ParseResult


def _parse_result_to_deep(pr: ParseResult) -> DeepAnalysisResult:
    """将 ParseResult 转换为 DeepAnalysisResult（向后兼容）"""
    symbols = []
    call_edges = []

    # 转换函数列表
    for func in pr.functions:
        symbols.append(Symbol(
            name=func['name'],
            kind=SymbolKind.FUNCTION,
            location=Location(
                file_path=pr.file_path,
                line_start=func.get('line_start', 1),
                line_end=func.get('line_end', 1),
            ),
        ))

    # 转换调用列表
    for call in pr.calls:
        call_edges.append(CallEdge(
            caller=call.get('caller', ''),
            callee=call.get('callee', ''),
            location=Location(
                file_path=pr.file_path,
                line_start=call.get('line', 1),
                line_end=call.get('line', 1),
            ),
        ))

    return DeepAnalysisResult(
        file_path=pr.file_path,
        language=pr.language,
        symbols=symbols,
        call_graph=call_edges,
        errors=pr.errors,
    )


def deep_scan(file_path: str) -> DeepAnalysisResult:
    """对单个文件执行完整的深度分析管线

    Args:
        file_path: 文件路径

    Returns:
        DeepAnalysisResult: 包含符号表、调用图、污点路径、攻击链的完整结果
    """
    # 1. AST 解析（自动选择后端）
    parse_result = parse_file_new(file_path)
    if parse_result.errors:
        return _parse_result_to_deep(parse_result)

    # 转换为内部格式
    result = _parse_result_to_deep(parse_result)

    # 2. 污点追踪
    result = run_taint_analysis(result)

    # 3. 攻击链检测
    result = detect_chains(result)

    return result


def deep_scan_directory(directory: str) -> list[DeepAnalysisResult]:
    """对目录执行深度分析（仅分析支持的文件类型）"""
    import os
    results = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in {
            '.git', '__pycache__', 'node_modules', '.venv', 'venv',
            'build', 'dist', '.mypy_cache', '.pytest_cache',
        }]
        for fname in files:
            file_path = os.path.join(root, fname)
            if is_supported(file_path):
                result = deep_scan(file_path)
                if result.attack_chains or result.taint_paths or result.errors:
                    results.append(result)

    return results
