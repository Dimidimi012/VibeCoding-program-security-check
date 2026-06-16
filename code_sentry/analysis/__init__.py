"""
深度分析模块：AST 解析 → 调用图 → 污点追踪 → 攻击链检测。

使用方式：
    from code_sentry.analysis import deep_scan
    result = deep_scan("path/to/file.py")
"""

from code_sentry.analysis.models import DeepAnalysisResult, AttackChainMatch, TaintPath
from code_sentry.analysis.ast_parser import parse_file, is_supported
from code_sentry.analysis.taint_tracker import run_taint_analysis
from code_sentry.analysis.chain_detector import detect_chains
from code_sentry.analysis.call_graph import build_call_graph


def deep_scan(file_path: str) -> DeepAnalysisResult:
    """对单个文件执行完整的深度分析管线

    Args:
        file_path: 文件路径

    Returns:
        DeepAnalysisResult: 包含符号表、调用图、污点路径、攻击链的完整结果
    """
    # 1. AST 解析
    result = parse_file(file_path)
    if result.errors:
        return result

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
        # 排除目录
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
