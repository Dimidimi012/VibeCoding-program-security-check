"""
CLI 入口：提供命令行扫描接口。

用法:
    code-sentry [PATH]             扫描指定目录或文件，不传则扫描当前目录
    code-sentry --json             以 JSON 格式输出
    code-sentry --severity high    仅显示 HIGH 及以上级别
    code-sentry --category poison  仅显示投毒检测结果
"""

import os
import sys
import json
from code_sentry.engine import run_scan
from code_sentry.reporters.terminal import render
from code_sentry.rules.base import Severity, Category


def _build_cli():
    """构建 CLI 解析器（优先使用 click，否则退化为 argparse）"""
    try:
        import click
        return _build_click(click)
    except ImportError:
        return _build_argparse()


def _build_click(click):
    """Click 版本的 CLI"""

    @click.command()
    @click.argument('path', type=click.Path(exists=True), default='.', required=False)
    @click.option('--json', 'output_json', is_flag=True, help='输出 JSON 格式')
    @click.option('--severity', '-s', type=click.Choice(['critical', 'high', 'medium', 'low']),
                  help='仅显示指定严重程度及以上的发现')
    @click.option('--category', '-c', type=click.Choice(['poisoning', 'security']),
                  help='仅显示指定类别')
    @click.option('--quiet', '-q', is_flag=True, help='安静模式，仅输出结果统计')
    @click.option('--version', is_flag=True, help='显示版本号')
    def cli(path, output_json, severity, category, quiet, version):
        """Code Sentry — AI 代码本地安检仪

        扫描目标目录或文件，检测中转站投毒和 AI 生成代码的安全漏洞。

        \b
        示例:
          code-sentry                   扫描当前目录
          code-sentry /path/to/project  扫描指定目录
          code-sentry main.py           扫描单个文件
          code-sentry --json            以 JSON 格式输出
        """
        if version:
            from code_sentry import __version__
            print(f"code-sentry v{__version__}")
            return

        _run(path, output_json, severity, category, quiet)

    return cli


def _build_argparse():
    """argparse 降级 CLI"""
    import argparse

    parser = argparse.ArgumentParser(
        prog='code-sentry',
        description='Code Sentry — AI 代码本地安检仪',
        epilog='扫描目标目录或文件，检测中转站投毒和 AI 生成代码的安全漏洞。'
    )
    parser.add_argument('path', nargs='?', default='.',
                        help='要扫描的目录或文件 (默认: 当前目录)')
    parser.add_argument('--json', action='store_true', dest='output_json',
                        help='输出 JSON 格式')
    parser.add_argument('--severity', '-s',
                        choices=['critical', 'high', 'medium', 'low'],
                        help='仅显示指定严重程度及以上的发现')
    parser.add_argument('--category', '-c',
                        choices=['poisoning', 'security'],
                        help='仅显示指定类别')
    parser.add_argument('--quiet', '-q', action='store_true',
                        help='安静模式')
    parser.add_argument('--version', action='store_true',
                        help='显示版本号')

    args = parser.parse_args()

    if args.version:
        from code_sentry import __version__
        print(f"code-sentry v{__version__}")
        return

    _run(args.path, args.output_json, args.severity, args.category, args.quiet)


def _run(path, output_json, severity, category, quiet):
    """执行扫描并输出结果"""
    # 规范化路径
    scan_path = os.path.abspath(path)

    # 执行扫描
    result = run_scan(scan_path)

    # 过滤
    if severity:
        levels = {
            'critical': [Severity.CRITICAL],
            'high': [Severity.CRITICAL, Severity.HIGH],
            'medium': [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
            'low': [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW],
        }
        allowed = levels.get(severity, [])
        result.findings = [f for f in result.findings if f.severity in allowed]

    if category:
        cat_map = {'poisoning': Category.POISONING, 'security': Category.SECURITY}
        allowed_cat = cat_map.get(category)
        if allowed_cat:
            result.findings = [f for f in result.findings if f.category == allowed_cat]

    if output_json:
        _output_json(result)
    elif quiet:
        _output_quiet(result)
    else:
        render(result)

    # 根据严重程度设置退出码
    has_critical = any(f.severity == Severity.CRITICAL for f in result.findings)
    has_high = any(f.severity == Severity.HIGH for f in result.findings)

    if has_critical:
        sys.exit(2)
    elif has_high:
        sys.exit(1)
    else:
        sys.exit(0)


def _output_json(result):
    """输出 JSON 格式"""
    output = {
        'scan_path': result.scan_path,
        'files_scanned': result.files_scanned,
        'findings_count': len(result.findings),
        'duration_seconds': result.duration_seconds,
        'findings': [
            {
                'rule_id': f.rule_id,
                'rule_name': f.rule_name,
                'severity': f.severity.value,
                'category': f.category.value,
                'file_path': f.file_path,
                'line_number': f.line_number,
                'matched_line': f.matched_line,
                'description': f.description,
                'recommendation': f.recommendation,
                'context_note': f.context_note,
            }
            for f in result.findings
        ],
    }
    print(json.dumps(output, ensure_ascii=False, indent=2))


def _output_quiet(result):
    """安静模式输出"""
    by_severity = {}
    for f in result.findings:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    parts = []
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        count = by_severity.get(sev, 0)
        if count:
            icon = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(sev.value, '')
            parts.append(f"{icon}{count}")

    print(f"扫描 {result.files_scanned} 文件 | 发现 {len(result.findings)} 问题 | {' '.join(parts)}")


def main():
    """程序入口"""
    cli = _build_cli()
    cli()


if __name__ == '__main__':
    main()
