"""
终端报告输出：使用 Rich 库渲染彩色扫描报告。
"""

import os
from code_sentry.rules.base import Finding, ScanResult, Severity, Category
from code_sentry.analyzers.context import analyze, RiskReport, FileRisk

# ── Rich 导入（延迟导入，允许在不安装 rich 时优雅降级）──

_RICH_AVAILABLE = True
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    from rich.layout import Layout
    from rich.columns import Columns
    from rich.align import Align
except ImportError:
    _RICH_AVAILABLE = False

# ── 图标 / 颜色映射 ────────────────────────────────────────

SEVERITY_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
}

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "bold orange3",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def _render_summary(result: ScanResult, risk: RiskReport):
    """渲染扫描摘要面板"""
    console = Console()
    console.print()
    console.print(Panel.fit(
        f"[bold white]Code Sentry 扫描报告[/bold white]\n"
        f"扫描路径: {result.scan_path}\n"
        f"扫描文件: {result.files_scanned} 个\n"
        f"发现数量: {len(result.findings)} 个\n"
        f"扫描耗时: {result.duration_seconds:.2f}s",
        border_style="cyan",
        title="📋 扫描摘要",
    ))
    console.print()


def _render_risk_gauge(risk: RiskReport):
    """渲染风险评分仪表盘"""
    console = Console()

    # 评分条
    bar_length = 40
    max_score = 150
    filled = min(bar_length, int(risk.overall_score / max_score * bar_length))
    bar = "█" * filled + "░" * (bar_length - filled)

    level_color = {
        "🟢 低风险": "green",
        "🟡 中等风险": "yellow",
        "🟠 高风险": "orange3",
        "🔴 严重风险": "red",
    }.get(risk.risk_level, "white")

    panel_content = (
        f"风险评分    [bold {level_color}]{risk.overall_score}[/bold {level_color}]\n"
        f"风险等级    [bold {level_color}]{risk.risk_level}[/bold {level_color}]\n"
        f"            [{level_color}]{bar}[/{level_color}]\n\n"
        f"投毒风险    [red]{risk.poisoning_score}[/red]\n"
        f"安全漏洞    [orange3]{risk.security_score}[/orange3]"
    )

    console.print(Panel.fit(
        panel_content,
        border_style=level_color,
        title="🎯 风险评估",
    ))
    console.print()


def _render_critical_flags(risk: RiskReport):
    """渲染关键警报"""
    if not risk.critical_flags:
        return
    console = Console()
    flags_text = "\n".join(f"  {flag}" for flag in risk.critical_flags)
    console.print(Panel.fit(
        flags_text,
        border_style="red",
        title="🚨 关键警报",
    ))
    console.print()


def _render_findings_table(findings: list[Finding], category: Category | None = None):
    """渲染发现列表"""
    console = Console()

    filtered = findings
    if category:
        filtered = [f for f in findings if f.category == category]

    if not filtered:
        return

    title = "🦠 投毒检测结果" if category == Category.POISONING else "🔒 安全漏洞检测"
    table = Table(title=title, box=box.SIMPLE, border_style="dim")
    table.add_column("#", style="dim", width=4)
    table.add_column("级别", width=4)
    table.add_column("规则", width=16)
    table.add_column("文件", width=30)
    table.add_column("行", width=4, justify="right")
    table.add_column("描述", width=40)

    for i, f in enumerate(filtered, 1):
        icon = SEVERITY_ICON.get(f.severity, "⚪")
        fname = os.path.basename(f.file_path)
        desc = f.description[:80]
        if f.context_note and f.context_note != desc:
            desc = f"{desc}\n[dim italic]{f.context_note}[/dim italic]"

        table.add_row(
            str(i),
            icon,
            f"[bold]{f.rule_name}[/bold]",
            fname,
            str(f.line_number),
            desc,
        )

    console.print(table)
    console.print()


def _render_fallback(result: ScanResult, risk: RiskReport):
    """无 Rich 时的降级纯文本输出"""
    print(f"\n{'='*60}")
    print(f"  Code Sentry 扫描报告")
    print(f"{'='*60}")
    print(f"  扫描路径: {result.scan_path}")
    print(f"  扫描文件: {result.files_scanned} 个")
    print(f"  发现数量: {len(result.findings)} 个")
    print(f"  扫描耗时: {result.duration_seconds:.2f}s")
    print(f"\n  风险评分: {risk.overall_score} / {risk.risk_level}")
    print(f"  投毒风险: {risk.poisoning_score} | 安全漏洞: {risk.security_score}")
    print(f"{'='*60}")

    if risk.critical_flags:
        print("\n  [关键警报]")
        for flag in risk.critical_flags:
            print(f"    {flag}")

    # 按严重程度分组
    by_severity = {}
    for f in result.findings:
        by_severity.setdefault(f.severity, []).append(f)

    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        items = by_severity.get(sev, [])
        if not items:
            continue
        icon = SEVERITY_ICON.get(sev, "⚪")
        print(f"\n  [{sev.upper()}] {len(items)} 条发现")
        for f in items:
            print(f"    {icon} {f.rule_name} | {os.path.basename(f.file_path)}:{f.line_number}")
            print(f"       {f.description[:100]}")
            if f.context_note:
                print(f"       → {f.context_note}")

    print(f"\n{'='*60}\n")


def render(result: ScanResult):
    """渲染完整扫描报告"""
    risk = analyze(result)

    if _RICH_AVAILABLE:
        _render_summary(result, risk)
        _render_risk_gauge(risk)
        _render_critical_flags(risk)
        _render_findings_table(result.findings, Category.POISONING)
        _render_findings_table(result.findings, Category.SECURITY)
    else:
        _render_fallback(result, risk)

    return risk
