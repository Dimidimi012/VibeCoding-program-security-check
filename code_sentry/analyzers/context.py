"""
上下文分析器：对扫描结果进行二次分析，提供风险评分和关联判断。

这是"基于本地逻辑判断"的核心层：
1. 风险评分 — 按严重程度加权计算文件/项目风险
2. 投毒特征叠加 — 同文件命中多项投毒规则时升级警报
3. 位置异常检测 — 代码底部突兀出现的高危特征更可疑
4. 模式关联 — 多个弱信号组合可能构成强信号
"""

import os
from collections import defaultdict
from dataclasses import dataclass, field
from code_sentry.rules.base import Finding, ScanResult, Severity, Category

# ── 严重程度权重 ──────────────────────────────────────────

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10,
    Severity.HIGH: 5,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}

# ── 风险等级阈值 ──────────────────────────────────────────

RISK_LEVELS = [
    (0, "🟢 低风险"),
    (15, "🟡 中等风险"),
    (40, "🟠 高风险"),
    (80, "🔴 严重风险"),
]


@dataclass
class FileRisk:
    """单文件风险评估"""
    file_path: str
    total_score: int = 0
    poisoning_score: int = 0
    security_score: int = 0
    findings_count: int = 0
    flags: list[str] = field(default_factory=list)


@dataclass
class RiskReport:
    """完整风险分析报告"""
    overall_score: int
    risk_level: str
    poisoning_score: int
    security_score: int
    file_risks: list[FileRisk]
    critical_flags: list[str]


def _score_finding(f: Finding) -> int:
    return SEVERITY_WEIGHT.get(f.severity, 1)


def _get_risk_level(score: int) -> str:
    for threshold, label in reversed(RISK_LEVELS):
        if score >= threshold:
            return label
    return RISK_LEVELS[0][1]


def _check_poisoning_combination(findings: list[Finding]) -> list[str]:
    """检测投毒特征的组合模式"""
    flags = []
    poison_rules = set()
    for f in findings:
        if f.category == Category.POISONING:
            poison_rules.add(f.rule_id)

    # 网络外联 + 命令执行 = 下载并执行（C2 模式）
    if 'POI-001' in poison_rules and 'POI-002' in poison_rules:
        flags.append("🔴 [C2模式] 网络外联 + 命令执行组合，疑似远程控制")

    # 网络外联 + 混淆 = 加密 C2 通信
    if 'POI-001' in poison_rules and 'POI-004' in poison_rules:
        flags.append("🔴 [隐蔽C2] 网络外联 + 混淆编码，疑似加密通信")

    # 敏感文件 + 网络外联 = 数据窃取
    if 'POI-003' in poison_rules and 'POI-001' in poison_rules:
        flags.append("🔴 [数据窃取] 敏感文件读取 + 网络外联，疑似信息外泄")

    # 持久化 + 命令执行 = APT 驻留
    if 'POI-006' in poison_rules and 'POI-002' in poison_rules:
        flags.append("🔴 [APT驻留] 持久化 + 命令执行，疑似高级持续性威胁")

    # 依赖投毒 + 命令执行 = 供应链攻击
    if 'POI-005' in poison_rules and 'POI-002' in poison_rules:
        flags.append("🔴 [供应链攻击] 依赖投毒 + 命令执行组合")

    return flags


def _check_lastline_anomaly(findings: list[Finding], file_path: str) -> list[str]:
    """检测代码底部突兀出现的高危特征"""
    flags = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except OSError:
        return flags

    total_lines = len(lines)
    if total_lines == 0:
        return flags

    last_quarter_threshold = max(1, total_lines - total_lines // 4)
    bottom_findings = [f for f in findings if f.line_number >= last_quarter_threshold]

    if bottom_findings:
        bottom_critical = [f for f in bottom_findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        if len(bottom_critical) >= 2:
            flags.append(
                f"⚠ [位置异常] 文件底部（第{last_quarter_threshold}行之后）集中出现"
                f" {len(bottom_critical)} 条高危发现，可能为追加的恶意代码"
            )

    return flags


def analyze(result: ScanResult) -> RiskReport:
    """对扫描结果进行二次分析"""
    # 按文件分组
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[f.file_path].append(f)

    file_risks: list[FileRisk] = []
    total_poisoning = 0
    total_security = 0
    all_critical_flags: list[str] = []

    for file_path, findings in by_file.items():
        fr = FileRisk(file_path=file_path, findings_count=len(findings))

        for f in findings:
            score = _score_finding(f)
            fr.total_score += score
            if f.category == Category.POISONING:
                fr.poisoning_score += score
            else:
                fr.security_score += score

        # 检查投毒组合
        fr.flags = _check_poisoning_combination(findings)

        # 检查位置异常
        location_flags = _check_lastline_anomaly(findings, file_path)
        fr.flags.extend(location_flags)

        total_poisoning += fr.poisoning_score
        total_security += fr.security_score
        all_critical_flags.extend(fr.flags)
        file_risks.append(fr)

    overall_score = total_poisoning + total_security

    return RiskReport(
        overall_score=overall_score,
        risk_level=_get_risk_level(overall_score),
        poisoning_score=total_poisoning,
        security_score=total_security,
        file_risks=file_risks,
        critical_flags=all_critical_flags,
    )
