"""
规则基类和数据模型。

每条规则描述一个需要检测的代码模式，分为两大类别：
- poisoning: 中转站投毒检测
- security:   AI 生成代码安全漏洞
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    POISONING = "poisoning"    # 投毒检测
    SECURITY = "security"      # 安全漏洞


@dataclass
class Finding:
    """单条检测结果"""
    rule_id: str
    rule_name: str
    severity: Severity
    category: Category
    file_path: str
    line_number: int
    matched_line: str
    description: str
    recommendation: str
    context_note: str = ""


@dataclass
class Rule:
    """检测规则定义"""
    id: str
    name: str
    severity: Severity
    category: Category
    description: str
    recommendation: str
    languages: list[str] = field(default_factory=lambda: ["all"])
    patterns: list[str] = field(default_factory=list)
    # 上下文判断函数，接收 (line: str, file_content: str, file_path: str) -> Optional[str]
    # 返回 None 表示不命中，返回字符串表示补充的 context_note
    context_check: Optional[Callable] = None
    # 需要检测的文件扩展名，空列表表示不限制
    extensions: list[str] = field(default_factory=list)
    # 排除的文件模式
    exclude_patterns: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """完整扫描结果"""
    scan_path: str
    files_scanned: int
    findings: list[Finding]
    duration_seconds: float
