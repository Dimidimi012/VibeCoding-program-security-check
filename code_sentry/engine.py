"""
扫描引擎：遍历目录 → 识别文件类型 → 应用规则 → 收集发现。
"""

import os
import re
import time
from pathlib import Path
from code_sentry.rules.base import Rule, Finding, ScanResult, Severity, Category
from code_sentry.rules import get_all_rules

# ── 文件扩展名 → 语言映射 ──────────────────────────────────

EXT_TO_LANG = {
    # Python
    '.py': 'python', '.pyw': 'python', '.pyx': 'python', '.pxd': 'python',
    # JavaScript / TypeScript
    '.js': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript',
    '.jsx': 'javascript', '.ts': 'typescript', '.tsx': 'typescript',
    '.vue': 'javascript', '.svelte': 'javascript',
    # Go
    '.go': 'go',
    # Java / Kotlin
    '.java': 'java', '.kt': 'java', '.kts': 'java', '.scala': 'java',
    # Ruby
    '.rb': 'ruby',
    # PHP
    '.php': 'php', '.phtml': 'php',
    # Rust
    '.rs': 'rust',
    # C / C++
    '.c': 'c', '.cpp': 'c', '.cc': 'c', '.cxx': 'c', '.h': 'c', '.hpp': 'c',
    # C#
    '.cs': 'csharp',
    # Shell
    '.sh': 'shell', '.bash': 'shell', '.zsh': 'shell', '.fish': 'shell',
    # 配置文件（也参与扫描，用于依赖检测）
    '.txt': 'text', '.toml': 'text', '.yaml': 'text', '.yml': 'text',
    '.json': 'text', '.cfg': 'text', '.ini': 'text', '.conf': 'text',
    '.dockerfile': 'dockerfile', 'dockerfile': 'dockerfile',
    '.md': 'markdown',
}

# ── 排除目录 ──────────────────────────────────────────────

EXCLUDE_DIRS = {
    '.git', '__pycache__', 'node_modules', '.venv', 'venv', 'env',
    '.tox', '.eggs', 'build', 'dist', '.mypy_cache', '.pytest_cache',
    '.next', '.nuxt', '.cache', 'target', '.gradle', '.idea', '.vscode',
    'bower_components', '.serverless', '.terraform',
}

# ── 排除文件 ──────────────────────────────────────────────

EXCLUDE_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    'poetry.lock', 'Pipfile.lock', 'Gemfile.lock',
    'Cargo.lock', 'go.sum', 'composer.lock',
}


def _get_language(file_path: str) -> str:
    """根据文件扩展名推断编程语言"""
    path_lower = file_path.lower()
    # 先检查完整文件名（如 Dockerfile）
    basename = os.path.basename(path_lower)
    if basename in EXT_TO_LANG:
        return EXT_TO_LANG[basename]
    # Dockerfile 变体
    if basename.startswith('dockerfile'):
        return 'dockerfile'
    # 扩展名匹配
    _, ext = os.path.splitext(path_lower)
    return EXT_TO_LANG.get(ext, 'unknown')


def _should_exclude(file_path: str) -> bool:
    """检查文件/目录是否应被排除"""
    parts = Path(file_path).parts
    # 检查目录
    for part in parts[:-1]:
        if part in EXCLUDE_DIRS:
            return True
    # 检查文件名
    basename = os.path.basename(file_path)
    if basename in EXCLUDE_FILES:
        return True
    # 检查扩展名：二进制/图片文件跳过
    skip_extensions = {
        '.pyc', '.pyo', '.so', '.dll', '.exe', '.bin', '.dat',
        '.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.ico',
        '.mp4', '.mp3', '.wav', '.avi', '.mov',
        '.zip', '.tar', '.gz', '.bz2', '.7z',
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.ttf', '.otf', '.woff', '.woff2',
        '.min.js', '.min.css',
    }
    basename_lower = basename.lower()
    if any(basename_lower.endswith(ext) for ext in skip_extensions):
        return True
    # 文件太大（>5MB）跳过
    try:
        if os.path.getsize(file_path) > 5 * 1024 * 1024:
            return True
    except OSError:
        return True
    return False


def _collect_files(scan_path: str) -> list[str]:
    """收集需要扫描的文件列表"""
    files = []
    for root, dirs, filenames in os.walk(scan_path):
        # 过滤排除目录
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
        for fname in filenames:
            full_path = os.path.join(root, fname)
            if not _should_exclude(full_path):
                files.append(full_path)
    return files


def _rule_matches_language(rule: Rule, file_lang: str) -> bool:
    """判断规则是否适用于当前文件语言"""
    if 'all' in rule.languages:
        return True
    return file_lang in rule.languages


def _scan_file(file_path: str, rules: list[Rule]) -> list[Finding]:
    """扫描单个文件，返回发现列表"""
    findings = []
    file_lang = _get_language(file_path)

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except (OSError, UnicodeDecodeError):
        return findings

    file_content = ''.join(lines)

    for rule in rules:
        if not _rule_matches_language(rule, file_lang):
            continue
        # 文件扩展名过滤
        if rule.extensions:
            _, ext = os.path.splitext(file_path)
            if ext.lower() not in [e.lower() if e.startswith('.') else f'.{e.lower()}' for e in rule.extensions]:
                continue
        # 排除模式
        if rule.exclude_patterns:
            if any(re.search(pat, file_path) for pat in rule.exclude_patterns):
                continue

        # 逐行匹配
        for lineno, line in enumerate(lines, start=1):
            for pattern in rule.patterns:
                try:
                    if re.search(pattern, line, re.IGNORECASE):
                        # 上下文判断
                        ctx_note = ""
                        skip = False
                        if rule.context_check:
                            result = rule.context_check(line, file_path)
                            if result is None:
                                skip = True
                            else:
                                ctx_note = result

                        if skip:
                            continue

                        findings.append(Finding(
                            rule_id=rule.id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            category=rule.category,
                            file_path=file_path,
                            line_number=lineno,
                            matched_line=line.strip()[:200],
                            description=rule.description,
                            recommendation=rule.recommendation,
                            context_note=ctx_note,
                        ))
                        break  # 一行匹配到任一 pattern 就够了
                except re.error:
                    continue

    return findings


def run_scan(scan_path: str, rules: list[Rule] | None = None) -> ScanResult:
    """执行完整扫描

    Args:
        scan_path: 要扫描的目录或文件路径
        rules: 自定义规则列表，不传则使用所有内置规则
    """
    if rules is None:
        rules = get_all_rules()

    start_time = time.time()

    scan_path = os.path.abspath(scan_path)

    if os.path.isfile(scan_path):
        files = [scan_path]
    else:
        files = _collect_files(scan_path)

    all_findings = []
    for file_path in files:
        file_findings = _scan_file(file_path, rules)
        all_findings.extend(file_findings)

    duration = time.time() - start_time

    return ScanResult(
        scan_path=scan_path,
        files_scanned=len(files),
        findings=all_findings,
        duration_seconds=duration,
    )
