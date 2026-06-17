"""
污点追踪器：追踪不可信数据从 Source 到 Sink 的完整路径。

v0.2: 优先使用 AST (UnifiedNode) 进行精确追踪，回退到字符串匹配作为兜底。
支持多语言：通过 DeepAnalysisResult.language 选择对应的 Source/Sink 特征表。

核心逻辑：
1. 在 AST 中标记所有 Source 点（用户输入/文件读取/网络接收）
2. 从每个 Source 出发，追踪变量赋值链（跨多层传播）
3. 检查是否到达 Sink 点（命令执行/网络发送/文件写入）
4. 记录完整的污点传播路径（source → ... → sink）
"""

import os
import re
from code_sentry.analysis.models import (
    Symbol, SymbolKind, TaintNode, TaintPath, TaintSource, TaintSink,
    Location, DeepAnalysisResult, SOURCE_PATTERNS, SINK_PATTERNS,
)
from code_sentry.analysis.ast_nodes import (
    UnifiedNode, UnifiedNodeType, ParseResult,
)


# ── 语言名称规范化映射 ──────────────────────────────────

_LANG_CANONICAL = {
    'python': 'python',
    'javascript': 'javascript',
    'js': 'javascript',
    'typescript': 'javascript',
    'ts': 'javascript',
    'tsx': 'javascript',
    'go': 'go',
    'java': 'java',
    'ruby': 'ruby',
    'php': 'php',
    'rust': 'rust',
    'c': 'c',
    'cpp': 'c',
    'csharp': 'csharp',
    'shell': 'shell',
    'bash': 'shell',
}


def _get_source_patterns(language: str) -> list[dict]:
    """获取指定语言的 Source 特征列表"""
    lang_key = _LANG_CANONICAL.get(language, 'python')
    return SOURCE_PATTERNS.get(lang_key, SOURCE_PATTERNS.get('python', []))


def _get_sink_patterns(language: str) -> list[dict]:
    """获取指定语言的 Sink 特征列表"""
    lang_key = _LANG_CANONICAL.get(language, 'python')
    return SINK_PATTERNS.get(lang_key, SINK_PATTERNS.get('python', []))


def _match_call_name(call_name: str, pattern: str) -> bool:
    """检查调用名是否匹配某个 Source/Sink 模式。

    支持三种匹配层级：
    1. 精确匹配: call_name == pattern（或 pattern 去掉末尾 '('）
    2. 后缀匹配: call_name 以 pattern 结尾（处理 obj.method 形式）
    3. 包含匹配: pattern 是 call_name 的子串（宽松模式）

    AST 解析出的函数名不含括号（如 exec），但特征表中的模式可能带括号
    （如 exec(），因此同时尝试带括号和不带括号的匹配。
    """
    if not call_name:
        return False
    # 尝试去掉末尾的 ( 进行匹配（AST 模式下函数名不含括号）
    clean_pattern = pattern.rstrip('(')
    if call_name == clean_pattern:
        return True
    if call_name.endswith('.' + clean_pattern):
        return True
    if clean_pattern in call_name:
        return True
    # 也尝试原始模式（兼容各种写法）
    if call_name == pattern:
        return True
    if call_name.endswith('.' + pattern):
        return True
    if pattern in call_name:
        return True
    return False


class TaintTracker:
    """基于 AST (优先) 的污点追踪器"""

    def __init__(self, result: DeepAnalysisResult, parse_result: ParseResult | None = None):
        self.result = result
        self.parse_result = parse_result
        self.language = result.language
        self.file_path = result.file_path

        # 被污染的变量名 → 对应的 Source TaintNode
        self.tainted_vars: dict[str, TaintNode] = {}
        # 污点路径列表
        self.taint_paths: list[TaintPath] = []
        # 用于回退模式的源码行
        self.source_lines: list[str] = []
        # 待匹配的 source 列表（回退模式用）
        self._pending_sources: list[tuple] = []

    # ── 主入口 ────────────────────────────────────────────

    def track(self) -> list[TaintPath]:
        """执行污点追踪。优先使用 AST，不可用时回退到字符串匹配。"""
        if self.parse_result and self.parse_result.root:
            self._track_via_ast()
        else:
            self._track_via_strings()

        return self.taint_paths

    # ═══════════════════════════════════════════════════════
    # AST 模式：基于 UnifiedNode 树的精确追踪
    # ═══════════════════════════════════════════════════════

    def _track_via_ast(self):
        """使用 AST 树进行污点追踪"""
        root = self.parse_result.root

        # Phase 1: 遍历 AST 找到所有 Source → 标记被污染变量
        self._find_sources_ast(root)

        # Phase 2: 遍历 AST 传播污点（处理变量赋值链）
        self._propagate_taint_ast(root)

        # Phase 3: 遍历 AST 找到 Sink + 被污染参数 → 构建路径
        self._find_sinks_ast(root)

    def _find_sources_ast(self, node: UnifiedNode):
        """Phase 1: 在 AST 中找到所有 Source 调用点

        覆盖两种 Source 模式：
        1. 函数调用：request.args.get("key")
        2. 属性访问链：req.query, process.env（JS 特有，不是函数调用而是属性读取）
        """
        source_patterns = _get_source_patterns(self.language)

        for n in node.walk():
            if n.type != UnifiedNodeType.ASSIGNMENT:
                continue

            target_names = n.attributes.get('target_names', [])
            if not target_names:
                continue
            var_name = target_names[0]

            # 检查赋值右侧是否包含 Source
            for child in n.children:
                # 模式 1: 函数调用作为 Source
                if child.type == UnifiedNodeType.CALL:
                    if self._is_source_call(child, source_patterns):
                        source_type = self._get_source_type(child, source_patterns)
                        self._mark_source(var_name, child, source_type)
                    continue

                # 递归检查深层 CALL
                found_call = False
                for sub in child.walk():
                    if sub.type == UnifiedNodeType.CALL:
                        if self._is_source_call(sub, source_patterns):
                            source_type = self._get_source_type(sub, source_patterns)
                            self._mark_source(var_name, sub, source_type)
                            found_call = True
                        break
                if found_call:
                    continue

                # 模式 2: 属性访问链（如 JS 的 req.query、process.env）
                # 使用节点的源代码文本做模式匹配
                source_text = child.source_code
                if not source_text:
                    # 回退：拼接标识符链
                    source_text = self._build_identifier_chain(child)
                if source_text:
                    for pat in source_patterns:
                        if pat['pattern'] in source_text:
                            loc = child.location
                            source_node = TaintNode(
                                symbol=Symbol(
                                    name=var_name,
                                    kind=SymbolKind.VARIABLE,
                                    location=Location(
                                        file_path=self.file_path,
                                        line_start=loc.line_start if loc else 1,
                                        line_end=loc.line_end if loc else 1,
                                    ),
                                ),
                                taint_type="source",
                                note=f"不可信数据来源: {pat['type'].value}",
                            )
                            self.tainted_vars[var_name] = source_node
                            break

    def _propagate_taint_ast(self, root: UnifiedNode):
        """Phase 2: 在 AST 中传播污点变量

        规则：如果 var_b = ... var_a ... 且 var_a 已污染，则 var_b 也污染。
        多轮迭代直到不动点（处理 a → b → c 多层链）。
        """
        max_iterations = 5
        for _ in range(max_iterations):
            new_tainted: dict[str, TaintNode] = {}

            for node in root.walk():
                if node.type != UnifiedNodeType.ASSIGNMENT:
                    continue

                target_names = node.attributes.get('target_names', [])
                if not target_names:
                    continue
                var_name = target_names[0]

                # 已经被污染，跳过
                if var_name in self.tainted_vars or var_name in new_tainted:
                    continue

                # 检查赋值右侧是否引用了被污染变量
                if self._references_tainted_var(node, self.tainted_vars):
                    # 收集右侧引用到的所有被污染变量名
                    ref_vars = self._collect_tainted_refs(node, self.tainted_vars)
                    # 使用第一个被污染变量作为源
                    source_node = self.tainted_vars.get(ref_vars[0]) if ref_vars else None
                    if source_node:
                        new_tainted[var_name] = source_node

            if not new_tainted:
                break
            self.tainted_vars.update(new_tainted)

    def _find_sinks_ast(self, root: UnifiedNode):
        """Phase 3: 在 AST 中找到 Sink 调用，匹配已污染的 Source → 构建路径"""
        sink_patterns = _get_sink_patterns(self.language)

        for node in root.walk():
            if node.type != UnifiedNodeType.CALL:
                continue

            if not self._is_sink_call(node, sink_patterns):
                continue

            sink_type = self._get_sink_type(node, sink_patterns)
            sink_location = node.location

            # 检查这个 sink 调用的参数是否引用了被污染变量
            tainted_refs = self._find_tainted_args_in_call(node)

            if not tainted_refs:
                # 也检查是否直接内联使用了 source 函数
                #（如 os.system(request.args.get('cmd'))）
                if not self._has_inline_source(node):
                    continue

            # 为每个被污染的 source 创建一条路径
            for var_name in tainted_refs:
                source_node = self.tainted_vars.get(var_name)
                if not source_node:
                    continue

                sink_node = TaintNode(
                    symbol=Symbol(
                        name=node.name,
                        kind=SymbolKind.FUNCTION,
                        location=Location(
                            file_path=self.file_path,
                            line_start=sink_location.line_start if sink_location else 1,
                            line_end=sink_location.line_end if sink_location else 1,
                        ),
                    ),
                    taint_type="sink",
                    note=f"危险操作: {sink_type.value}",
                )

                # 检查中间是否有净化措施
                sanitized = self._check_sanitization_ast(source_node, sink_node)

                path = TaintPath(
                    source=source_node,
                    sink=sink_node,
                    confidence=0.3 if sanitized else 0.85,
                    source_type=source_node.note,
                    sink_type=sink_node.note,
                )
                self.taint_paths.append(path)

            # 如果有内联 source，为所有待定 source 创建路径
            if not tainted_refs:
                for var_name, source_node in self.tainted_vars.items():
                    sink_node = TaintNode(
                        symbol=Symbol(
                            name=node.name,
                            kind=SymbolKind.FUNCTION,
                            location=Location(
                                file_path=self.file_path,
                                line_start=sink_location.line_start if sink_location else 1,
                                line_end=sink_location.line_end if sink_location else 1,
                            ),
                        ),
                        taint_type="sink",
                        note=f"危险操作: {sink_type.value}",
                    )
                    path = TaintPath(
                        source=source_node,
                        sink=sink_node,
                        confidence=0.6,
                        source_type=source_node.note,
                        sink_type=sink_node.note,
                    )
                    self.taint_paths.append(path)

    # ── AST 辅助方法 ──────────────────────────────────────

    def _is_source_call(self, call_node: UnifiedNode, patterns: list[dict]) -> bool:
        """判断一个 CALL 节点是否匹配 Source 模式"""
        call_name = call_node.name
        for pat in patterns:
            if _match_call_name(call_name, pat['pattern']):
                return True
        return False

    def _get_source_type(self, call_node: UnifiedNode, patterns: list[dict]) -> TaintSource:
        """获取匹配的 Source 类型"""
        call_name = call_node.name
        for pat in patterns:
            if _match_call_name(call_name, pat['pattern']):
                return pat['type']
        return TaintSource.HTTP_PARAM  # fallback

    def _is_sink_call(self, call_node: UnifiedNode, patterns: list[dict]) -> bool:
        """判断一个 CALL 节点是否匹配 Sink 模式"""
        call_name = call_node.name
        for pat in patterns:
            if _match_call_name(call_name, pat['pattern']):
                return True
        return False

    def _get_sink_type(self, call_node: UnifiedNode, patterns: list[dict]) -> TaintSink:
        """获取匹配的 Sink 类型"""
        call_name = call_node.name
        for pat in patterns:
            if _match_call_name(call_name, pat['pattern']):
                return pat['type']
        return TaintSink.COMMAND_EXEC

    def _mark_source(self, var_name: str, call_node: UnifiedNode, source_type: TaintSource):
        """标记一个变量为被污染，记录其 Source 信息"""
        loc = call_node.location
        source_node = TaintNode(
            symbol=Symbol(
                name=var_name,
                kind=SymbolKind.VARIABLE,
                location=Location(
                    file_path=self.file_path,
                    line_start=loc.line_start if loc else 1,
                    line_end=loc.line_end if loc else 1,
                ),
            ),
            taint_type="source",
            note=f"不可信数据来源: {source_type.value}",
        )
        self.tainted_vars[var_name] = source_node

    def _build_identifier_chain(self, node: UnifiedNode) -> str:
        """从 AST 子树中拼接标识符链（如 req.query → 'req.query'）"""
        parts = []
        for n in node.walk():
            if n.type == UnifiedNodeType.IDENTIFIER and n.name:
                if not parts or n.name != parts[-1]:  # 去重
                    parts.append(n.name)
            elif n.type == UnifiedNodeType.ATTRIBUTE_ACCESS and n.name:
                if not parts or n.name != parts[-1]:
                    parts.append(n.name)
        if parts:
            return '.'.join(parts)
        return node.source_code or ''

    def _references_tainted_var(self, node: UnifiedNode, tainted: dict[str, TaintNode]) -> bool:
        """检查节点及其子树是否引用了任一被污染变量"""
        for n in node.walk():
            if n.type == UnifiedNodeType.IDENTIFIER and n.name in tainted:
                return True
        return False

    def _collect_tainted_refs(self, node: UnifiedNode, tainted: dict[str, TaintNode]) -> list[str]:
        """收集节点子树中引用的被污染变量名"""
        refs = []
        seen = set()
        for n in node.walk():
            if n.type == UnifiedNodeType.IDENTIFIER and n.name in tainted and n.name not in seen:
                refs.append(n.name)
                seen.add(n.name)
        return refs

    def _find_tainted_args_in_call(self, call_node: UnifiedNode) -> list[str]:
        """检查 CALL 节点的参数子树中是否包含被污染变量"""
        tainted_refs = []
        seen = set()
        # 遍历 call 节点的所有子节点
        for child in call_node.children:
            for n in child.walk():
                if n.type == UnifiedNodeType.IDENTIFIER and n.name in self.tainted_vars:
                    if n.name not in seen:
                        tainted_refs.append(n.name)
                        seen.add(n.name)
        return tainted_refs

    def _has_inline_source(self, call_node: UnifiedNode) -> bool:
        """检查 CALL 节点的参数中是否直接包含 source 函数调用（如 sink(source())）"""
        source_patterns = _get_source_patterns(self.language)
        for child in call_node.children:
            for n in child.walk():
                if n.type == UnifiedNodeType.CALL:
                    if self._is_source_call(n, source_patterns):
                        return True
        return False

    def _check_sanitization_ast(self, source: TaintNode, sink: TaintNode) -> bool:
        """检查 source 和 sink 之间是否有净化措施（AST 版本）"""
        src_line = source.symbol.location.line_start
        sink_line = sink.symbol.location.line_start

        # 加载源代码用于行间检查
        if not self.source_lines:
            self._load_source_lines()

        for line_no in range(src_line + 1, sink_line):
            if line_no - 1 < len(self.source_lines):
                line = self.source_lines[line_no - 1].strip().lower()
                sanitizers = [
                    'shlex.quote', 'escape', 'sanitize', 'validate',
                    'isinstance', 'isdigit', 'isalnum', 're.match',
                    'bleach.clean', 'html.escape', 'markupsafe',
                ]
                if any(s in line for s in sanitizers):
                    return True
        return False

    # ═══════════════════════════════════════════════════════
    # 回退模式：基于字符串匹配（保持向后兼容）
    # ═══════════════════════════════════════════════════════

    def _load_source_lines(self):
        """加载源代码行"""
        if self.source_lines:
            return
        try:
            with open(self.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.source_lines = f.read().splitlines()
        except OSError:
            self.source_lines = []

    def _track_via_strings(self):
        """回退：使用字符串匹配进行污点追踪"""
        self._load_source_lines()
        source_patterns = _get_source_patterns(self.language)
        sink_patterns = _get_sink_patterns(self.language)

        # Phase 1: 找 Source
        for line_no, line in enumerate(self.source_lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                continue

            for pat in source_patterns:
                if pat['pattern'] in line:
                    source_type = pat['type']
                    var_name = self._extract_assigned_var(line)
                    if var_name:
                        source_node = TaintNode(
                            symbol=Symbol(
                                name=var_name,
                                kind=SymbolKind.VARIABLE,
                                location=Location(
                                    file_path=self.file_path,
                                    line_start=line_no,
                                    line_end=line_no,
                                ),
                            ),
                            taint_type="source",
                            note=f"不可信数据来源: {source_type.value}",
                        )
                        self.tainted_vars[var_name] = source_node
                        self._pending_sources.append((source_node, var_name, line_no))

        # Phase 2: 传播污点
        self._propagate_taint_strings()

        # Phase 3: 找 Sink 并配对
        for line_no, line in enumerate(self.source_lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                continue

            for pat in sink_patterns:
                if pat['pattern'] not in line:
                    continue

                sink_type = pat['type']
                tainted_arg = self._find_tainted_arg_string(line)

                if not tainted_arg and not self._is_direct_use_in_line(line):
                    continue

                for source_node, var_name, src_line in self._pending_sources:
                    sink_node = TaintNode(
                        symbol=Symbol(
                            name=sink_type.value,
                            kind=SymbolKind.FUNCTION,
                            location=Location(
                                file_path=self.file_path,
                                line_start=line_no,
                                line_end=line_no,
                            ),
                        ),
                        taint_type="sink",
                        note=f"危险操作: {sink_type.value}",
                    )
                    sanitized = self._check_sanitization_string(source_node, sink_node)
                    path = TaintPath(
                        source=source_node,
                        sink=sink_node,
                        confidence=0.3 if sanitized else 0.85,
                        source_type=source_node.note,
                        sink_type=sink_node.note,
                    )
                    self.taint_paths.append(path)

    def _propagate_taint_strings(self):
        """回退模式：字符串匹配的污点传播"""
        max_iterations = 5
        for _ in range(max_iterations):
            new_tainted: dict[str, TaintNode] = {}
            for line in self.source_lines:
                line_stripped = line.strip()
                if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                    continue
                if '=' not in line or line_stripped.startswith('if') or line_stripped.startswith('for'):
                    continue

                var_name = self._extract_assigned_var(line)
                if not var_name or var_name in self.tainted_vars or var_name in new_tainted:
                    continue

                right_side = line.split('=', 1)[1] if '=' in line else ''
                for tainted_var, source_node in self.tainted_vars.items():
                    if re.search(r'\b' + re.escape(tainted_var) + r'\b', right_side):
                        new_tainted[var_name] = source_node
                        break

            if not new_tainted:
                break
            self.tainted_vars.update(new_tainted)

    def _extract_assigned_var(self, line: str) -> str | None:
        """从赋值行提取变量名。支持 Python 和 JS/TS 语法。"""
        line = line.strip()
        if '=' not in line:
            return None
        if line.startswith('if') or line.startswith('for') or line.startswith('while'):
            return None

        left = line.split('=')[0].strip()

        # 去除 JS/TS 声明关键字
        for kw in ['const ', 'let ', 'var ']:
            if left.startswith(kw):
                left = left[len(kw):].strip()
                break

        parts = left.split(',')
        if parts:
            first = parts[0].strip()
            # 去除类型注解（TS: `name: string`）
            if ':' in first:
                first = first.split(':')[0].strip()
            if first.isidentifier():
                return first
        return None

    def _find_tainted_arg_string(self, line: str) -> str | None:
        """检查行中是否使用了被污染变量（字符串匹配）"""
        for var in self.tainted_vars:
            if re.search(r'\b' + re.escape(var) + r'\b', line):
                return var
        return None

    def _is_direct_use_in_line(self, line: str) -> bool:
        """检查行中是否直接内联调用了 source 函数"""
        source_patterns_in_line = [
            'request.args', 'request.form', 'request.json',
            'os.environ', 'sys.argv', 'input()',
        ]
        return any(p in line for p in source_patterns_in_line)

    def _check_sanitization_string(self, source: TaintNode, sink: TaintNode) -> bool:
        """检查 source 和 sink 之间是否有净化措施"""
        if not self.source_lines:
            return False
        src_line = source.symbol.location.line_start
        sink_line = sink.symbol.location.line_start
        sanitizers = [
            'shlex.quote', 'escape', 'sanitize', 'validate',
            'isinstance', 'isdigit', 'isalnum', 're.match',
            'bleach.clean', 'html.escape', 'markupsafe',
        ]
        for line_no in range(src_line + 1, sink_line):
            if line_no - 1 < len(self.source_lines):
                line = self.source_lines[line_no - 1].strip().lower()
                if any(s in line for s in sanitizers):
                    return True
        return False


# ── 公共接口 ──────────────────────────────────────────────

def run_taint_analysis(
    result: DeepAnalysisResult,
    parse_result: ParseResult | None = None,
) -> DeepAnalysisResult:
    """对深度分析结果执行污点追踪

    Args:
        result: 深度分析结果（含符号表和调用图）
        parse_result: AST 解析结果（可选，提供时使用 AST 精确追踪）

    Returns:
        添加了 taint_paths 的 DeepAnalysisResult
    """
    if result.errors:
        return result

    tracker = TaintTracker(result, parse_result)
    result.taint_paths = tracker.track()
    return result
