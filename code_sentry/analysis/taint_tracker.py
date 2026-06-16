"""
污点追踪器：追踪不可信数据从 Source 到 Sink 的完整路径。

核心逻辑：
1. 在符号表和调用图中标记所有 Source 点（用户输入/文件读取/网络接收）
2. 从每个 Source 出发，追踪变量赋值链和函数调用链
3. 检查是否到达 Sink 点（命令执行/网络发送/文件写入）
4. 记录完整的污点传播路径
"""

import ast
import os
import re
from code_sentry.analysis.models import (
    Symbol, SymbolKind, CallEdge, TaintNode, TaintPath, TaintSource, TaintSink,
    Location, DeepAnalysisResult, SOURCE_PATTERNS, SINK_PATTERNS,
)


class TaintTracker:
    """基于 AST 和调用图的污点追踪器"""

    def __init__(self, result: DeepAnalysisResult):
        self.result = result
        self.source_code = ""
        self.source_lines: list[str] = []
        self.tainted_vars: set[str] = set()          # 被污染的变量名
        self.tainted_funcs: set[str] = set()          # 返回污点数据的函数
        self.var_definitions: dict[str, str] = {}     # 变量 → 定义处的源码
        self.taint_paths: list[TaintPath] = []

        self._load_source()

    def _load_source(self):
        """加载源代码"""
        try:
            with open(self.result.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                self.source_code = f.read()
            self.source_lines = self.source_code.splitlines()
        except OSError:
            pass

    def track(self) -> list[TaintPath]:
        """执行污点追踪"""
        self._find_sources()
        self._propagate_taint()
        self._find_sinks_and_trace()
        return self.taint_paths

    def _find_sources(self):
        """第一遍：标记所有污点来源"""
        patterns = SOURCE_PATTERNS.get('python', [])

        for line_no, line in enumerate(self.source_lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                continue

            for pat in patterns:
                if pat['pattern'] in line:
                    source_type = pat['type']
                    # 提取变量名
                    var_name = self._extract_assigned_var(line)
                    if var_name:
                        self.tainted_vars.add(var_name)
                        self.var_definitions[var_name] = line_stripped

                        # 创建 Source 污点节点
                        source_node = TaintNode(
                            symbol=Symbol(
                                name=var_name,
                                kind=SymbolKind.VARIABLE,
                                location=Location(
                                    file_path=self.result.file_path,
                                    line_start=line_no,
                                    line_end=line_no,
                                ),
                            ),
                            taint_type="source",
                            note=f"不可信数据来源: {source_type.value}",
                        )

                        # 暂时记录，等找到 sink 后配对
                        # 存入一个中间结构
                        if not hasattr(self, '_pending_sources'):
                            self._pending_sources = []
                        self._pending_sources.append((source_node, var_name, line_no))

    def _propagate_taint(self):
        """传播污点：追踪赋值链，将污点从 source 变量传播到派生变量

        如果 b = func(a) 且 a 被污染，则 b 也被污染
        如果 b = a.attr 且 a 被污染，则 b 也被污染
        如果 b = transform(a) 且 a 被污染，则 b 也被污染
        """
        # 多次迭代直到不动点（处理多层传播：a → b → c）
        max_iterations = 5
        for _ in range(max_iterations):
            new_tainted = set()

            for line in self.source_lines:
                line_stripped = line.strip()
                if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                    continue
                if '=' not in line or line_stripped.startswith('if') or line_stripped.startswith('for'):
                    continue

                # 提取左侧变量名
                var_name = self._extract_assigned_var(line)
                if not var_name or var_name in self.tainted_vars:
                    continue

                # 检查右侧是否引用了被污染变量
                right_side = line.split('=', 1)[1] if '=' in line else ''
                for tainted_var in self.tainted_vars:
                    if re.search(r'\b' + re.escape(tainted_var) + r'\b', right_side):
                        new_tainted.add(var_name)
                        self.var_definitions[var_name] = line_stripped
                        break

            if not new_tainted:
                break
            self.tainted_vars.update(new_tainted)

    def _find_sinks_and_trace(self):
        """第二遍：找到 Sink 并回溯污点路径"""
        patterns = SINK_PATTERNS.get('python', [])
        if not hasattr(self, '_pending_sources'):
            self._pending_sources = []

        for line_no, line in enumerate(self.source_lines, start=1):
            line_stripped = line.strip()
            if line_stripped.startswith('#') or line_stripped.startswith('"""'):
                continue

            for pat in patterns:
                if pat['pattern'] not in line:
                    continue

                sink_type = pat['type']

                # 检查：这个 sink 调用的参数是否被污染？
                tainted_arg = self._find_tainted_arg(line, line_no)
                if not tainted_arg:
                    # 也检查是否直接使用了 source 函数
                    if not self._is_direct_use_in_line(line):
                        continue

                # 创建 Sink 节点，匹配所有 pending source
                for source_node, var_name, src_line in self._pending_sources:
                    # 构建路径：任何 source → 此 sink
                    sink_node = TaintNode(
                        symbol=Symbol(
                            name=sink_type.value,
                            kind=SymbolKind.FUNCTION,
                            location=Location(
                                file_path=self.result.file_path,
                                line_start=line_no,
                                line_end=line_no,
                            ),
                        ),
                        taint_type="sink",
                        note=f"危险操作: {sink_type.value}",
                    )

                    # 检查中间是否有净化
                    sanitized = self._check_sanitization(source_node, sink_node)

                    path = TaintPath(
                        source=source_node,
                        sink=sink_node,
                        confidence=0.3 if sanitized else 0.85,
                        source_type=source_node.note,
                        sink_type=sink_node.note,
                    )
                    self.taint_paths.append(path)

    def _extract_assigned_var(self, line: str) -> str | None:
        """从赋值行中提取被赋值的变量名"""
        line = line.strip()

        # 普通赋值: var = source_func()
        if '=' in line and not line.startswith('if') and not line.startswith('for'):
            left = line.split('=')[0].strip()
            # 提取第一个变量名
            # 处理 var = 或 var1 = var2 = 等情况
            parts = left.split(',')
            if parts:
                first = parts[0].strip()
                # 提取纯变量名（去除类型注解）
                if ':' in first:
                    first = first.split(':')[0].strip()
                if first.isidentifier():
                    return first

        # 属性赋值: obj.attr = ...
        return None

    def _find_tainted_arg(self, line: str, line_no: int) -> str | None:
        """检查行中是否使用了被污染的变量作为参数"""
        line_stripped = line.strip()

        # 提取函数调用的参数
        # subprocess.run(tainted_var, shell=True)
        # os.system(f"cmd {tainted_var}")
        # 检查所有被污染的变量是否出现在这一行
        for var in self.tainted_vars:
            # 简单匹配：变量名出现在行中
            # 使用词边界检查避免部分匹配
            import re
            if re.search(r'\b' + re.escape(var) + r'\b', line):
                return var

        return None

    def _is_direct_use(self, source_node: TaintNode, line: str) -> bool:
        """检查是否直接使用了 source（非变量传递）"""
        source_patterns_in_line = [
            'request.args', 'request.form', 'request.json',
            'os.environ', 'sys.argv', 'input()',
        ]
        return any(p in line for p in source_patterns_in_line)

    def _is_direct_use_in_line(self, line: str) -> bool:
        """检查行中是否直接调用了 source 函数（如 request.args.get 直接在 sink 参数中）"""
        source_patterns_in_line = [
            'request.args', 'request.form', 'request.json',
            'os.environ', 'sys.argv', 'input()',
        ]
        return any(p in line for p in source_patterns_in_line)

    def _check_sanitization(self, source: TaintNode, sink: TaintNode) -> bool:
        """检查 source 和 sink 之间是否有净化措施"""
        src_line = source.symbol.location.line_start
        sink_line = sink.symbol.location.line_start

        # 检查两者之间的行
        for line_no in range(src_line + 1, sink_line):
            if line_no - 1 < len(self.source_lines):
                line = self.source_lines[line_no - 1].strip().lower()
                # 净化标志
                sanitizers = [
                    'shlex.quote', 'escape', 'sanitize', 'validate',
                    'isinstance', 'isdigit', 'isalnum', 're.match',
                    'bleach.clean', 'html.escape', 'markupsafe',
                ]
                if any(s in line for s in sanitizers):
                    return True

        return False


def run_taint_analysis(result: DeepAnalysisResult) -> DeepAnalysisResult:
    """对深度分析结果执行污点追踪"""
    if result.errors:
        return result

    tracker = TaintTracker(result)
    result.taint_paths = tracker.track()
    return result
