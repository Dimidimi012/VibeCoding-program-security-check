"""
攻击链检测器：在污点路径和调用图上匹配多步攻击模式。

攻击链是一系列关联的操作步骤，单独看每一步可能无害，但组合起来构成恶意行为。
例如：下载文件 → 解码 → 执行，这三步分散在不同函数里，单步分析不会告警，
但链式分析能识别出完整的攻击链条。
"""

from code_sentry.analysis.models import (
    TaintPath, TaintNode, AttackChainMatch, ATTACK_CHAIN_DEFINITIONS,
    DeepAnalysisResult, ChainStepType,
)
from code_sentry.analysis.call_graph import CallGraph, build_call_graph


class ChainDetector:
    """攻击链检测器"""

    def __init__(self, result: DeepAnalysisResult):
        self.result = result
        self.call_graph = build_call_graph(result)
        self.taint_paths = result.taint_paths
        self.matched_chains: list[AttackChainMatch] = []

    def detect(self) -> list[AttackChainMatch]:
        """执行攻击链检测"""
        for chain_def in ATTACK_CHAIN_DEFINITIONS:
            match = self._match_chain(chain_def)
            if match:
                self.matched_chains.append(match)

        return self.matched_chains

    def _match_chain(self, chain_def: dict) -> AttackChainMatch | None:
        """尝试匹配一条攻击链定义"""
        required_steps = chain_def['steps']
        matched_paths: list[TaintPath] = []

        # 检查每条污点路径是否能匹配攻击链的步骤
        for taint_path in self.taint_paths:
            if self._path_matches_chain(taint_path, chain_def):
                matched_paths.append(taint_path)

        if not matched_paths:
            return None

        # 检查调用图中的链式关系
        graph_match = self._check_call_chain(chain_def)

        confidence = self._calculate_confidence(matched_paths, required_steps, graph_match)

        return AttackChainMatch(
            chain_name=chain_def['name'],
            severity=chain_def['severity'],
            description=chain_def['description'],
            matched_paths=matched_paths,
            confidence=confidence,
            summary=self._build_summary(chain_def, matched_paths, confidence),
        )

    def _path_matches_chain(self, path: TaintPath, chain_def: dict) -> bool:
        """检查一条污点路径是否匹配攻击链定义"""
        steps = chain_def['steps']
        source_type = path.source_type
        sink_type = path.sink_type

        # 提取步骤中的 source 类型和 sink 类型
        source_step = next((s for s in steps if s['type'] == 'source'), None)
        sink_step = next((s for s in steps if s['type'] == 'sink'), None)
        transform_step = next((s for s in steps if s['type'] == 'transform'), None)

        # 检查 source
        if source_step:
            allowed_sources = source_step.get('source_types', [])
            if allowed_sources:
                source_matched = any(st in source_type for st in allowed_sources)
                if not source_matched:
                    return False

            # 检查 source 关键词
            keywords = source_step.get('keywords', [])
            if keywords:
                source_line = self._get_line(path.source.symbol.location.line_start)
                if not any(kw.lower() in source_line.lower() for kw in keywords):
                    return False

        # 检查 sink
        if sink_step:
            allowed_sinks = sink_step.get('sink_types', [])
            if allowed_sinks:
                sink_matched = any(st in sink_type for st in allowed_sinks)
                if not sink_matched:
                    return False

            keywords = sink_step.get('keywords', [])
            if keywords:
                sink_line = self._get_line(path.sink.symbol.location.line_start)
                if not any(kw.lower() in sink_line.lower() for kw in keywords):
                    return False

        # 检查转换步骤
        if transform_step:
            keywords = transform_step.get('keywords', [])
            if keywords:
                # 检查中间节点或整段代码中是否有转换关键词
                found_transform = False
                for node in path.intermediate:
                    node_line = self._get_line(node.symbol.location.line_start)
                    if any(kw.lower() in node_line.lower() for kw in keywords):
                        found_transform = True
                        break

                # 也检查 source 和 sink 之间的代码
                if not found_transform:
                    src_line = path.source.symbol.location.line_start
                    sink_line = path.sink.symbol.location.line_start
                    for lno in range(src_line + 1, sink_line):
                        line = self._get_line(lno)
                        if any(kw.lower() in line.lower() for kw in keywords):
                            found_transform = True
                            break

                if not found_transform:
                    return False

        return True

    def _check_call_chain(self, chain_def: dict) -> bool:
        """检查调用图中是否存在链式关系"""
        steps = chain_def['steps']

        # 提取关键函数
        source_funcs = set()
        sink_funcs = set()
        transform_funcs = set()

        for edge in self.result.call_graph:
            callee = edge.callee.lower()

            for step in steps:
                keywords = step.get('keywords', [])
                for kw in keywords:
                    if kw.lower() in callee:
                        if step['type'] == 'source':
                            source_funcs.add(edge.caller)
                            source_funcs.add(callee)
                        elif step['type'] == 'sink':
                            sink_funcs.add(callee)
                        elif step['type'] == 'transform':
                            transform_funcs.add(callee)

        # 检查调用路径
        for src in source_funcs:
            for snk in sink_funcs:
                if self.call_graph.has_path(src, snk):
                    return True

        return False

    def _calculate_confidence(
        self,
        matched_paths: list[TaintPath],
        required_steps: list[dict],
        graph_match: bool,
    ) -> float:
        """计算匹配置信度"""
        if not matched_paths:
            return 0.0

        # 基础分：有匹配路径
        base = 0.6

        # 多条路径 → 更高置信度
        if len(matched_paths) >= 2:
            base += 0.15

        # 调用图中有链式关系 → 更高置信度
        if graph_match:
            base += 0.15

        # 取路径中最高置信度
        max_path_conf = max(p.confidence for p in matched_paths)
        confidence = (base + max_path_conf) / 2

        return min(1.0, confidence)

    def _get_line(self, line_no: int) -> str:
        """获取指定行的源代码"""
        try:
            with open(self.result.file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            if 0 < line_no <= len(lines):
                return lines[line_no - 1]
        except OSError:
            pass
        return ""

    def _build_summary(
        self,
        chain_def: dict,
        matched_paths: list[TaintPath],
        confidence: float,
    ) -> str:
        """构建人类可读的摘要"""
        conf_pct = int(confidence * 100)
        severity = chain_def['severity'].upper()
        name = chain_def['name']

        summary = f"[{severity}] {name} (置信度: {conf_pct}%)"

        # 列出关键路径
        if matched_paths:
            summary += "\n检测到的关键路径:"
            for i, path in enumerate(matched_paths[:3], 1):  # 最多展示 3 条
                src_line = path.source.symbol.location.line_start
                sink_line = path.sink.symbol.location.line_start
                summary += f"\n  {i}. 行 {src_line} → 行 {sink_line}"

        return summary


def detect_chains(result: DeepAnalysisResult) -> DeepAnalysisResult:
    """检测攻击链"""
    if result.errors:
        return result

    detector = ChainDetector(result)
    result.attack_chains = detector.detect()
    return result
