"""
调用图构建器：从 AST 分析结果构建函数调用关系图。

支持：
- 直接调用：A 函数调用 B 函数
- 间接调用追踪：通过 import 解析跨模块调用
- 环路检测：检测递归和互相调用
"""

from collections import defaultdict
from code_sentry.analysis.models import CallEdge, DeepAnalysisResult


class CallGraph:
    """函数调用图"""

    def __init__(self):
        # 邻接表：caller → [callee]
        self.graph: dict[str, list[str]] = defaultdict(list)
        # 反向邻接表：callee → [caller]
        self.reverse_graph: dict[str, list[str]] = defaultdict(list)
        # 所有节点
        self.nodes: set[str] = set()

    def add_edge(self, edge: CallEdge):
        """添加一条调用边"""
        self.graph[edge.caller].append(edge.callee)
        self.reverse_graph[edge.callee].append(edge.caller)
        self.nodes.add(edge.caller)
        self.nodes.add(edge.callee)

    def get_callees(self, func_name: str) -> list[str]:
        """获取某个函数调用的所有函数"""
        return self.graph.get(func_name, [])

    def get_callers(self, func_name: str) -> list[str]:
        """获取调用某个函数的所有函数"""
        return self.reverse_graph.get(func_name, [])

    def has_path(self, source: str, target: str, max_depth: int = 5) -> bool:
        """检查从 source 到 target 是否存在调用路径（BFS）"""
        if source == target:
            return True

        visited = {source}
        queue = [source]
        depth = 0

        while queue and depth < max_depth:
            next_queue = []
            for node in queue:
                for callee in self.graph.get(node, []):
                    if callee == target:
                        return True
                    if callee not in visited:
                        visited.add(callee)
                        next_queue.append(callee)
            queue = next_queue
            depth += 1

        return False

    def find_all_paths(self, source: str, target: str, max_depth: int = 5) -> list[list[str]]:
        """找到从 source 到 target 的所有调用路径（DFS）"""
        paths = []

        def dfs(current: str, target: str, visited: list[str], depth: int):
            if depth > max_depth:
                return
            if current == target:
                paths.append(visited + [current])
                return
            for callee in self.graph.get(current, []):
                if callee not in visited:
                    dfs(callee, target, visited + [current], depth + 1)

        dfs(source, target, [], 0)
        return paths

    def get_reachable_from(self, func_name: str, max_depth: int = 5) -> set[str]:
        """获取从某个函数出发能到达的所有函数"""
        visited = set()
        queue = [func_name]
        depth = 0

        while queue and depth < max_depth:
            next_queue = []
            for node in queue:
                for callee in self.graph.get(node, []):
                    if callee not in visited:
                        visited.add(callee)
                        next_queue.append(callee)
            queue = next_queue
            depth += 1

        return visited

    def detect_cycles(self) -> list[list[str]]:
        """检测调用图中的环路"""
        cycles = []
        visited = set()
        stack = []

        def dfs(node: str):
            if node in stack:
                cycle_start = stack.index(node)
                cycles.append(stack[cycle_start:] + [node])
                return
            if node in visited:
                return

            visited.add(node)
            stack.append(node)

            for callee in self.graph.get(node, []):
                dfs(callee)

            stack.pop()

        for node in self.nodes:
            if node not in visited:
                dfs(node)

        return cycles

    def to_summary(self) -> dict:
        """生成摘要"""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": sum(len(v) for v in self.graph.values()),
            "isolated_nodes": len([n for n in self.nodes
                                   if not self.graph.get(n) and not self.reverse_graph.get(n)]),
            "max_callers": max((len(v) for v in self.reverse_graph.values()), default=0),
            "max_callees": max((len(v) for v in self.graph.values()), default=0),
        }


def build_call_graph(result: DeepAnalysisResult) -> CallGraph:
    """从深度分析结果构建调用图"""
    graph = CallGraph()
    for edge in result.call_graph:
        graph.add_edge(edge)
    return graph
