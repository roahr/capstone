"""
Per-node feature extractor for GNN input.

Extracts six hand-crafted features per node from a Code Property Graph,
producing a (num_nodes, 6) tensor that is concatenated with 768-dim
GraphCodeBERT embeddings to form the 774-dim input for MiniGINv3.

These features match exactly what the Kaggle training pipeline computes,
so inference reproduces the same feature semantics.

Features (all normalised to [0, 1])
------------------------------------
1. **in_degree_norm**  -- node in-degree / max in-degree in the graph.
2. **out_degree_norm** -- node out-degree / max out-degree in the graph.
3. **is_sink**         -- 1.0 if the node's code matches a known taint sink.
4. **is_source**       -- 1.0 if the node's code matches a known taint source.
5. **depth_norm**      -- BFS depth from root / max BFS depth.
6. **language_id**     -- language encoding (py=0.0, js=0.2, java=0.4, c/cpp=0.6, go=0.8).
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

import networkx as nx
import torch

logger = logging.getLogger(__name__)


class NodeFeatureExtractor:
    """Extract per-node features from a Joern CPG.

    6 features per node, all normalised to [0, 1]:
      - in_degree_norm:  in-degree  / max_in_degree
      - out_degree_norm: out-degree / max_out_degree
      - is_sink:   1.0 if node looks like a taint sink
      - is_source: 1.0 if node looks like a taint source
      - depth_norm: BFS depth from root / max_depth
      - language_id: language encoding (py=0.0, js=0.2, java=0.4, c/cpp=0.6, go=0.8)
    """

    NUM_FEATURES: int = 6

    LANGUAGE_IDS: dict[str, float] = {
        "python": 0.0,
        "javascript": 0.2,
        "typescript": 0.2,
        "java": 0.4,
        "c": 0.6,
        "cpp": 0.6,
        "c_cpp": 0.6,
        "go": 0.8,
    }

    SINK_PATTERNS: list[str] = [
        "execute", "system", "popen", "eval", "exec", "write",
        "send", "print", "log", "query", "run", "open", "load",
        "deserialize", "pickle", "innerHTML",
    ]

    SOURCE_PATTERNS: list[str] = [
        "request", "input", "argv", "getenv", "environ",
        "read", "recv", "get_parameter", "getParameter",
        "stdin", "form", "query_string", "GET", "POST",
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(
        self, graph: nx.DiGraph, language: str = "python"
    ) -> torch.Tensor:
        """Extract per-node features from *graph*.

        Args:
            graph: A NetworkX directed graph (typically a CPG or CPG
                slice).  Nodes may carry ``"code"`` attributes used for
                sink/source detection.
            language: Programming language of the code (used for the
                ``language_id`` feature).

        Returns:
            A ``torch.Tensor`` of shape ``(num_nodes, 6)`` with dtype
            ``float32``.  If the graph is empty, returns a tensor of
            shape ``(0, 6)``.
        """
        nodes: list[Any] = list(graph.nodes())
        num_nodes = len(nodes)

        if num_nodes == 0:
            return torch.zeros(0, self.NUM_FEATURES, dtype=torch.float32)

        node_to_idx: dict[Any, int] = {n: i for i, n in enumerate(nodes)}

        # -- Degree features -------------------------------------------
        in_degrees = self._compute_in_degrees(graph, nodes)
        out_degrees = self._compute_out_degrees(graph, nodes)

        max_in = max(in_degrees) if in_degrees else 1
        max_out = max(out_degrees) if out_degrees else 1
        # Avoid division by zero when all degrees are 0
        max_in = max(max_in, 1)
        max_out = max(max_out, 1)

        in_degree_norm = [d / max_in for d in in_degrees]
        out_degree_norm = [d / max_out for d in out_degrees]

        # -- Sink / Source flags ---------------------------------------
        is_sink = self._detect_patterns(graph, nodes, self.SINK_PATTERNS)
        is_source = self._detect_patterns(graph, nodes, self.SOURCE_PATTERNS)

        # -- BFS depth from root ---------------------------------------
        depth_norm = self._compute_bfs_depth(graph, nodes, node_to_idx)

        # -- Language ID -----------------------------------------------
        lang_id = self.LANGUAGE_IDS.get(language.lower(), 0.5)

        # -- Assemble tensor -------------------------------------------
        features = torch.zeros(num_nodes, self.NUM_FEATURES, dtype=torch.float32)
        for i in range(num_nodes):
            features[i, 0] = in_degree_norm[i]
            features[i, 1] = out_degree_norm[i]
            features[i, 2] = is_sink[i]
            features[i, 3] = is_source[i]
            features[i, 4] = depth_norm[i]
            features[i, 5] = lang_id

        return features

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_in_degrees(
        graph: nx.DiGraph, nodes: list[Any]
    ) -> list[int]:
        """Return a list of in-degree values aligned with *nodes*."""
        return [graph.in_degree(n) for n in nodes]

    @staticmethod
    def _compute_out_degrees(
        graph: nx.DiGraph, nodes: list[Any]
    ) -> list[int]:
        """Return a list of out-degree values aligned with *nodes*."""
        return [graph.out_degree(n) for n in nodes]

    @staticmethod
    def _detect_patterns(
        graph: nx.DiGraph,
        nodes: list[Any],
        patterns: list[str],
    ) -> list[float]:
        """Return 1.0 for nodes whose ``code`` contains any *pattern*.

        Matching is case-insensitive.
        """
        results: list[float] = []
        for node in nodes:
            code: str = str(graph.nodes[node].get("code", "")).lower()
            matched = any(p.lower() in code for p in patterns)
            results.append(1.0 if matched else 0.0)
        return results

    @staticmethod
    def _compute_bfs_depth(
        graph: nx.DiGraph,
        nodes: list[Any],
        node_to_idx: dict[Any, int],
    ) -> list[float]:
        """Compute BFS depth from the root node, normalised to [0, 1].

        The *root* is selected as the node with the highest total degree
        (in + out).  If the graph is disconnected, unreachable nodes
        receive a depth of ``max_depth`` (i.e. normalised to 1.0).
        """
        num_nodes = len(nodes)
        if num_nodes == 0:
            return []

        # Pick root: highest total degree
        root = max(nodes, key=lambda n: graph.degree(n))

        # BFS
        depths: dict[Any, int] = {root: 0}
        queue: deque[Any] = deque([root])

        while queue:
            current = queue.popleft()
            current_depth = depths[current]
            # Traverse both predecessors and successors for an
            # undirected-style BFS (covers all reachable nodes
            # regardless of edge direction).
            for neighbour in set(graph.successors(current)) | set(
                graph.predecessors(current)
            ):
                if neighbour not in depths:
                    depths[neighbour] = current_depth + 1
                    queue.append(neighbour)

        max_depth = max(depths.values()) if depths else 1
        max_depth = max(max_depth, 1)  # avoid div-by-zero

        result: list[float] = []
        for node in nodes:
            d = depths.get(node, max_depth)
            result.append(d / max_depth)

        return result
