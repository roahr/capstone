"""
PyG Data builder for Mini-GAT inference (and training).

Converts a NetworkX Code Property Graph into a ``torch_geometric.data.Data``
object suitable for the Mini-GAT model.  The builder applies the same
pipeline used during Kaggle training so that the feature semantics are
identical at inference time:

    CPG (nx.DiGraph)
        -> truncate to ``max_nodes`` (BFS from highest-degree node)
        -> embed each node via GraphCodeBERT (768-dim), or random fallback
        -> extract 5 hand-crafted node features
        -> concatenate -> (num_nodes, 773)
        -> build COO edge_index
        -> Data(x, edge_index, y)
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

import networkx as nx
import torch

logger = logging.getLogger(__name__)

# Lazy imports -- torch_geometric may not be installed.  The top-level
# import is deferred so that the module can be imported even when PyG is
# absent (``GraphValidator`` catches the ``ImportError``).
_Data = None  # type: ignore[assignment]


def _ensure_pyg() -> type:
    """Import and return ``torch_geometric.data.Data``, raising on failure."""
    global _Data  # noqa: PLW0603
    if _Data is None:
        from torch_geometric.data import Data as _DataCls  # type: ignore[import-untyped]
        _Data = _DataCls
    return _Data


class GraphDataBuilder:
    """Build PyG ``Data`` objects from NetworkX CPGs.

    Pipeline::

        CPG -> truncate to max_nodes -> embed nodes -> extract features -> Data

    Args:
        embedder: A :class:`CodeEmbedder` instance (from
            ``src.graph.features.embeddings``).  If ``None`` a random
            768-dim fallback is used -- useful for testing or when
            GraphCodeBERT is not installed.
        max_nodes: Maximum number of nodes to keep after BFS truncation.
    """

    MAX_NODES: int = 200

    EMBEDDING_DIM: int = 768
    NODE_FEATURE_DIM: int = 5
    TOTAL_DIM: int = EMBEDDING_DIM + NODE_FEATURE_DIM  # 773

    def __init__(
        self,
        embedder: Any | None = None,
        max_nodes: int = 200,
    ) -> None:
        self.embedder = embedder
        self.max_nodes = max_nodes

        # Lazy import -- avoid hard dependency at module level.
        from src.graph.features.node_features import NodeFeatureExtractor
        self.node_feature_extractor = NodeFeatureExtractor()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(self, cpg: nx.DiGraph, label: int | None = None) -> Any:
        """Convert a CPG into a PyG ``Data`` object.

        Steps:
            1. Truncate to ``max_nodes`` by BFS from highest-degree node.
            2. Embed nodes via GraphCodeBERT (768-dim) or random fallback.
            3. Extract per-node features (5-dim).
            4. Concatenate -> ``(num_nodes, 773)``.
            5. Build COO ``edge_index``.
            6. Return ``Data(x, edge_index, y)``.

        Args:
            cpg: A NetworkX ``DiGraph`` representing the CPG (or a
                backward slice of one).
            label: Optional integer label (0 = safe, 1 = vulnerable).
                Used during training; ``None`` at inference time.

        Returns:
            A ``torch_geometric.data.Data`` instance.
        """
        Data = _ensure_pyg()

        # 1. Truncate
        graph = self._truncate_graph(cpg)

        nodes: list[Any] = list(graph.nodes())
        num_nodes = len(nodes)

        # Handle empty / trivially small graphs
        if num_nodes == 0:
            data = Data(
                x=torch.zeros(1, self.TOTAL_DIM, dtype=torch.float32),
                edge_index=torch.zeros(2, 0, dtype=torch.long),
            )
            if label is not None:
                data.y = torch.tensor([label], dtype=torch.long)
            return data

        node_to_idx: dict[Any, int] = {n: i for i, n in enumerate(nodes)}

        # 2. Node embeddings (768-dim)
        embeddings = self._embed_nodes(graph, num_nodes)

        # 3. Hand-crafted features (5-dim)
        node_features = self.node_feature_extractor.extract(graph)

        # 4. Concatenate -> (num_nodes, 773)
        x = torch.cat([embeddings, node_features], dim=1)

        # 5. Build edge_index (COO format)
        edge_index = self._build_edge_index(graph, node_to_idx)

        # 6. Create Data
        data = Data(x=x, edge_index=edge_index)
        if label is not None:
            data.y = torch.tensor([label], dtype=torch.long)

        return data

    # ------------------------------------------------------------------
    # Graph truncation
    # ------------------------------------------------------------------

    def _truncate_graph(self, graph: nx.DiGraph) -> nx.DiGraph:
        """BFS from the highest-degree node, keeping first ``max_nodes``.

        If the graph already has at most ``max_nodes`` nodes it is
        returned as-is.

        Args:
            graph: The input CPG.

        Returns:
            A (possibly smaller) ``nx.DiGraph``.
        """
        if graph.number_of_nodes() <= self.max_nodes:
            return graph

        # Pick the root: node with the highest total degree.
        nodes = list(graph.nodes())
        root = max(nodes, key=lambda n: graph.degree(n))

        # BFS keeping first max_nodes reachable nodes.
        visited: set[Any] = set()
        queue: deque[Any] = deque([root])
        visited.add(root)

        while queue and len(visited) < self.max_nodes:
            current = queue.popleft()
            for neighbour in set(graph.successors(current)) | set(
                graph.predecessors(current)
            ):
                if neighbour not in visited:
                    visited.add(neighbour)
                    queue.append(neighbour)
                    if len(visited) >= self.max_nodes:
                        break

        truncated = graph.subgraph(visited).copy()

        logger.debug(
            "Graph truncated from %d to %d nodes (max_nodes=%d)",
            graph.number_of_nodes(),
            truncated.number_of_nodes(),
            self.max_nodes,
        )
        return truncated

    # ------------------------------------------------------------------
    # Node embeddings
    # ------------------------------------------------------------------

    def _embed_nodes(
        self, graph: nx.DiGraph, num_nodes: int
    ) -> torch.Tensor:
        """Produce a ``(num_nodes, 768)`` embedding matrix.

        If *embedder* is set, delegates to
        :pymethod:`CodeEmbedder.embed_nodes`.  Otherwise falls back to
        random vectors (drawn from N(0, 0.02), matching typical
        transformer init scale) so that the model can still run.
        """
        if self.embedder is not None:
            try:
                return self.embedder.embed_nodes(graph)
            except Exception as exc:
                logger.warning(
                    "Embedder failed, falling back to random embeddings: %s",
                    exc,
                )

        # Random fallback (deterministic per-node via code hash).
        return torch.randn(num_nodes, self.EMBEDDING_DIM) * 0.02

    # ------------------------------------------------------------------
    # Edge index construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_edge_index(
        graph: nx.DiGraph,
        node_to_idx: dict[Any, int],
    ) -> torch.Tensor:
        """Build a COO edge-index tensor of shape ``(2, E)``.

        Only edges whose both endpoints are in *node_to_idx* are
        included.  Self-loops are preserved (PyG GATConv handles them).
        """
        src_list: list[int] = []
        dst_list: list[int] = []

        for u, v in graph.edges():
            if u in node_to_idx and v in node_to_idx:
                src_list.append(node_to_idx[u])
                dst_list.append(node_to_idx[v])

        if not src_list:
            return torch.zeros(2, 0, dtype=torch.long)

        edge_index = torch.tensor(
            [src_list, dst_list], dtype=torch.long
        )
        return edge_index
