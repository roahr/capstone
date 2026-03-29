"""
Graph Feature Extractor for Code Property Graphs.

Extracts five topology-based features from a (typically sliced) CPG that
characterise the structural risk of a vulnerability finding.  All feature
values are normalised to the ``[0, 1]`` range so they can be consumed
directly by downstream classifiers or scoring functions.

Features
--------
1. **taint_path_length** -- number of hops from source to sink in the slice.
2. **control_flow_complexity** -- cyclomatic complexity (decision-node ratio).
3. **data_flow_fan_out** -- maximum outgoing data-dependency degree, normalised.
4. **sanitizer_coverage** -- fraction of source-sink paths that traverse a
   sanitizer-like node.
5. **interprocedural_depth** -- number of CALL edges crossed, normalised.
"""

from __future__ import annotations

import logging
import math
from typing import Any

import networkx as nx

from src.sast.sarif.schema import Finding

logger = logging.getLogger(__name__)

# Heuristic patterns that indicate a sanitizer or validation function.
_SANITIZER_PATTERNS: tuple[str, ...] = (
    "sanitize",
    "sanitise",
    "escape",
    "encode",
    "validate",
    "filter",
    "clean",
    "purify",
    "strip",
    "quote",
    "parameterize",
    "htmlspecialchars",
    "urlencode",
    "bleach",
    "dompurify",
    "cgi.escape",
    "markupsafe",
    "html.escape",
    "shlex.quote",
)

# Normalisation ceilings -- values above these are clamped to 1.0.
_MAX_TAINT_PATH_LENGTH: int = 20
_MAX_FAN_OUT: int = 15
_MAX_INTERPROCEDURAL_DEPTH: int = 8


class GraphFeatureExtractor:
    """Extracts normalised topology features from a Code Property Graph.

    Features are designed to quantify the structural risk profile of a
    vulnerability finding and can feed into a GNN classifier, a conformal
    prediction model, or a simple scoring heuristic.

    All five feature values are floats in ``[0, 1]``.
    """

    def extract_features(self, cpg: nx.DiGraph, finding: Finding) -> dict[str, float]:
        """Extract all five topology features for a finding.

        Args:
            cpg: A (preferably sliced) Code Property Graph.
            finding: The vulnerability finding whose taint flow defines the
                source and sink locations.

        Returns:
            A dictionary with keys ``taint_path_length``,
            ``control_flow_complexity``, ``data_flow_fan_out``,
            ``sanitizer_coverage``, and ``interprocedural_depth``.
            Each value is a float in ``[0.0, 1.0]``.
        """
        source_id = self._locate_node(cpg, finding, role="source")
        sink_id = self._locate_node(cpg, finding, role="sink")

        features: dict[str, float] = {
            "taint_path_length": self._taint_path_length(cpg, source_id, sink_id),
            "control_flow_complexity": self._control_flow_complexity(cpg),
            "data_flow_fan_out": self._data_flow_fan_out(cpg),
            "sanitizer_coverage": self._sanitizer_coverage(cpg, source_id, sink_id),
            "interprocedural_depth": self._interprocedural_depth(cpg, source_id, sink_id),
        }

        logger.debug("Extracted features for finding %s: %s", finding.id, features)
        return features

    # ------------------------------------------------------------------
    # Feature 1: Taint Path Length
    # ------------------------------------------------------------------

    def _taint_path_length(
        self,
        cpg: nx.DiGraph,
        source_id: Any | None,
        sink_id: Any | None,
    ) -> float:
        """Compute normalised shortest-path length from source to sink.

        Uses data-dependency and control-dependency edges to find the shortest
        path.  Longer paths indicate more complex data propagation, which may
        either increase false-positive likelihood (benign transformations) or
        indicate deeper vulnerabilities.

        Returns:
            Normalised value in ``[0, 1]``.  Returns ``1.0`` if no path exists
            (indicating maximum uncertainty).
        """
        if source_id is None or sink_id is None:
            return 1.0

        if source_id not in cpg or sink_id not in cpg:
            return 1.0

        # Build a subgraph with only data/control dependency edges.
        dep_graph = self._dependency_subgraph(cpg)

        try:
            path_length = nx.shortest_path_length(dep_graph, source_id, sink_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            # Try the full graph as fallback.
            try:
                path_length = nx.shortest_path_length(cpg, source_id, sink_id)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return 1.0

        return min(path_length / _MAX_TAINT_PATH_LENGTH, 1.0)

    # ------------------------------------------------------------------
    # Feature 2: Control Flow Complexity
    # ------------------------------------------------------------------

    def _control_flow_complexity(self, cpg: nx.DiGraph) -> float:
        """Compute normalised cyclomatic complexity from the CPG.

        Cyclomatic complexity is estimated as the ratio of decision nodes
        (CONTROL_STRUCTURE type) to total nodes.  This captures how many
        conditional branches exist in the analysed code region.

        Returns:
            Normalised value in ``[0, 1]``.
        """
        total_nodes = cpg.number_of_nodes()
        if total_nodes == 0:
            return 0.0

        decision_count = 0
        for _, attrs in cpg.nodes(data=True):
            node_type = attrs.get("type", "")
            code = attrs.get("code", "").lower()
            if node_type == "CONTROL_STRUCTURE":
                decision_count += 1
            elif node_type == "CALL" and code in ("if", "while", "for", "switch", "case"):
                decision_count += 1

        # Cyclomatic complexity M = E - N + 2P, but we approximate using
        # the decision-node ratio capped by a sigmoid for normalisation.
        ratio = decision_count / total_nodes
        # Use a sigmoid-like transformation so that moderate complexity
        # maps to ~0.5 and very high complexity saturates at ~1.0.
        normalised = 1.0 - math.exp(-5.0 * ratio)
        return round(min(max(normalised, 0.0), 1.0), 6)

    # ------------------------------------------------------------------
    # Feature 3: Data Flow Fan-Out
    # ------------------------------------------------------------------

    def _data_flow_fan_out(self, cpg: nx.DiGraph) -> float:
        """Compute normalised maximum data-dependency fan-out.

        The fan-out is the maximum number of outgoing DDG or REACHING_DEF
        edges from any single node.  High fan-out indicates a variable that
        flows into many downstream operations.

        Returns:
            Normalised value in ``[0, 1]``.
        """
        max_fan_out = 0

        for node in cpg.nodes():
            ddg_out = 0
            for _, _, attrs in cpg.out_edges(node, data=True):
                edge_type = attrs.get("type", "")
                if edge_type in ("DDG", "REACHING_DEF"):
                    ddg_out += 1
            max_fan_out = max(max_fan_out, ddg_out)

        if max_fan_out == 0:
            return 0.0

        return min(max_fan_out / _MAX_FAN_OUT, 1.0)

    # ------------------------------------------------------------------
    # Feature 4: Sanitizer Coverage
    # ------------------------------------------------------------------

    def _sanitizer_coverage(
        self,
        cpg: nx.DiGraph,
        source_id: Any | None,
        sink_id: Any | None,
    ) -> float:
        """Compute the ratio of source-to-sink paths passing through a sanitizer.

        Identifies sanitizer-like nodes by matching their ``code`` attribute
        against known sanitisation function patterns.  Then enumerates simple
        paths between source and sink and checks how many traverse at least
        one sanitizer.

        Higher coverage means more paths are protected, which lowers the
        likelihood of a true positive vulnerability.

        Returns:
            Normalised value in ``[0, 1]``.  ``0.0`` means no paths are
            sanitised; ``1.0`` means all paths are sanitised.
        """
        if source_id is None or sink_id is None:
            return 0.0

        if source_id not in cpg or sink_id not in cpg:
            return 0.0

        # Find sanitizer nodes.
        sanitizer_ids: set[Any] = set()
        for nid, attrs in cpg.nodes(data=True):
            code = attrs.get("code", "").lower()
            node_type = attrs.get("type", "")
            if node_type in ("CALL", "IDENTIFIER", "METHOD"):
                if any(pattern in code for pattern in _SANITIZER_PATTERNS):
                    sanitizer_ids.add(nid)

        if not sanitizer_ids:
            return 0.0

        # Enumerate paths (bounded to avoid combinatorial explosion).
        max_paths = 50
        total_paths = 0
        sanitised_paths = 0

        try:
            for path in nx.all_simple_paths(cpg, source_id, sink_id, cutoff=15):
                total_paths += 1
                path_set = set(path)
                if path_set & sanitizer_ids:
                    sanitised_paths += 1
                if total_paths >= max_paths:
                    break
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return 0.0

        if total_paths == 0:
            return 0.0

        return round(sanitised_paths / total_paths, 6)

    # ------------------------------------------------------------------
    # Feature 5: Interprocedural Depth
    # ------------------------------------------------------------------

    def _interprocedural_depth(
        self,
        cpg: nx.DiGraph,
        source_id: Any | None,
        sink_id: Any | None,
    ) -> float:
        """Count the number of CALL edges on the path from source to sink.

        Interprocedural depth measures how many function boundaries the taint
        flow crosses.  Deeper interprocedural paths are harder for simple SAST
        tools to track.

        Returns:
            Normalised value in ``[0, 1]``.
        """
        if source_id is None or sink_id is None:
            # Fall back to counting all CALL edges in the graph.
            call_edge_count = sum(
                1
                for _, _, attrs in cpg.edges(data=True)
                if attrs.get("type") == "CALL"
            )
            return min(call_edge_count / _MAX_INTERPROCEDURAL_DEPTH, 1.0)

        if source_id not in cpg or sink_id not in cpg:
            return 0.0

        # Find the shortest path and count CALL edges along it.
        try:
            path = nx.shortest_path(cpg, source_id, sink_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return 0.0

        call_count = 0
        for i in range(len(path) - 1):
            edge_data = cpg.get_edge_data(path[i], path[i + 1])
            if edge_data and edge_data.get("type") == "CALL":
                call_count += 1

        return min(call_count / _MAX_INTERPROCEDURAL_DEPTH, 1.0)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _dependency_subgraph(cpg: nx.DiGraph) -> nx.DiGraph:
        """Create a subgraph containing only data/control dependency edges.

        Args:
            cpg: The full CPG.

        Returns:
            A view (not a copy) of the CPG with only DDG, REACHING_DEF,
            CDG, and CFG edges.
        """
        dep_edge_types = {"DDG", "REACHING_DEF", "CDG", "CFG"}
        edges_to_keep = [
            (u, v)
            for u, v, attrs in cpg.edges(data=True)
            if attrs.get("type", "") in dep_edge_types
        ]
        sub = cpg.edge_subgraph(edges_to_keep)
        return sub

    @staticmethod
    def _locate_node(
        cpg: nx.DiGraph,
        finding: Finding,
        role: str = "sink",
    ) -> Any | None:
        """Locate a source or sink node in the CPG by taint-flow location.

        Args:
            cpg: The CPG to search.
            finding: The vulnerability finding.
            role: ``"source"`` or ``"sink"``.

        Returns:
            The node ID of the matching CPG node, or ``None``.
        """
        if not finding.taint_flow:
            if role == "sink" and finding.location:
                target_line = finding.location.start_line
            else:
                return None
        elif role == "source":
            step = finding.taint_flow.source
            if step is None:
                return None
            target_line = step.location.start_line
        else:
            step = finding.taint_flow.sink
            if step is None:
                if finding.location:
                    target_line = finding.location.start_line
                else:
                    return None
            else:
                target_line = step.location.start_line

        if target_line <= 0:
            return None

        # Find the best matching node.
        preferred_types = {"CALL", "IDENTIFIER", "METHOD"}
        exact_matches: list[tuple[Any, dict[str, Any]]] = []
        closest: tuple[Any, int] | None = None

        for nid, attrs in cpg.nodes(data=True):
            node_line = attrs.get("lineNumber", 0)
            if node_line <= 0:
                continue
            distance = abs(node_line - target_line)
            if distance == 0:
                exact_matches.append((nid, attrs))
            elif closest is None or distance < closest[1]:
                closest = (nid, distance)

        for nid, attrs in exact_matches:
            if attrs.get("type", "") in preferred_types:
                return nid

        if exact_matches:
            return exact_matches[0][0]

        if closest is not None and closest[1] <= 3:
            return closest[0]

        return None
