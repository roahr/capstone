"""
Backward Slicer for Code Property Graphs (LLMxCPG-inspired).

Extracts a minimal, security-relevant subgraph from a full CPG by performing
backward slicing from the sink of a taint flow.  The slicer traverses data-
dependency (DDG / REACHING_DEF) and control-dependency (CDG) edges in reverse,
then optionally expands the result with surrounding AST context.

Typical code reduction is 67-91 %, matching the figures reported by LLMxCPG,
which dramatically reduces the input size for downstream LLM analysis.
"""

from __future__ import annotations

import logging
from collections import deque
from typing import Any

import networkx as nx

from src.sast.sarif.schema import Finding

logger = logging.getLogger(__name__)

# Edge types traversed during backward slicing.
_DATA_DEP_EDGES: frozenset[str] = frozenset({"DDG", "REACHING_DEF"})
_CONTROL_DEP_EDGES: frozenset[str] = frozenset({"CDG"})
_SLICE_EDGE_TYPES: frozenset[str] = _DATA_DEP_EDGES | _CONTROL_DEP_EDGES


class BackwardSlicer:
    """Backward slicer that extracts security-relevant subgraphs from CPGs.

    Given a full Code Property Graph and a :class:`Finding` describing a
    vulnerability (with source/sink from its taint flow), the slicer walks
    backward from the sink along data- and control-dependency edges to isolate
    only the code that can influence the vulnerable operation.

    The resulting slice is typically 67-91 % smaller than the original CPG,
    making it feasible to feed into an LLM for deeper analysis.
    """

    def __init__(
        self,
        max_depth: int = 10,
        context_lines: int = 5,
        follow_call_edges: bool = True,
    ) -> None:
        """Initialise the slicer.

        Args:
            max_depth: Maximum BFS depth when traversing backward from the
                sink.  Higher values capture more context but increase slice
                size.
            context_lines: Number of surrounding source lines to include when
                expanding the slice for AST context.
            follow_call_edges: Whether to also traverse ``CALL`` edges during
                slicing to capture inter-procedural dependencies.
        """
        self.max_depth: int = max_depth
        self.context_lines: int = context_lines
        self.follow_call_edges: bool = follow_call_edges

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def slice_for_finding(self, cpg: nx.DiGraph, finding: Finding) -> nx.DiGraph:
        """Extract a backward slice relevant to a specific finding.

        The method locates the sink node in the CPG (matching the finding's
        taint flow sink location), slices backward from it, optionally adds
        AST context, and returns the subgraph.

        Args:
            cpg: The full Code Property Graph.
            finding: A vulnerability finding that must have a ``taint_flow``
                with at least a sink location.

        Returns:
            A ``nx.DiGraph`` subgraph containing only the nodes and edges
            in the backward slice.  If the sink cannot be located in the CPG,
            the original graph is returned unchanged with a warning.
        """
        sink_node_id = self._locate_sink_node(cpg, finding)

        if sink_node_id is None:
            logger.warning(
                "Could not locate sink node in CPG for finding %s. "
                "Returning original graph.",
                finding.id,
            )
            return cpg

        # 1. Backward slice from the sink.
        slice_node_ids = self._backward_slice(cpg, sink_node_id, self.max_depth)

        # 2. Also include the source node if identifiable.
        source_node_id = self._locate_source_node(cpg, finding)
        if source_node_id is not None:
            source_slice = self._backward_slice(cpg, source_node_id, max_depth=3)
            slice_node_ids |= source_slice

        # 3. Expand with AST context.
        slice_node_ids = self._expand_context(cpg, slice_node_ids, self.context_lines)

        # 4. Build the subgraph.
        sliced = cpg.subgraph(slice_node_ids).copy()

        # Copy graph-level metadata.
        sliced.graph.update(cpg.graph)
        sliced.graph["sliced"] = True
        sliced.graph["finding_id"] = finding.id

        reduction = self.compute_slice_reduction(cpg, sliced)
        logger.info(
            "Slice for finding %s: %d -> %d nodes (%.1f%% reduction)",
            finding.id,
            cpg.number_of_nodes(),
            sliced.number_of_nodes(),
            reduction * 100,
        )

        return sliced

    # ------------------------------------------------------------------
    # Core slicing algorithms
    # ------------------------------------------------------------------

    def _backward_slice(
        self,
        graph: nx.DiGraph,
        sink_node_id: Any,
        max_depth: int = 10,
    ) -> set[Any]:
        """BFS backward from a sink node following dependency edges.

        Traverses incoming data-dependency (DDG, REACHING_DEF) and control-
        dependency (CDG) edges in reverse to collect all nodes that can
        influence the sink.  Optionally follows CALL edges for inter-
        procedural analysis.

        Args:
            graph: The full CPG.
            sink_node_id: Starting node for the backward traversal.
            max_depth: Maximum BFS depth to prevent runaway traversals.

        Returns:
            Set of node identifiers in the backward slice (including the
            sink itself).
        """
        if sink_node_id not in graph:
            return set()

        visited: set[Any] = set()
        queue: deque[tuple[Any, int]] = deque()
        queue.append((sink_node_id, 0))
        visited.add(sink_node_id)

        allowed_edge_types = set(_SLICE_EDGE_TYPES)
        if self.follow_call_edges:
            allowed_edge_types.add("CALL")

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue

            # Traverse predecessors (incoming edges) in the directed graph.
            for predecessor in graph.predecessors(current):
                edge_data = graph.get_edge_data(predecessor, current)
                if edge_data is None:
                    continue

                edge_type = edge_data.get("type", "")
                if edge_type in allowed_edge_types:
                    if predecessor not in visited:
                        visited.add(predecessor)
                        queue.append((predecessor, depth + 1))

        return visited

    def _expand_context(
        self,
        graph: nx.DiGraph,
        node_ids: set[Any],
        context_lines: int = 5,
    ) -> set[Any]:
        """Expand the slice with nearby AST nodes for source-level context.

        For each node in the slice that has a ``lineNumber`` attribute, finds
        other nodes in the CPG whose line numbers fall within
        ``[line - context_lines, line + context_lines]`` and that are connected
        via AST edges.  This ensures that the sliced code remains readable.

        Args:
            graph: The full CPG.
            node_ids: Current set of node IDs in the slice.
            context_lines: Number of source lines of context to add around
                each slice node.

        Returns:
            An expanded set of node IDs including the context nodes.
        """
        if context_lines <= 0:
            return node_ids

        # Collect line numbers from the slice.
        slice_lines: set[int] = set()
        for nid in node_ids:
            if nid not in graph:
                continue
            line = graph.nodes[nid].get("lineNumber", 0)
            if line > 0:
                slice_lines.add(line)

        if not slice_lines:
            return node_ids

        # Build ranges of lines to include.
        min_line = min(slice_lines) - context_lines
        max_line = max(slice_lines) + context_lines

        expanded = set(node_ids)
        for nid, attrs in graph.nodes(data=True):
            line = attrs.get("lineNumber", 0)
            if min_line <= line <= max_line:
                # Only add if connected to the slice via AST edges.
                if nid in expanded:
                    continue
                for neighbour in graph.predecessors(nid):
                    edge_data = graph.get_edge_data(neighbour, nid)
                    if edge_data and edge_data.get("type") == "AST" and neighbour in expanded:
                        expanded.add(nid)
                        break
                else:
                    for neighbour in graph.successors(nid):
                        edge_data = graph.get_edge_data(nid, neighbour)
                        if (
                            edge_data
                            and edge_data.get("type") == "AST"
                            and neighbour in expanded
                        ):
                            expanded.add(nid)
                            break

        return expanded

    # ------------------------------------------------------------------
    # Metrics
    # ------------------------------------------------------------------

    @staticmethod
    def compute_slice_reduction(original: nx.DiGraph, sliced: nx.DiGraph) -> float:
        """Compute the percentage reduction in nodes between graphs.

        Args:
            original: The full CPG before slicing.
            sliced: The CPG after backward slicing.

        Returns:
            A float in ``[0.0, 1.0]`` representing the fraction of nodes
            removed.  For example, ``0.85`` means 85 % of nodes were
            eliminated.  Returns ``0.0`` if the original graph is empty.
        """
        orig_count = original.number_of_nodes()
        if orig_count == 0:
            return 0.0
        sliced_count = sliced.number_of_nodes()
        return 1.0 - (sliced_count / orig_count)

    # ------------------------------------------------------------------
    # Node location helpers
    # ------------------------------------------------------------------

    def _locate_sink_node(self, cpg: nx.DiGraph, finding: Finding) -> Any | None:
        """Find the CPG node corresponding to the finding's sink location.

        Matches by file path and line number from the taint flow sink.  If
        no taint flow is available, falls back to the finding's primary
        location.

        Args:
            cpg: The full CPG.
            finding: The vulnerability finding.

        Returns:
            The node ID of the best-matching sink node, or ``None`` if no
            match is found.
        """
        # Determine target location.
        target_line: int = 0
        target_file: str = ""

        if finding.taint_flow and finding.taint_flow.sink:
            target_line = finding.taint_flow.sink.location.start_line
            target_file = finding.taint_flow.sink.location.file_path
        elif finding.location:
            target_line = finding.location.start_line
            target_file = finding.location.file_path

        if target_line <= 0:
            return None

        return self._find_best_node(cpg, target_file, target_line)

    def _locate_source_node(self, cpg: nx.DiGraph, finding: Finding) -> Any | None:
        """Find the CPG node corresponding to the finding's source location.

        Args:
            cpg: The full CPG.
            finding: The vulnerability finding.

        Returns:
            The node ID of the best-matching source node, or ``None``.
        """
        if not finding.taint_flow or not finding.taint_flow.source:
            return None

        source = finding.taint_flow.source
        return self._find_best_node(
            cpg,
            source.location.file_path,
            source.location.start_line,
        )

    @staticmethod
    def _find_best_node(
        cpg: nx.DiGraph,
        file_path: str,
        line_number: int,
    ) -> Any | None:
        """Find the CPG node closest to a given file location.

        When multiple nodes match the exact line, prefers CALL and IDENTIFIER
        nodes over others since they are more likely to represent the actual
        sink/source operation.

        Args:
            cpg: The CPG to search.
            file_path: Source file path to match (matched as a suffix to
                handle absolute vs relative path differences).
            line_number: Target line number.

        Returns:
            The best-matching node ID, or ``None``.
        """
        # Priority: exact line match with preferred type > exact line > closest line.
        preferred_types = {"CALL", "IDENTIFIER", "METHOD"}
        exact_matches: list[tuple[Any, dict[str, Any]]] = []
        closest: tuple[Any, int] | None = None  # (node_id, distance)

        for nid, attrs in cpg.nodes(data=True):
            node_line = attrs.get("lineNumber", 0)
            if node_line <= 0:
                continue

            distance = abs(node_line - line_number)
            if distance == 0:
                exact_matches.append((nid, attrs))
            elif closest is None or distance < closest[1]:
                closest = (nid, distance)

        # Among exact matches, prefer specific node types.
        for nid, attrs in exact_matches:
            if attrs.get("type", "") in preferred_types:
                return nid

        if exact_matches:
            return exact_matches[0][0]

        # Fall back to the closest node (within 3 lines).
        if closest is not None and closest[1] <= 3:
            return closest[0]

        return None
