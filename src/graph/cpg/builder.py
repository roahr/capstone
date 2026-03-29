"""
Joern CPG (Code Property Graph) Builder.

Constructs Code Property Graphs from source code using the Joern static analysis
framework. Supports multiple languages and produces NetworkX directed graphs with
full AST, CFG, DDG, CDG, and call-graph edge types.

When Joern is not available, falls back to a minimal stub graph for testing and
development purposes.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final

import networkx as nx

logger = logging.getLogger(__name__)

# Languages supported by Joern for CPG generation.
SUPPORTED_LANGUAGES: Final[frozenset[str]] = frozenset(
    {"python", "javascript", "java", "c", "cpp", "go"}
)

# Language name mappings for Joern CLI (Joern uses its own identifiers).
_JOERN_LANGUAGE_MAP: Final[dict[str, str]] = {
    "python": "pythonsrc",
    "javascript": "jssrc",
    "java": "javasrc",
    "c": "c",
    "cpp": "cpp",
    "go": "golang",
}

# Node type constants used in the CPG.
NODE_TYPES: Final[frozenset[str]] = frozenset(
    {
        "METHOD",
        "METHOD_RETURN",
        "METHOD_PARAMETER_IN",
        "METHOD_PARAMETER_OUT",
        "BLOCK",
        "CALL",
        "IDENTIFIER",
        "LITERAL",
        "LOCAL",
        "RETURN",
        "CONTROL_STRUCTURE",
        "FIELD_IDENTIFIER",
        "TYPE_REF",
        "UNKNOWN",
    }
)

# Edge type constants used in the CPG.
EDGE_TYPES: Final[frozenset[str]] = frozenset(
    {"AST", "CFG", "DDG", "CDG", "CALL", "REACHING_DEF"}
)

# Joern Scala script that exports the CPG to GraphML format.
_JOERN_EXPORT_SCRIPT: Final[str] = """\
@main def main(inputPath: String, outputPath: String): Unit = {
  importCode(inputPath)
  cpg.graph.export(outputPath, "graphml")
}
"""

# Joern Scala script that exports the CPG to JSON format.
_JOERN_JSON_EXPORT_SCRIPT: Final[str] = """\
@main def main(inputPath: String, outputPath: String): Unit = {
  importCode(inputPath)
  val nodes = cpg.all.map { n =>
    Map(
      "id" -> n.id(),
      "label" -> n.label,
      "properties" -> n.propertiesMap
    )
  }.toList
  val edges = cpg.graph.edges().asScala.map { e =>
    Map(
      "src" -> e.outNode().id(),
      "dst" -> e.inNode().id(),
      "label" -> e.label
    )
  }.toList
  val result = Map("nodes" -> nodes, "edges" -> edges)
  val json = upickle.default.write(result, indent = 2)
  os.write.over(os.Path(outputPath), json)
}
"""


class JoernCPGBuilder:
    """Builds Code Property Graphs using the Joern static analysis tool.

    This builder invokes Joern via its CLI to generate a CPG from source code,
    then parses the exported graph into a NetworkX ``DiGraph``. If Joern is not
    installed, it degrades gracefully by returning a minimal empty graph and
    logging a warning.

    Attributes:
        joern_path: Resolved path to the ``joern`` executable, or ``None``
            if Joern is not found on the system.
    """

    def __init__(self, joern_path: str | None = None) -> None:
        """Initialise the builder and locate the Joern binary.

        Args:
            joern_path: Explicit path to the ``joern`` executable.  If not
                provided, the builder searches ``$PATH`` automatically.
        """
        self.joern_path: str | None = joern_path or shutil.which("joern")
        if self.joern_path is None:
            logger.warning(
                "Joern executable not found on PATH. "
                "CPG generation will fall back to empty stub graphs. "
                "Install Joern from https://joern.io to enable full CPG analysis."
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_cpg(self, source_path: str, language: str) -> nx.DiGraph:
        """Generate a Code Property Graph from source code.

        Invokes Joern to parse the given source, export the CPG to GraphML,
        and convert it into a NetworkX directed graph.

        Args:
            source_path: Absolute or relative path to the source file or
                directory to analyse.
            language: Programming language of the source.  Must be one of
                :data:`SUPPORTED_LANGUAGES`.

        Returns:
            A ``nx.DiGraph`` representing the CPG.  Nodes carry attributes
            ``id``, ``type``, ``code``, ``lineNumber``, and ``columnNumber``.
            Edges carry the attribute ``type`` (e.g. ``AST``, ``CFG``).

        Raises:
            ValueError: If *language* is not supported.
            FileNotFoundError: If *source_path* does not exist.
        """
        language = language.lower()
        if language not in SUPPORTED_LANGUAGES:
            raise ValueError(
                f"Unsupported language '{language}'. "
                f"Supported: {sorted(SUPPORTED_LANGUAGES)}"
            )

        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source path does not exist: {source_path}")

        if self.joern_path is None:
            logger.warning(
                "Joern is not installed; returning an empty stub CPG. "
                "Install Joern for full CPG generation."
            )
            return self._build_stub_graph(source_path, language)

        return self._build_with_joern(source_path, language)

    def export_cpg(
        self,
        source_path: str,
        output_path: str,
        format: str = "graphml",
    ) -> None:
        """Export a CPG to a file.

        Uses Joern's export command to write the CPG in the requested format.
        If Joern is not installed, the method builds the CPG with the stub
        builder and serialises it with NetworkX instead.

        Args:
            source_path: Path to the source code.
            output_path: Destination file path for the exported graph.
            format: Output format -- ``"graphml"`` (default) or ``"json"``.

        Raises:
            ValueError: If *format* is not ``"graphml"`` or ``"json"``.
            FileNotFoundError: If *source_path* does not exist.
        """
        format = format.lower()
        if format not in ("graphml", "json"):
            raise ValueError(f"Unsupported export format '{format}'. Use 'graphml' or 'json'.")

        source = Path(source_path)
        if not source.exists():
            raise FileNotFoundError(f"Source path does not exist: {source_path}")

        if self.joern_path is None:
            logger.warning(
                "Joern is not installed; exporting a stub CPG via NetworkX."
            )
            graph = self._build_stub_graph(source_path, language="python")
            if format == "graphml":
                nx.write_graphml(graph, output_path)
            else:
                self._write_json(graph, output_path)
            return

        self._export_with_joern(source_path, output_path, format)

    # ------------------------------------------------------------------
    # Internal: Joern invocation
    # ------------------------------------------------------------------

    def _build_with_joern(self, source_path: str, language: str) -> nx.DiGraph:
        """Invoke Joern CLI to build and export the CPG, then parse it.

        Args:
            source_path: Path to source code.
            language: Language identifier (already validated).

        Returns:
            Parsed ``nx.DiGraph``.
        """
        with tempfile.TemporaryDirectory(prefix="secc_cpg_") as tmpdir:
            graphml_path = os.path.join(tmpdir, "cpg.graphml")
            script_path = os.path.join(tmpdir, "export_cpg.sc")

            # Write the Joern export script.
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(_JOERN_EXPORT_SCRIPT)

            cmd = [
                self.joern_path,  # type: ignore[list-item]
                "--script",
                script_path,
                "--param",
                f"inputPath={source_path}",
                "--param",
                f"outputPath={graphml_path}",
            ]

            logger.info("Running Joern: %s", " ".join(cmd))
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.error("Joern timed out after 300 s for %s", source_path)
                return self._build_stub_graph(source_path, language)

            if result.returncode != 0:
                logger.error(
                    "Joern failed (rc=%d) for %s:\nstdout: %s\nstderr: %s",
                    result.returncode,
                    source_path,
                    result.stdout,
                    result.stderr,
                )
                return self._build_stub_graph(source_path, language)

            if not os.path.isfile(graphml_path):
                logger.error("Joern did not produce a GraphML file at %s", graphml_path)
                return self._build_stub_graph(source_path, language)

            return self._parse_graphml(graphml_path)

    def _export_with_joern(
        self, source_path: str, output_path: str, format: str
    ) -> None:
        """Run Joern export command to write CPG in the given format.

        Args:
            source_path: Source code path.
            output_path: Destination file.
            format: ``"graphml"`` or ``"json"``.
        """
        with tempfile.TemporaryDirectory(prefix="secc_cpg_export_") as tmpdir:
            if format == "json":
                script_content = _JOERN_JSON_EXPORT_SCRIPT
            else:
                script_content = _JOERN_EXPORT_SCRIPT

            script_path = os.path.join(tmpdir, "export_cpg.sc")
            with open(script_path, "w", encoding="utf-8") as fh:
                fh.write(script_content)

            cmd = [
                self.joern_path,  # type: ignore[list-item]
                "--script",
                script_path,
                "--param",
                f"inputPath={source_path}",
                "--param",
                f"outputPath={output_path}",
            ]

            logger.info("Running Joern export: %s", " ".join(cmd))
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                logger.error("Joern export timed out after 300 s")
                return

            if result.returncode != 0:
                logger.error(
                    "Joern export failed (rc=%d):\nstdout: %s\nstderr: %s",
                    result.returncode,
                    result.stdout,
                    result.stderr,
                )

    # ------------------------------------------------------------------
    # GraphML parsing
    # ------------------------------------------------------------------

    def _parse_graphml(self, graphml_path: str) -> nx.DiGraph:
        """Parse a GraphML file produced by Joern into a NetworkX ``DiGraph``.

        Normalises node and edge attributes so that downstream consumers
        always see the same schema regardless of the Joern version used.

        Args:
            graphml_path: Path to the ``.graphml`` file.

        Returns:
            A ``nx.DiGraph`` with normalised node/edge attributes.
        """
        try:
            graph: nx.DiGraph = nx.read_graphml(graphml_path)
        except Exception:
            logger.exception("Failed to parse GraphML from %s", graphml_path)
            return nx.DiGraph()

        # Normalise node attributes.
        normalised = nx.DiGraph()
        for node_id, attrs in graph.nodes(data=True):
            normalised.add_node(
                node_id,
                id=attrs.get("id", node_id),
                type=attrs.get("label", attrs.get("type", "UNKNOWN")),
                code=attrs.get("CODE", attrs.get("code", "")),
                lineNumber=int(attrs.get("LINE_NUMBER", attrs.get("lineNumber", 0))),
                columnNumber=int(
                    attrs.get("COLUMN_NUMBER", attrs.get("columnNumber", 0))
                ),
            )

        for src, dst, attrs in graph.edges(data=True):
            edge_type = attrs.get("label", attrs.get("type", "UNKNOWN"))
            normalised.add_edge(src, dst, type=edge_type)

        logger.info(
            "Parsed CPG: %d nodes, %d edges from %s",
            normalised.number_of_nodes(),
            normalised.number_of_edges(),
            graphml_path,
        )
        return normalised

    # ------------------------------------------------------------------
    # Fallback stub builder
    # ------------------------------------------------------------------

    def _build_stub_graph(self, source_path: str, language: str) -> nx.DiGraph:
        """Build a minimal stub CPG when Joern is unavailable.

        The stub contains a single METHOD node representing the file.  This
        allows downstream components to operate without errors, though the
        analysis quality will be significantly reduced.

        Args:
            source_path: Original source path (stored as metadata).
            language: Language identifier.

        Returns:
            A minimal ``nx.DiGraph`` with a root METHOD node.
        """
        graph = nx.DiGraph()
        graph.graph["source_path"] = source_path
        graph.graph["language"] = language
        graph.graph["stub"] = True

        graph.add_node(
            0,
            id=0,
            type="METHOD",
            code=f"<stub for {Path(source_path).name}>",
            lineNumber=1,
            columnNumber=1,
        )
        return graph

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write_json(graph: nx.DiGraph, output_path: str) -> None:
        """Serialise a NetworkX graph to a JSON file.

        Args:
            graph: The graph to serialise.
            output_path: Destination file path.
        """
        data = nx.node_link_data(graph)
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
