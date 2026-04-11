"""
Graph Validator -- Module 2 inference orchestrator.

Runs the full graph-augmented validation pipeline for escalated findings:

    1. Build a CPG via Joern (or fall back to a simplified line graph)
    2. Backward-slice the CPG for the finding's taint flow
    3. Build a PyG ``Data`` object (same pipeline as Kaggle training)
    4. Run Mini-GAT forward pass (eval mode, CPU only)
    5. Apply conformal prediction to decide escalation
    6. Attach :class:`GraphValidation` to the :class:`Finding`

The validator degrades gracefully when optional dependencies are
missing:

* **Joern not installed** -- builds a simplified graph from code
  lines in the finding's location.
* **Model file missing** -- skips the GNN and uses only the
  graph-topology feature extractor to populate the validation.
* **torch / torch_geometric not installed** -- the import error is
  caught in ``__init__`` and the class signals unavailability via
  :pyattr:`available`.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

import networkx as nx

from src.sast.sarif.schema import Finding, GraphValidation

logger = logging.getLogger(__name__)

# Sentinel: lazy-loaded heavy modules
_torch = None
_torch_F = None  # torch.nn.functional


def _ensure_torch():
    """Import torch lazily and cache it."""
    global _torch, _torch_F  # noqa: PLW0603
    if _torch is None:
        import torch
        import torch.nn.functional as F

        _torch = torch
        _torch_F = F
    return _torch, _torch_F


class GraphValidator:
    """Module 2: Graph-augmented structural validation.

    For each escalated finding:
        1. Build CPG via Joern (or stub)
        2. Backward slice for the finding
        3. Build PyG Data (same pipeline as training)
        4. Run MiniGAT forward pass (eval mode, CPU)
        5. Apply conformal prediction
        6. Attach ``GraphValidation`` to ``Finding``

    Args:
        config: The ``graph`` section of the framework configuration
            (from ``configs/default.yaml``).  If ``None``, defaults
            are used for all parameters.
    """

    def __init__(self, config: dict | None = None) -> None:
        self._config = config or {}
        self._available = False
        self._model = None
        self._conformal = None
        self._builder = None       # JoernCPGBuilder
        self._slicer = None        # BackwardSlicer
        self._data_builder = None  # GraphDataBuilder
        self._feature_extractor = None  # GraphFeatureExtractor

        # Metadata exposed to the pipeline for display
        self.last_validation_metadata: dict[str, Any] = {}

        self._init_components()

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """Whether the GNN model was loaded successfully."""
        return self._available

    # ------------------------------------------------------------------
    # Initialisation helpers
    # ------------------------------------------------------------------

    def _init_components(self) -> None:
        """Wire up all sub-components, handling missing dependencies."""
        # -- CPG builder -----------------------------------------------
        try:
            from src.graph.cpg.builder import JoernCPGBuilder

            joern_cfg = self._config.get("joern", {})
            self._builder = JoernCPGBuilder(
                joern_path=joern_cfg.get("binary_path")
            )
        except Exception as exc:
            logger.warning("JoernCPGBuilder unavailable: %s", exc)

        # -- Backward slicer ------------------------------------------
        try:
            from src.graph.slicing.slicer import BackwardSlicer

            self._slicer = BackwardSlicer()
        except Exception as exc:
            logger.warning("BackwardSlicer unavailable: %s", exc)

        # -- Graph feature extractor -----------------------------------
        try:
            from src.graph.features.extractor import GraphFeatureExtractor

            self._feature_extractor = GraphFeatureExtractor()
        except Exception as exc:
            logger.warning("GraphFeatureExtractor unavailable: %s", exc)

        # -- GNN-related components (torch required) -------------------
        try:
            torch, F = _ensure_torch()
            self._init_gnn(torch)
        except ImportError:
            logger.info(
                "torch/torch_geometric not installed -- "
                "GNN inference disabled"
            )
        except Exception as exc:
            logger.warning("GNN init failed: %s", exc)

    def _init_gnn(self, torch: Any) -> None:
        """Load the Mini-GAT model, conformal calibration and data builder."""
        gnn_cfg = self._config.get("gnn", {})

        # -- Resolve model path ----------------------------------------
        model_path = Path(
            gnn_cfg.get("model_path", "data/models/mini_gat.pt")
        )
        if not model_path.exists():
            logger.info("GNN model not found at %s -- GNN disabled", model_path)
            self._init_data_builder_only()
            return

        # -- Load model ------------------------------------------------
        from src.graph.gnn.mini_gin_v3 import MiniGINv3

        self._model = MiniGINv3(
            input_dim=int(gnn_cfg.get("input_dim", 774)),
            hidden_dim=int(gnn_cfg.get("hidden_dim", 384)),
            num_gin_layers=int(gnn_cfg.get("num_gin_layers", 3)),
            dropout=float(gnn_cfg.get("dropout", 0.35)),
            num_classes=int(gnn_cfg.get("num_classes", 2)),
        )

        state_dict = torch.load(
            model_path,
            map_location=torch.device("cpu"),
            weights_only=False,
        )
        self._model.load_state_dict(state_dict)
        self._model.eval()
        logger.info(
            "MiniGINv3 loaded from %s (%s params)",
            model_path,
            f"{self._model.parameter_count()['trainable']:,}",
        )

        # -- Conformal calibration -------------------------------------
        cal_path = model_path.parent / "conformal_calibration.json"
        self._load_conformal_calibration(cal_path)

        # -- Data builder (with optional embedder) ---------------------
        self._init_data_builder()

        self._available = True

    def _load_conformal_calibration(self, cal_path: Path) -> None:
        """Load the quantile threshold from a saved calibration JSON.

        The training script (``scripts/train_gat.py``) saves a JSON
        file produced by ``ConformalPredictor.get_calibration_stats()``.
        We restore the threshold from that file so we can skip the
        calibrate() step at inference time.
        """
        if not cal_path.exists():
            logger.info(
                "Conformal calibration not found at %s -- "
                "conformal prediction will be disabled",
                cal_path,
            )
            return

        try:
            with open(cal_path, "r", encoding="utf-8") as f:
                cal_data = json.load(f)

            from src.graph.uncertainty.conformal import ConformalPredictor

            alpha = float(cal_data.get("alpha", 0.1))
            self._conformal = ConformalPredictor(alpha=alpha)
            # Directly set internal state from saved calibration
            # Support both key names for backward compatibility
            threshold = cal_data.get(
                "quantile_threshold",
                cal_data.get("threshold", 1.0),
            )
            self._conformal._quantile_threshold = float(threshold)
            self._conformal._calibration_size = int(
                cal_data.get("calibration_size",
                             cal_data.get("n_calibration", 0))
            )
            self._conformal._is_calibrated = True

            # Load ConfTS temperature if present
            temperature = float(cal_data.get("conformal_temperature", 1.0))
            self._conformal._temperature = temperature

            logger.info(
                "Conformal calibration loaded: alpha=%.2f, "
                "threshold=%.4f, temperature=%.4f (from %s)",
                alpha,
                self._conformal._quantile_threshold,
                temperature,
                cal_path,
            )
        except Exception as exc:
            logger.warning(
                "Failed to load conformal calibration from %s: %s",
                cal_path,
                exc,
            )

    def _init_data_builder(self) -> None:
        """Initialise the PyG data builder, optionally with an embedder."""
        embedder = self._try_create_embedder()
        max_nodes = int(
            self._config.get("gnn", {}).get("max_nodes", 200)
        )

        from src.graph.gnn.data_builder import GraphDataBuilder

        self._data_builder = GraphDataBuilder(
            embedder=embedder,
            max_nodes=max_nodes,
        )

    def _init_data_builder_only(self) -> None:
        """Initialise just the data builder (no model loaded)."""
        try:
            self._init_data_builder()
        except Exception as exc:
            logger.debug(
                "Could not create data builder (non-critical): %s", exc
            )

    def _try_create_embedder(self) -> Any | None:
        """Attempt to create a CodeEmbedder; return None on failure."""
        try:
            from src.graph.features.embeddings import CodeEmbedder

            emb_cfg = self._config.get("embeddings", {})
            model_name = emb_cfg.get(
                "model", "microsoft/graphcodebert-base"
            )
            device = emb_cfg.get("device", "cpu")
            embedder = CodeEmbedder(
                model_name=model_name,
                device=device,
            )
            logger.info("CodeEmbedder loaded: %s on %s", model_name, device)
            return embedder
        except ImportError:
            logger.info(
                "transformers not installed -- using random embeddings"
            )
        except Exception as exc:
            logger.warning(
                "Failed to create CodeEmbedder: %s -- using random "
                "embeddings",
                exc,
            )
        return None

    # ------------------------------------------------------------------
    # Validation API
    # ------------------------------------------------------------------

    async def validate(self, finding: Finding) -> Finding:
        """Run graph-augmented validation on a single finding.

        This is the method called by
        :meth:`PipelineOrchestrator._run_graph_stage` for each
        escalated finding.

        Args:
            finding: The finding to validate.

        Returns:
            The same ``Finding`` instance with its
            ``graph_validation`` attribute populated.
        """
        start = time.perf_counter()

        try:
            gv = await self._validate_single(finding)
        except Exception as exc:
            logger.warning(
                "Graph validation failed for finding %s: %s",
                finding.id,
                exc,
            )
            gv = GraphValidation()

        finding.graph_validation = gv

        elapsed_ms = (time.perf_counter() - start) * 1000
        finding.processing_time_ms += elapsed_ms
        logger.debug(
            "Graph validation for %s completed in %.1f ms "
            "(risk=%.2f, set=%s)",
            finding.id,
            elapsed_ms,
            gv.structural_risk_score,
            gv.conformal_prediction_set,
        )

        return finding

    async def validate_batch(
        self, findings: list[Finding]
    ) -> list[Finding]:
        """Validate a list of findings.

        Currently sequential; could be parallelised for Joern
        invocations in the future.
        """
        results: list[Finding] = []
        total_start = time.perf_counter()

        for finding in findings:
            result = await self.validate(finding)
            results.append(result)

        elapsed = time.perf_counter() - total_start
        self.last_validation_metadata = {
            "avg_slice_reduction_pct": self._avg_slice_reduction(results),
            "gat_status": (
                f"completed ({len(results)} graphs analyzed)"
                if self._available
                else "skipped -- model not trained"
            ),
            "cp_status": (
                f"completed ({len(results)} predictions)"
                if self._conformal is not None and self._conformal.is_calibrated
                else "skipped -- not calibrated"
            ),
            "total_time_ms": elapsed * 1000,
        }

        return results

    # ------------------------------------------------------------------
    # Core validation logic
    # ------------------------------------------------------------------

    async def _validate_single(self, finding: Finding) -> GraphValidation:
        """Perform all graph analysis steps and return a ``GraphValidation``."""

        # 1. Build CPG
        cpg = self._build_cpg(finding)

        # 2. Backward slice
        sliced = self._slice_cpg(cpg, finding)

        # 3. Extract topology features (always, even without GNN)
        topo_features = self._extract_topology_features(sliced, finding)

        # 4. GNN inference (if model available)
        # Use full CPG for GNN (not backward-sliced) — sliced graphs are
        # too small (1-6 nodes) for the model trained on 10-300 node graphs.
        # The data_builder truncates to max_nodes=300 if needed.
        lang = finding.language.value if finding.language else "python"
        gnn_result = self._run_gnn(cpg, language=lang)

        # 5. Conformal prediction (also uses full CPG)
        conformal_set, conformal_coverage = self._run_conformal(
            cpg, language=lang
        )

        # 6. Assemble GraphValidation
        gv = GraphValidation(
            structural_risk_score=gnn_result.get("risk_score", 0.0),
            conformal_prediction_set=conformal_set,
            conformal_coverage=conformal_coverage,
            taint_path_length=topo_features.get("taint_path_length_raw", 0),
            control_flow_complexity=topo_features.get(
                "control_flow_complexity", 0.0
            ),
            data_flow_fan_out=topo_features.get("data_flow_fan_out_raw", 0),
            sanitizer_coverage=topo_features.get("sanitizer_coverage", 0.0),
            interprocedural_depth=topo_features.get(
                "interprocedural_depth_raw", 0
            ),
            attention_weights=gnn_result.get("attention_weights", {}),
        )

        # If no GNN, use topology heuristic for risk score
        if not self._available:
            gv.structural_risk_score = self._heuristic_risk(topo_features)

        return gv

    # ------------------------------------------------------------------
    # Step 1: CPG construction
    # ------------------------------------------------------------------

    def _build_cpg(self, finding: Finding) -> nx.DiGraph:
        """Build or approximate a CPG for the finding's source file."""
        file_path = finding.location.file_path if finding.location else ""
        language = finding.language.value if finding.language else "python"

        # Try Joern first
        if self._builder is not None and file_path and Path(file_path).exists():
            try:
                cpg = self._builder.build_cpg(file_path, language)
                if cpg.number_of_nodes() > 0:
                    return cpg
            except Exception as exc:
                logger.debug(
                    "Joern CPG build failed, using simplified graph: %s",
                    exc,
                )

        # Fallback: simplified line-level graph from the finding
        return self._build_simplified_graph(finding)

    def _build_simplified_graph(self, finding: Finding) -> nx.DiGraph:
        """Build a minimal graph from the finding's location info.

        This creates one node per relevant source line, connected
        sequentially by CFG edges.  It is a poor approximation of a real
        CPG but allows the feature extractors to produce non-trivial
        values.
        """
        graph = nx.DiGraph()
        graph.graph["stub"] = True
        graph.graph["source"] = "simplified"

        start_line = (
            finding.location.start_line if finding.location else 1
        )
        end_line = (
            finding.location.end_line
            if finding.location and finding.location.end_line
            else start_line
        )

        # Ensure at least a few nodes for meaningful features
        if end_line <= start_line:
            end_line = start_line + 5

        code_snippet = (
            finding.location.snippet if finding.location else ""
        ) or finding.sast_message or ""

        lines = code_snippet.split("\n") if code_snippet else []

        for i, line_num in enumerate(range(start_line, end_line + 1)):
            code = lines[i] if i < len(lines) else f"<line {line_num}>"
            node_type = "CALL" if i == 0 else "IDENTIFIER"
            graph.add_node(
                i,
                id=i,
                type=node_type,
                code=code.strip(),
                lineNumber=line_num,
                columnNumber=1,
            )

        # Sequential CFG edges
        node_ids = list(graph.nodes())
        for j in range(len(node_ids) - 1):
            graph.add_edge(node_ids[j], node_ids[j + 1], type="CFG")

        # Add a DDG edge from first to last for data flow
        if len(node_ids) >= 2:
            graph.add_edge(
                node_ids[0], node_ids[-1], type="DDG"
            )

        return graph

    # ------------------------------------------------------------------
    # Step 2: Backward slicing
    # ------------------------------------------------------------------

    def _slice_cpg(self, cpg: nx.DiGraph, finding: Finding) -> nx.DiGraph:
        """Backward-slice the CPG for the given finding."""
        if self._slicer is None:
            return cpg

        try:
            sliced = self._slicer.slice_for_finding(cpg, finding)
            return sliced
        except Exception as exc:
            logger.debug("Slicing failed, using full CPG: %s", exc)
            return cpg

    # ------------------------------------------------------------------
    # Step 3: Topology features
    # ------------------------------------------------------------------

    def _extract_topology_features(
        self, cpg: nx.DiGraph, finding: Finding
    ) -> dict[str, Any]:
        """Extract graph-level topology features via GraphFeatureExtractor."""
        if self._feature_extractor is None:
            return {}

        try:
            feats = self._feature_extractor.extract_features(cpg, finding)
            # Derive raw (un-normalised) counts for GraphValidation fields
            num_nodes = cpg.number_of_nodes()
            num_edges = cpg.number_of_edges()

            # Approximate raw values from normalised features
            taint_len = int(feats.get("taint_path_length", 0.0) * 20)
            fan_out = int(feats.get("data_flow_fan_out", 0.0) * 15)
            inter_depth = int(
                feats.get("interprocedural_depth", 0.0) * 8
            )

            return {
                **feats,
                "taint_path_length_raw": taint_len,
                "data_flow_fan_out_raw": fan_out,
                "interprocedural_depth_raw": inter_depth,
                "num_nodes": num_nodes,
                "num_edges": num_edges,
            }
        except Exception as exc:
            logger.debug("Topology feature extraction failed: %s", exc)
            return {}

    # ------------------------------------------------------------------
    # Step 4: GNN inference
    # ------------------------------------------------------------------

    def _run_gnn(
        self, cpg: nx.DiGraph, language: str = "python"
    ) -> dict[str, Any]:
        """Run MiniGINv3 forward pass on the CPG.

        Returns a dict with ``risk_score`` (float in [0,1]) and
        ``attention_weights`` (dict mapping edge descriptions to
        float weights, empty if unavailable).
        """
        if self._model is None or self._data_builder is None:
            return {"risk_score": 0.0, "attention_weights": {}}

        try:
            torch, F = _ensure_torch()

            # Build PyG Data
            data = self._data_builder.build(cpg, language=language)

            # Ensure batch tensor exists
            batch = torch.zeros(
                data.x.size(0), dtype=torch.long
            )

            # Forward pass (eval mode, no grad)
            pred_class, pred_prob, confidence = self._model.predict(
                data.x, data.edge_index, batch
            )

            # Risk score: probability of class 1 (vulnerable)
            with torch.no_grad():
                logits, conf = self._model(
                    data.x, data.edge_index, batch
                )
                probs = F.softmax(logits, dim=-1)
                vuln_prob = float(probs[0, 1].item())

            # Extract attention weights summary
            attn = self._model.get_attention_weights()
            attn_summary: dict[str, float] = {}
            for layer_name, weights in attn.items():
                if weights is not None:
                    attn_summary[f"{layer_name}_mean"] = float(
                        weights.mean().item()
                    )
                    attn_summary[f"{layer_name}_max"] = float(
                        weights.max().item()
                    )

            return {
                "risk_score": vuln_prob,
                "predicted_class": pred_class,
                "confidence": confidence,
                "attention_weights": attn_summary,
            }

        except Exception as exc:
            logger.warning("GNN inference failed: %s", exc)
            return {"risk_score": 0.0, "attention_weights": {}}

    # ------------------------------------------------------------------
    # Step 5: Conformal prediction
    # ------------------------------------------------------------------

    def _run_conformal(
        self, cpg: nx.DiGraph, language: str = "python"
    ) -> tuple[list[str], float]:
        """Produce a conformal prediction set for the graph.

        Returns ``(prediction_set, coverage)`` where prediction_set is
        e.g. ``["safe"]``, ``["vulnerable"]``, or
        ``["safe", "vulnerable"]`` for ambiguous cases.
        """
        if (
            self._model is None
            or self._conformal is None
            or not self._conformal.is_calibrated
            or self._data_builder is None
        ):
            # No conformal prediction available -- return empty set
            # so that ``is_ambiguous`` is False and the finding passes
            # through without conformal gating.
            return [], 0.0

        try:
            torch, _ = _ensure_torch()
            data = self._data_builder.build(cpg, language=language)
            batch = torch.zeros(data.x.size(0), dtype=torch.long)

            pred_set, coverage = self._conformal.predict(
                self._model, data.x, data.edge_index, batch
            )
            return pred_set, coverage

        except Exception as exc:
            logger.warning("Conformal prediction failed: %s", exc)
            return [], 0.0

    # ------------------------------------------------------------------
    # Heuristic fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _heuristic_risk(features: dict[str, Any]) -> float:
        """Compute a simple heuristic risk score from topology features.

        Used when the GNN model is not available.  The weights are
        intentionally conservative (centre around 0.5).
        """
        if not features:
            return 0.5

        score = (
            0.25 * features.get("taint_path_length", 0.5)
            + 0.20 * features.get("control_flow_complexity", 0.5)
            + 0.15 * features.get("data_flow_fan_out", 0.5)
            + 0.25 * (1.0 - features.get("sanitizer_coverage", 0.0))
            + 0.15 * features.get("interprocedural_depth", 0.5)
        )

        return max(0.0, min(1.0, score))

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _avg_slice_reduction(findings: list[Finding]) -> float:
        """Compute average slice reduction across validated findings."""
        reductions: list[float] = []
        for f in findings:
            gv = f.graph_validation
            if gv is not None:
                # Approximate from sanitizer_coverage as a proxy
                reductions.append(gv.sanitizer_coverage * 100)

        if not reductions:
            return 0.0
        return sum(reductions) / len(reductions)
