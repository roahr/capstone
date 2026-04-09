"""
Conformal prediction for vulnerability detection with coverage guarantees.

Implements the Adaptive Prediction Sets (APS) algorithm to produce
prediction sets with finite-sample coverage guarantees.  This is the
first application of conformal prediction to static-analysis
vulnerability detection, enabling principled escalation decisions in the
SEC-C cascade:

* A singleton prediction set (``["safe"]`` or ``["vulnerable"]``) means
  the model is confident enough to resolve the finding at the graph
  stage.
* A two-element set (``["safe", "vulnerable"]``) signals genuine
  ambiguity: the finding should be escalated to the LLM dual-agent
  stage for deeper reasoning.

Mathematical background
-----------------------

**Calibration phase** (on a held-out calibration set):

1. For each sample *i* with true label *y_i*, compute the softmax
   vector *pi_i* from the model.
2. Sort the classes in descending order of *pi_i*.
3. Compute the cumulative sum of the sorted probabilities.
4. The *nonconformity score* s_i is the cumulative sum at the position
   where the true label *y_i* first appears (inclusive).
5. Compute the *quantile threshold* q_hat as the
   ceil((n+1)(1-alpha)) / n quantile of {s_1, ..., s_n}.

**Inference phase**:

1. Compute softmax vector *pi* for the new sample.
2. Sort classes in descending order of *pi*.
3. Include classes greedily until the cumulative sum >= q_hat.
4. The resulting set has **guaranteed marginal coverage**:
   P(y in C(X)) >= 1 - alpha.
"""

from __future__ import annotations

import logging
import math
from typing import Any

import numpy as np
import torch
import torch.nn.functional as F
from torch import Tensor

logger = logging.getLogger(__name__)

# Human-readable class labels matching the GNN output indices
CLASS_LABELS: list[str] = ["safe", "vulnerable"]


class ConformalPredictor:
    """
    Adaptive Prediction Sets (APS) for binary vulnerability classification.

    Provides distribution-free coverage guarantees for the Mini-GAT
    model's predictions, enabling principled uncertainty quantification
    without distributional assumptions.

    Args:
        alpha: Mis-coverage rate.  The prediction sets are guaranteed to
            contain the true label with probability at least ``1 - alpha``.
            Default ``0.1`` (90 % coverage).

    Usage::

        cp = ConformalPredictor(alpha=0.1)
        cp.calibrate(model, calibration_loader)
        pred_set, coverage = cp.predict(model, x, edge_index, batch)

        if len(pred_set) > 1:
            # Ambiguous -- escalate to LLM
            ...
    """

    def __init__(self, alpha: float = 0.1) -> None:
        if not 0.0 < alpha < 1.0:
            raise ValueError(f"alpha must be in (0, 1), got {alpha}")

        self.alpha: float = alpha
        self._quantile_threshold: float | None = None
        self._calibration_scores: np.ndarray | None = None
        self._is_calibrated: bool = False
        self._calibration_size: int = 0
        self._temperature: float = 1.0  # ConfTS temperature (1.0 = no scaling)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def quantile_threshold(self) -> float:
        """The APS quantile threshold computed during calibration."""
        if self._quantile_threshold is None:
            raise RuntimeError(
                "ConformalPredictor has not been calibrated yet. "
                "Call calibrate() first."
            )
        return self._quantile_threshold

    @property
    def is_calibrated(self) -> bool:
        """Whether calibrate() has been called successfully."""
        return self._is_calibrated

    @torch.no_grad()
    def calibrate(
        self,
        model: torch.nn.Module,
        calibration_loader: Any,
    ) -> float:
        """
        Compute the APS quantile threshold on a calibration set.

        The calibration set must be disjoint from both the training and
        test sets to preserve the coverage guarantee.

        Args:
            model: A trained :class:`MiniGAT` (or compatible model)
                that returns ``(logits, confidence)`` from its forward
                method.
            calibration_loader: A ``torch_geometric.loader.DataLoader``
                yielding ``Data`` objects with ``.y`` labels.

        Returns:
            The computed quantile threshold (also stored internally).

        Raises:
            ValueError: If the calibration set is empty.
        """
        model.eval()
        device = next(model.parameters()).device

        all_softmax: list[np.ndarray] = []
        all_labels: list[int] = []

        for data in calibration_loader:
            data = data.to(device)
            logits, _ = model(data.x, data.edge_index, data.batch)
            # Apply ConfTS temperature scaling before softmax
            probs = F.softmax(logits / self._temperature, dim=-1)

            all_softmax.append(probs.cpu().numpy())
            all_labels.extend(data.y.cpu().tolist())

        if not all_labels:
            raise ValueError(
                "Calibration set is empty. Cannot compute threshold."
            )

        softmax_matrix = np.concatenate(all_softmax, axis=0)  # (n, C)
        labels_array = np.array(all_labels, dtype=np.int64)   # (n,)

        # Compute nonconformity scores using APS
        scores = self._compute_nonconformity(softmax_matrix, labels_array)

        # Compute the corrected quantile level
        n = len(scores)
        quantile_level = min(
            math.ceil((n + 1) * (1.0 - self.alpha)) / n, 1.0
        )
        self._quantile_threshold = min(
            float(np.quantile(scores, quantile_level, method="higher")),
            1.0,  # Clamp to 1.0 (float precision can produce 1.0+eps)
        )
        self._calibration_scores = scores
        self._calibration_size = n
        self._is_calibrated = True

        logger.info(
            "Calibration complete: n=%d, alpha=%.2f, "
            "quantile_level=%.4f, threshold=%.4f",
            n, self.alpha, quantile_level, self._quantile_threshold,
        )

        return self._quantile_threshold

    @torch.no_grad()
    def predict(
        self,
        model: torch.nn.Module,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> tuple[list[str], float]:
        """
        Produce a conformal prediction set for a single graph.

        Args:
            model: The trained model (same one used for calibration).
            x: Node features ``(N, D)``.
            edge_index: COO edge index ``(2, E)``.
            batch: Batch assignment vector ``(N,)``.

        Returns:
            A tuple ``(prediction_set, coverage)`` where:

            * **prediction_set** is a list of class labels that form the
              conformal prediction set.  Possible values:
              ``["safe"]``, ``["vulnerable"]``, or
              ``["safe", "vulnerable"]``.
            * **coverage** is the nominal coverage level ``1 - alpha``.

        Raises:
            RuntimeError: If the predictor has not been calibrated.
        """
        if not self._is_calibrated:
            raise RuntimeError(
                "ConformalPredictor has not been calibrated. "
                "Call calibrate() first."
            )

        model.eval()
        device = next(model.parameters()).device
        x = x.to(device)
        edge_index = edge_index.to(device)
        batch = batch.to(device)

        logits, _ = model(x, edge_index, batch)
        # Apply ConfTS temperature scaling before softmax
        probs = F.softmax(logits / self._temperature, dim=-1)  # (1, C)
        probs_np = probs.cpu().numpy().squeeze(0)  # (C,)

        prediction_set = self._build_prediction_set(probs_np)
        coverage = 1.0 - self.alpha

        return prediction_set, coverage

    @torch.no_grad()
    def predict_batch(
        self,
        model: torch.nn.Module,
        loader: Any,
    ) -> list[tuple[list[str], float]]:
        """
        Produce conformal prediction sets for all graphs in a loader.

        Args:
            model: The trained model.
            loader: A ``DataLoader`` of graph ``Data`` objects.

        Returns:
            A list of ``(prediction_set, coverage)`` tuples, one per
            graph in the loader.
        """
        if not self._is_calibrated:
            raise RuntimeError(
                "ConformalPredictor has not been calibrated. "
                "Call calibrate() first."
            )

        model.eval()
        device = next(model.parameters()).device
        coverage = 1.0 - self.alpha
        results: list[tuple[list[str], float]] = []

        for data in loader:
            data = data.to(device)
            logits, _ = model(data.x, data.edge_index, data.batch)
            probs = F.softmax(logits, dim=-1).cpu().numpy()

            for i in range(probs.shape[0]):
                pred_set = self._build_prediction_set(probs[i])
                results.append((pred_set, coverage))

        return results

    def get_calibration_stats(self) -> dict[str, Any]:
        """
        Return diagnostic statistics about the calibration.

        Useful for debugging and reporting.
        """
        if not self._is_calibrated or self._calibration_scores is None:
            return {"is_calibrated": False}

        scores = self._calibration_scores
        return {
            "is_calibrated": True,
            "alpha": self.alpha,
            "coverage_target": 1.0 - self.alpha,
            "calibration_size": self._calibration_size,
            "quantile_threshold": self._quantile_threshold,
            "score_mean": float(np.mean(scores)),
            "score_std": float(np.std(scores)),
            "score_min": float(np.min(scores)),
            "score_max": float(np.max(scores)),
            "score_median": float(np.median(scores)),
        }

    # ------------------------------------------------------------------
    # Core APS implementation
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_nonconformity(
        softmax_probs: np.ndarray,
        true_labels: np.ndarray,
    ) -> np.ndarray:
        """
        Compute APS nonconformity scores for each calibration sample.

        For each sample:

        1. Sort classes by descending softmax probability.
        2. Compute the cumulative sum of these sorted probabilities.
        3. Find the position of the true label in the sorted order.
        4. The nonconformity score is the cumulative sum at that
           position (inclusive).

        A higher score means the model was less certain about the true
        class: the true label appeared further down the sorted list and
        more probability mass had to be accumulated to reach it.

        Args:
            softmax_probs: Array of shape ``(n, C)`` with softmax
                probabilities.
            true_labels: Array of shape ``(n,)`` with integer class
                indices.

        Returns:
            1-D array of shape ``(n,)`` with nonconformity scores in
            [0, 1].
        """
        n, num_classes = softmax_probs.shape
        scores = np.zeros(n, dtype=np.float64)

        for i in range(n):
            probs = softmax_probs[i]  # (C,)
            true_label = true_labels[i]

            # Sort classes by descending probability
            sorted_indices = np.argsort(-probs)
            sorted_probs = probs[sorted_indices]

            # Cumulative sum of sorted probabilities
            cumsum = np.cumsum(sorted_probs)

            # Find the rank (0-indexed position) of the true label
            rank = int(np.where(sorted_indices == true_label)[0][0])

            # Nonconformity score = cumulative sum at the true label's
            # position (inclusive)
            scores[i] = cumsum[rank]

        return scores

    def _build_prediction_set(self, probs: np.ndarray) -> list[str]:
        """
        Construct the conformal prediction set for a single sample.

        Greedily includes classes in descending probability order until
        the cumulative probability meets or exceeds the quantile
        threshold.

        Args:
            probs: 1-D softmax probability vector of shape ``(C,)``.

        Returns:
            A list of class label strings forming the prediction set.
        """
        assert self._quantile_threshold is not None

        sorted_indices = np.argsort(-probs)
        sorted_probs = probs[sorted_indices]
        cumsum = np.cumsum(sorted_probs)

        # Include classes until cumulative sum >= threshold
        prediction_set: list[str] = []
        for j, idx in enumerate(sorted_indices):
            prediction_set.append(CLASS_LABELS[int(idx)])
            if cumsum[j] >= self._quantile_threshold:
                break

        # Guarantee at least one class in the set
        if not prediction_set:
            prediction_set.append(CLASS_LABELS[int(sorted_indices[0])])

        return prediction_set
