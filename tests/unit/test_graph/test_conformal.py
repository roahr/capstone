"""
Tests for conformal prediction (src.graph.uncertainty.conformal).

Verifies ConformalPredictor initialization, nonconformity score
computation, prediction set construction, calibration, and the
coverage guarantee. All tests run on CPU with synthetic data.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import numpy as np
import pytest
import torch
import torch.nn as nn
import torch.nn.functional as F

from src.graph.uncertainty.conformal import CLASS_LABELS, ConformalPredictor


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class MockGATModel(nn.Module):
    """
    A deterministic mock model that returns fixed logits for each sample.

    If ``fixed_logits`` is provided, every forward call returns those
    logits.  Otherwise, a learned linear layer is used (useful for
    generating varied but reproducible outputs from different inputs).
    """

    def __init__(self, fixed_logits: torch.Tensor | None = None) -> None:
        super().__init__()
        self._fixed_logits = fixed_logits
        # A dummy parameter so `next(model.parameters())` works.
        self._dummy = nn.Parameter(torch.zeros(1))

    def forward(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
    ) -> tuple[torch.Tensor, torch.Tensor]:
        if self._fixed_logits is not None:
            logits = self._fixed_logits.unsqueeze(0)
        else:
            # Simple aggregation: mean of node features, then project to 2 classes
            # batch size = number of unique graphs
            num_graphs = int(batch.max().item()) + 1 if batch.numel() > 0 else 1
            logits_list = []
            for g in range(num_graphs):
                mask = batch == g
                node_feats = x[mask]
                mean_feat = node_feats.mean(dim=0)
                # Use first two features as logits
                logit = mean_feat[:2] if mean_feat.shape[0] >= 2 else torch.zeros(2)
                logits_list.append(logit)
            logits = torch.stack(logits_list)

        confidence = torch.sigmoid(logits[:, 0:1])
        return logits, confidence


class _FakeData:
    """Mimics a torch_geometric Data object for calibration."""

    def __init__(
        self,
        x: torch.Tensor,
        edge_index: torch.Tensor,
        batch: torch.Tensor,
        y: torch.Tensor,
    ):
        self.x = x
        self.edge_index = edge_index
        self.batch = batch
        self.y = y

    def to(self, device: torch.device | str) -> "_FakeData":
        return _FakeData(
            x=self.x.to(device),
            edge_index=self.edge_index.to(device),
            batch=self.batch.to(device),
            y=self.y.to(device),
        )


def _make_calibration_loader(
    n_samples: int,
    model: MockGATModel,
    rng: np.random.Generator | None = None,
) -> list[_FakeData]:
    """
    Build a synthetic calibration loader of ``n_samples`` single-graph
    batches.  Each graph has 4 nodes and 4 edges.  Labels are sampled
    uniformly at random.
    """
    if rng is None:
        rng = np.random.default_rng(42)

    loader: list[_FakeData] = []
    for _ in range(n_samples):
        x = torch.randn(4, 8)
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 0]], dtype=torch.long)
        batch = torch.zeros(4, dtype=torch.long)
        y = torch.tensor([int(rng.integers(0, 2))], dtype=torch.long)
        loader.append(_FakeData(x=x, edge_index=edge_index, batch=batch, y=y))

    return loader


# ── Initialization ───────────────────────────────────────────────────────────

class TestConformalPredictorInit:
    def test_default_alpha(self):
        cp = ConformalPredictor()
        assert cp.alpha == pytest.approx(0.1)

    @pytest.mark.parametrize("alpha", [0.01, 0.05, 0.1, 0.2, 0.5, 0.99])
    def test_custom_alpha(self, alpha: float):
        cp = ConformalPredictor(alpha=alpha)
        assert cp.alpha == pytest.approx(alpha)

    @pytest.mark.parametrize("bad_alpha", [0.0, 1.0, -0.1, 1.5])
    def test_invalid_alpha_raises(self, bad_alpha: float):
        with pytest.raises(ValueError, match="alpha must be in"):
            ConformalPredictor(alpha=bad_alpha)

    def test_not_calibrated_initially(self):
        cp = ConformalPredictor()
        assert cp.is_calibrated is False

    def test_quantile_threshold_raises_before_calibration(self):
        cp = ConformalPredictor()
        with pytest.raises(RuntimeError, match="not been calibrated"):
            _ = cp.quantile_threshold


# ── _compute_nonconformity ───────────────────────────────────────────────────

class TestComputeNonconformity:
    """Test the static APS nonconformity score computation."""

    def test_perfect_prediction(self):
        """Model is 100% sure of the correct class -> score = prob of that class."""
        probs = np.array([[1.0, 0.0]])
        labels = np.array([0])

        scores = ConformalPredictor._compute_nonconformity(probs, labels)

        # True label is class 0, which is the top class.
        # Sorted: [1.0, 0.0], cumsum: [1.0, 1.0].
        # True label at rank 0, score = cumsum[0] = 1.0
        assert scores[0] == pytest.approx(1.0)

    def test_worst_prediction(self):
        """Model assigns all probability to the wrong class -> score = 1.0."""
        probs = np.array([[0.0, 1.0]])
        labels = np.array([0])

        scores = ConformalPredictor._compute_nonconformity(probs, labels)

        # Sorted: [1.0 (class1), 0.0 (class0)], cumsum: [1.0, 1.0].
        # True label = class 0, which is at rank 1.  score = cumsum[1] = 1.0
        assert scores[0] == pytest.approx(1.0)

    def test_balanced_prediction(self):
        """Model is 50/50 -> score should be 0.5 or 1.0 depending on position."""
        probs = np.array([[0.5, 0.5]])
        labels = np.array([0])

        scores = ConformalPredictor._compute_nonconformity(probs, labels)

        # Both classes have prob 0.5. argsort(-probs) picks one first.
        # Either way, score is cumsum at the position of the true label.
        assert 0.5 <= scores[0] <= 1.0

    def test_known_multi_sample(self):
        """Multiple samples with known outcomes."""
        probs = np.array([
            [0.9, 0.1],  # model confident on class 0
            [0.2, 0.8],  # model confident on class 1
            [0.6, 0.4],  # model leans class 0
        ])
        labels = np.array([0, 1, 1])

        scores = ConformalPredictor._compute_nonconformity(probs, labels)

        assert len(scores) == 3

        # Sample 0: true=0, sorted=[0.9(cls0), 0.1(cls1)], cumsum=[0.9, 1.0]
        # true label cls0 is at rank 0 -> score = 0.9
        assert scores[0] == pytest.approx(0.9)

        # Sample 1: true=1, sorted=[0.8(cls1), 0.2(cls0)], cumsum=[0.8, 1.0]
        # true label cls1 is at rank 0 -> score = 0.8
        assert scores[1] == pytest.approx(0.8)

        # Sample 2: true=1, sorted=[0.6(cls0), 0.4(cls1)], cumsum=[0.6, 1.0]
        # true label cls1 is at rank 1 -> score = 1.0
        assert scores[2] == pytest.approx(1.0)

    def test_scores_in_valid_range(self):
        """All scores should be in [0, 1]."""
        rng = np.random.default_rng(123)
        n = 50
        raw = rng.random((n, 2))
        probs = raw / raw.sum(axis=1, keepdims=True)
        labels = rng.integers(0, 2, size=n)

        scores = ConformalPredictor._compute_nonconformity(probs, labels)

        assert np.all(scores >= 0.0)
        assert np.all(scores <= 1.0)


# ── _build_prediction_set ────────────────────────────────────────────────────

class TestBuildPredictionSet:
    """Test prediction set construction with a manually set threshold."""

    @pytest.fixture
    def calibrated_predictor(self) -> ConformalPredictor:
        cp = ConformalPredictor(alpha=0.1)
        # Manually set calibration state
        cp._is_calibrated = True
        return cp

    def test_high_confidence_singleton_safe(self, calibrated_predictor):
        """High probability for class 0 ('safe') -> singleton set ['safe']."""
        calibrated_predictor._quantile_threshold = 0.8
        probs = np.array([0.95, 0.05])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert pred_set == ["safe"]

    def test_high_confidence_singleton_vulnerable(self, calibrated_predictor):
        """High probability for class 1 ('vulnerable') -> singleton set."""
        calibrated_predictor._quantile_threshold = 0.8
        probs = np.array([0.05, 0.95])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert pred_set == ["vulnerable"]

    def test_low_confidence_both_classes(self, calibrated_predictor):
        """When probabilities are balanced and threshold is high -> both classes."""
        calibrated_predictor._quantile_threshold = 0.95
        probs = np.array([0.55, 0.45])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert sorted(pred_set) == ["safe", "vulnerable"]

    def test_exactly_at_threshold(self, calibrated_predictor):
        """Cumsum equals threshold at first class -> singleton."""
        calibrated_predictor._quantile_threshold = 0.7
        probs = np.array([0.7, 0.3])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert pred_set == ["safe"]

    def test_very_low_threshold_singleton(self, calibrated_predictor):
        """Very low threshold -> even moderate confidence yields singleton."""
        calibrated_predictor._quantile_threshold = 0.3
        probs = np.array([0.6, 0.4])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert len(pred_set) == 1

    def test_threshold_one_includes_all(self, calibrated_predictor):
        """Threshold = 1.0 always needs cumsum = 1.0 -> both classes."""
        calibrated_predictor._quantile_threshold = 1.0
        probs = np.array([0.8, 0.2])

        pred_set = calibrated_predictor._build_prediction_set(probs)

        assert sorted(pred_set) == ["safe", "vulnerable"]


# ── Calibration ──────────────────────────────────────────────────────────────

class TestCalibration:
    def test_calibrate_sets_threshold(self):
        cp = ConformalPredictor(alpha=0.1)
        model = MockGATModel()
        loader = _make_calibration_loader(30, model)

        threshold = cp.calibrate(model, loader)

        assert cp.is_calibrated is True
        assert cp.quantile_threshold == pytest.approx(threshold)
        assert 0.0 < threshold <= 1.0

    def test_calibrate_empty_loader_raises(self):
        cp = ConformalPredictor(alpha=0.1)
        model = MockGATModel()

        with pytest.raises(ValueError, match="empty"):
            cp.calibrate(model, [])

    def test_calibration_stats(self):
        cp = ConformalPredictor(alpha=0.1)
        model = MockGATModel()
        loader = _make_calibration_loader(50, model)
        cp.calibrate(model, loader)

        stats = cp.get_calibration_stats()

        assert stats["is_calibrated"] is True
        assert stats["alpha"] == pytest.approx(0.1)
        assert stats["coverage_target"] == pytest.approx(0.9)
        assert stats["calibration_size"] == 50
        assert stats["quantile_threshold"] is not None

    def test_uncalibrated_stats(self):
        cp = ConformalPredictor()
        stats = cp.get_calibration_stats()
        assert stats["is_calibrated"] is False

    @pytest.mark.parametrize("alpha", [0.05, 0.1, 0.2, 0.3])
    def test_different_alpha_calibrations(self, alpha: float):
        cp = ConformalPredictor(alpha=alpha)
        model = MockGATModel()
        loader = _make_calibration_loader(40, model)

        cp.calibrate(model, loader)

        assert cp.is_calibrated is True
        assert cp.alpha == pytest.approx(alpha)


# ── Coverage guarantee ───────────────────────────────────────────────────────

class TestCoverageGuarantee:
    """
    The fundamental property of conformal prediction:
    empirical coverage >= 1 - alpha.

    We test this by calibrating on one set and evaluating on a
    held-out test set.  With finite samples the guarantee is
    marginal, so we allow a small tolerance.
    """

    @pytest.mark.parametrize("alpha", [0.1, 0.2])
    def test_coverage_holds(self, alpha: float):
        rng = np.random.default_rng(7)
        model = MockGATModel()

        # Calibration set
        cal_loader = _make_calibration_loader(200, model, rng)

        cp = ConformalPredictor(alpha=alpha)
        cp.calibrate(model, cal_loader)

        # Test set
        test_loader = _make_calibration_loader(100, model, rng)

        covered = 0
        total = 0

        for data in test_loader:
            pred_set, coverage_nominal = cp.predict(
                model, data.x, data.edge_index, data.batch
            )
            true_label = data.y.item()
            true_label_str = CLASS_LABELS[true_label]

            if true_label_str in pred_set:
                covered += 1
            total += 1

            assert coverage_nominal == pytest.approx(1.0 - alpha)

        empirical_coverage = covered / total

        # Allow a small tolerance for finite-sample effects
        assert empirical_coverage >= (1.0 - alpha) - 0.15, (
            f"Coverage {empirical_coverage:.2f} < {1.0 - alpha - 0.15:.2f} "
            f"(alpha={alpha})"
        )


# ── Prediction sets ──────────────────────────────────────────────────────────

class TestPredictionSets:
    """Test that prediction sets match expected values for known inputs."""

    def test_predict_raises_before_calibration(self):
        cp = ConformalPredictor()
        model = MockGATModel(fixed_logits=torch.tensor([2.0, -2.0]))

        x = torch.randn(4, 8)
        edge_index = torch.tensor([[0, 1, 2, 3], [1, 2, 3, 0]], dtype=torch.long)
        batch = torch.zeros(4, dtype=torch.long)

        with pytest.raises(RuntimeError, match="not been calibrated"):
            cp.predict(model, x, edge_index, batch)

    def test_confident_safe_prediction(self):
        """Model very confident about class 0 (safe) -> singleton ['safe'].

        We manually set a realistic threshold to isolate the prediction
        logic from calibration artifacts caused by using a fixed-logits
        model on random labels.
        """
        cp = ConformalPredictor(alpha=0.1)
        cp._is_calibrated = True
        # Threshold below the top-class probability (0.9999) -> singleton
        cp._quantile_threshold = 0.95

        probs = F.softmax(torch.tensor([[5.0, -5.0]]), dim=-1).numpy().squeeze(0)
        result_set = cp._build_prediction_set(probs)

        assert result_set == ["safe"]

    def test_confident_vulnerable_prediction(self):
        """Model very confident about class 1 (vulnerable) -> singleton ['vulnerable']."""
        cp = ConformalPredictor(alpha=0.1)
        cp._is_calibrated = True
        cp._quantile_threshold = 0.95

        probs = F.softmax(torch.tensor([[-5.0, 5.0]]), dim=-1).numpy().squeeze(0)
        result_set = cp._build_prediction_set(probs)

        assert result_set == ["vulnerable"]

    def test_uncertain_prediction_both_classes(self):
        """Near-equal probabilities with a high threshold -> both classes."""
        cp = ConformalPredictor(alpha=0.1)
        cp._is_calibrated = True
        cp._quantile_threshold = 0.99

        probs = np.array([0.52, 0.48])
        result_set = cp._build_prediction_set(probs)

        assert sorted(result_set) == ["safe", "vulnerable"]

    def test_prediction_set_always_nonempty(self):
        """The prediction set must contain at least one class."""
        cp = ConformalPredictor(alpha=0.1)
        cp._is_calibrated = True
        cp._quantile_threshold = 0.001  # very low threshold

        probs = np.array([0.5, 0.5])
        result_set = cp._build_prediction_set(probs)

        assert len(result_set) >= 1

    def test_prediction_set_labels_are_valid(self):
        """All labels in prediction sets must be from CLASS_LABELS."""
        cp = ConformalPredictor(alpha=0.1)
        cp._is_calibrated = True
        cp._quantile_threshold = 0.8

        for _ in range(20):
            probs = np.random.dirichlet([1.0, 1.0])
            result_set = cp._build_prediction_set(probs)
            for label in result_set:
                assert label in CLASS_LABELS


# ── predict_batch ────────────────────────────────────────────────────────────

class TestPredictBatch:
    def test_batch_prediction_count(self):
        model = MockGATModel()
        cp = ConformalPredictor(alpha=0.1)
        cal_loader = _make_calibration_loader(30, model)
        cp.calibrate(model, cal_loader)

        test_loader = _make_calibration_loader(10, model)
        results = cp.predict_batch(model, test_loader)

        assert len(results) == 10
        for pred_set, coverage in results:
            assert len(pred_set) >= 1
            assert coverage == pytest.approx(0.9)

    def test_batch_raises_before_calibration(self):
        model = MockGATModel()
        cp = ConformalPredictor(alpha=0.1)
        loader = _make_calibration_loader(5, model)

        with pytest.raises(RuntimeError, match="not been calibrated"):
            cp.predict_batch(model, loader)
