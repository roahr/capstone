"""
Training pipeline for the Mini-GAT vulnerability detection model.

Handles the full training lifecycle: training loop with early stopping,
evaluation with standard classification metrics, model checkpointing,
and weighted loss computation for class-imbalanced vulnerability datasets.
"""

from __future__ import annotations

import copy
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch.optim import Adam
from torch_geometric.loader import DataLoader  # type: ignore[import-untyped]

from src.graph.gnn.mini_gat import MiniGAT

logger = logging.getLogger(__name__)

# Default path for persisting the best model checkpoint
_DEFAULT_MODEL_PATH = Path("data/models/mini_gat.pt")


@dataclass
class TrainingMetrics:
    """Container for metrics recorded during a single training epoch."""

    epoch: int = 0
    train_loss: float = 0.0
    val_loss: float = 0.0
    val_accuracy: float = 0.0
    val_precision: float = 0.0
    val_recall: float = 0.0
    val_f1: float = 0.0
    lr: float = 0.0
    elapsed_sec: float = 0.0


@dataclass
class TrainingHistory:
    """Accumulated metrics across all epochs."""

    epochs: list[TrainingMetrics] = field(default_factory=list)
    best_epoch: int = 0
    best_val_loss: float = float("inf")

    def append(self, m: TrainingMetrics) -> None:
        self.epochs.append(m)
        if m.val_loss < self.best_val_loss:
            self.best_val_loss = m.val_loss
            self.best_epoch = m.epoch

    @property
    def latest(self) -> TrainingMetrics | None:
        return self.epochs[-1] if self.epochs else None


class GATTrainer:
    """
    End-to-end trainer for :class:`MiniGAT`.

    Features:

    * **Weighted cross-entropy** for handling class imbalance between
      safe and vulnerable samples.
    * **Confidence calibration loss** that penalises over- or
      under-confidence by comparing the learned confidence head against
      the actual prediction correctness.
    * **Early stopping** on validation loss with configurable patience.
    * **Model checkpointing** -- the best model (by validation loss) is
      saved to disk automatically.

    Usage::

        model = MiniGAT()
        trainer = GATTrainer(model, device="cuda")
        history = trainer.train(train_loader, val_loader, epochs=50)
        results = trainer.evaluate(test_loader)

    Args:
        model: A :class:`MiniGAT` instance.
        device: PyTorch device string.
        model_save_path: Where to persist the best checkpoint.
        class_weights: Optional manual class weights ``[w_safe, w_vuln]``.
            When ``None``, weights are computed automatically from the
            training set.
    """

    def __init__(
        self,
        model: MiniGAT,
        device: str = "cpu",
        model_save_path: str | Path = _DEFAULT_MODEL_PATH,
        class_weights: list[float] | None = None,
    ) -> None:
        self._device = torch.device(device)
        self._model = model.to(self._device)
        self._save_path = Path(model_save_path)
        self._class_weights = class_weights

        # Will be initialised in train()
        self._optimizer: Adam | None = None
        self._criterion: nn.CrossEntropyLoss | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def train(
        self,
        train_loader: DataLoader,
        val_loader: DataLoader,
        epochs: int = 50,
        lr: float = 0.001,
        weight_decay: float = 1e-4,
        patience: int = 10,
        confidence_loss_weight: float = 0.2,
    ) -> TrainingHistory:
        """
        Train the model with early stopping and checkpointing.

        Args:
            train_loader: DataLoader yielding ``torch_geometric.data.Data``
                objects for training.
            val_loader: DataLoader for validation.
            epochs: Maximum number of training epochs.
            lr: Initial learning rate for Adam.
            weight_decay: L2 regularisation coefficient.
            patience: Number of epochs without improvement before stopping.
            confidence_loss_weight: Scalar weight for the confidence
                calibration loss relative to the classification loss.

        Returns:
            A :class:`TrainingHistory` recording per-epoch metrics.
        """
        # --- Setup ------------------------------------------------------
        self._optimizer = Adam(
            self._model.parameters(), lr=lr, weight_decay=weight_decay
        )

        # Compute class weights if not provided
        weights_tensor = self._compute_class_weights(train_loader)
        self._criterion = nn.CrossEntropyLoss(weight=weights_tensor)

        history = TrainingHistory()
        best_state: dict[str, Any] | None = None
        epochs_without_improvement = 0

        logger.info(
            "Starting training: epochs=%d, lr=%s, patience=%d, "
            "class_weights=%s, device=%s",
            epochs, lr, patience, weights_tensor.tolist(), self._device,
        )

        for epoch in range(1, epochs + 1):
            t0 = time.perf_counter()

            train_loss = self._train_one_epoch(
                train_loader, confidence_loss_weight
            )
            val_metrics = self._validate(val_loader, confidence_loss_weight)

            elapsed = time.perf_counter() - t0

            metrics = TrainingMetrics(
                epoch=epoch,
                train_loss=train_loss,
                val_loss=val_metrics["loss"],
                val_accuracy=val_metrics["accuracy"],
                val_precision=val_metrics["precision"],
                val_recall=val_metrics["recall"],
                val_f1=val_metrics["f1"],
                lr=lr,
                elapsed_sec=elapsed,
            )
            history.append(metrics)

            logger.info(
                "Epoch %d/%d  train_loss=%.4f  val_loss=%.4f  "
                "acc=%.3f  P=%.3f  R=%.3f  F1=%.3f  (%.1fs)",
                epoch, epochs,
                metrics.train_loss, metrics.val_loss,
                metrics.val_accuracy, metrics.val_precision,
                metrics.val_recall, metrics.val_f1,
                elapsed,
            )

            # Early stopping bookkeeping
            if metrics.val_loss < history.best_val_loss:
                history.best_val_loss = metrics.val_loss
                history.best_epoch = epoch
                best_state = copy.deepcopy(self._model.state_dict())
                epochs_without_improvement = 0
            else:
                epochs_without_improvement += 1

            if epochs_without_improvement >= patience:
                logger.info(
                    "Early stopping triggered at epoch %d "
                    "(best epoch: %d, best val_loss: %.4f)",
                    epoch, history.best_epoch, history.best_val_loss,
                )
                break

        # Restore and persist the best model
        if best_state is not None:
            self._model.load_state_dict(best_state)
            self._save_checkpoint(best_state, history)

        return history

    @torch.no_grad()
    def evaluate(self, test_loader: DataLoader) -> dict[str, float]:
        """
        Evaluate the model on a held-out test set.

        Args:
            test_loader: DataLoader for the test split.

        Returns:
            A dict with keys ``accuracy``, ``precision``, ``recall``,
            ``f1``, ``loss``, and ``total_samples``.
        """
        self._model.eval()

        all_preds: list[int] = []
        all_labels: list[int] = []
        total_loss = 0.0
        num_batches = 0

        criterion = nn.CrossEntropyLoss()

        for data in test_loader:
            data = data.to(self._device)
            logits, _ = self._model(data.x, data.edge_index, data.batch)
            labels = data.y

            total_loss += criterion(logits, labels).item()
            num_batches += 1

            preds = logits.argmax(dim=-1)
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

        return self._compute_metrics(all_preds, all_labels, total_loss, num_batches)

    def load_checkpoint(self, path: str | Path | None = None) -> None:
        """Load model weights from a saved checkpoint."""
        load_path = Path(path) if path else self._save_path
        if not load_path.exists():
            raise FileNotFoundError(f"Checkpoint not found: {load_path}")

        checkpoint = torch.load(load_path, map_location=self._device, weights_only=False)
        self._model.load_state_dict(checkpoint["model_state_dict"])
        logger.info("Loaded checkpoint from %s (epoch %d)", load_path, checkpoint.get("epoch", -1))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _train_one_epoch(
        self,
        loader: DataLoader,
        confidence_loss_weight: float,
    ) -> float:
        """Run one training epoch; return mean loss."""
        self._model.train()
        assert self._optimizer is not None
        assert self._criterion is not None

        total_loss = 0.0
        num_batches = 0

        for data in loader:
            data = data.to(self._device)
            self._optimizer.zero_grad()

            logits, confidence = self._model(
                data.x, data.edge_index, data.batch
            )
            labels = data.y

            # Classification loss (weighted cross-entropy)
            cls_loss = self._criterion(logits, labels)

            # Confidence calibration loss:
            # The confidence head should output high confidence when the
            # model predicts correctly, and low confidence otherwise.
            with torch.no_grad():
                preds = logits.argmax(dim=-1)
                correct = (preds == labels).float().unsqueeze(-1)

            conf_loss = F.binary_cross_entropy(confidence, correct)

            loss = cls_loss + confidence_loss_weight * conf_loss

            loss.backward()
            # Gradient clipping for training stability
            nn.utils.clip_grad_norm_(self._model.parameters(), max_norm=1.0)
            self._optimizer.step()

            total_loss += loss.item()
            num_batches += 1

        return total_loss / max(num_batches, 1)

    @torch.no_grad()
    def _validate(
        self,
        loader: DataLoader,
        confidence_loss_weight: float,
    ) -> dict[str, float]:
        """Evaluate on the validation set, returning a metrics dict."""
        self._model.eval()
        assert self._criterion is not None

        all_preds: list[int] = []
        all_labels: list[int] = []
        total_loss = 0.0
        num_batches = 0

        for data in loader:
            data = data.to(self._device)
            logits, confidence = self._model(
                data.x, data.edge_index, data.batch
            )
            labels = data.y

            cls_loss = self._criterion(logits, labels)

            preds = logits.argmax(dim=-1)
            correct = (preds == labels).float().unsqueeze(-1)
            conf_loss = F.binary_cross_entropy(confidence, correct)

            loss = cls_loss + confidence_loss_weight * conf_loss

            total_loss += loss.item()
            num_batches += 1

            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

        return self._compute_metrics(all_preds, all_labels, total_loss, num_batches)

    def _compute_class_weights(self, loader: DataLoader) -> Tensor:
        """
        Derive inverse-frequency class weights from the training set.

        If the user provided explicit class weights at construction time,
        those are used instead.
        """
        if self._class_weights is not None:
            return torch.tensor(self._class_weights, dtype=torch.float32).to(
                self._device
            )

        label_counts: dict[int, int] = {}
        for data in loader:
            for label in data.y.tolist():
                label_counts[label] = label_counts.get(label, 0) + 1

        total = sum(label_counts.values())
        num_classes = max(label_counts.keys()) + 1 if label_counts else 2

        weights: list[float] = []
        for c in range(num_classes):
            count = label_counts.get(c, 1)
            weights.append(total / (num_classes * count))

        logger.info(
            "Auto class weights from %d samples: %s", total, weights
        )
        return torch.tensor(weights, dtype=torch.float32).to(self._device)

    @staticmethod
    def _compute_metrics(
        preds: list[int],
        labels: list[int],
        total_loss: float,
        num_batches: int,
    ) -> dict[str, float]:
        """Compute precision, recall, F1, accuracy from flat lists."""
        n = len(preds)
        if n == 0:
            return {
                "accuracy": 0.0,
                "precision": 0.0,
                "recall": 0.0,
                "f1": 0.0,
                "loss": 0.0,
                "total_samples": 0.0,
            }

        # Binary metrics with positive class = 1 (vulnerable)
        tp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 1)
        fp = sum(1 for p, l in zip(preds, labels) if p == 1 and l == 0)
        fn = sum(1 for p, l in zip(preds, labels) if p == 0 and l == 1)
        correct = sum(1 for p, l in zip(preds, labels) if p == l)

        accuracy = correct / n
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )

        return {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "loss": total_loss / max(num_batches, 1),
            "total_samples": float(n),
        }

    def _save_checkpoint(
        self,
        state_dict: dict[str, Any],
        history: TrainingHistory,
    ) -> None:
        """Persist the best model checkpoint to disk."""
        self._save_path.parent.mkdir(parents=True, exist_ok=True)
        checkpoint = {
            "model_state_dict": state_dict,
            "epoch": history.best_epoch,
            "val_loss": history.best_val_loss,
            "model_config": {
                "input_dim": self._model.input_dim,
                "hidden_dim": self._model.hidden_dim,
                "output_dim": self._model.output_dim,
            },
        }
        torch.save(checkpoint, self._save_path)
        logger.info(
            "Saved best model (epoch %d, val_loss=%.4f) to %s",
            history.best_epoch, history.best_val_loss, self._save_path,
        )
