"""
MiniGINv3: 3-layer Graph Isomorphism Network for vulnerability detection.

Architecture overview::

    Input: 774-dim  (768 GraphCodeBERT + 6 structural features)
       |
    Linear 774 -> 384 + BatchNorm + ReLU
       |
    GINConv (MLP: 384->768->384) + BN + ReLU + Dropout + Residual  x3
       |
    DualPool: global_mean + global_add -> 768-dim graph embedding
       |
    +-- Head 1 (Classification): Linear 768->384->2
    +-- Head 2 (Confidence):     Linear 768->1, Sigmoid

GIN (Xu et al. 2019, ICLR) uses sum-aggregation which is provably
as expressive as the 1-Weisfeiler-Lehman graph isomorphism test --
the theoretical maximum for message-passing GNNs.

Trained on 21K+ vulnerability samples from BigVul, DiverseVul, Devign,
Juliet, CrossVul, VUDENC, and CVEfixes.
"""

from __future__ import annotations

import logging

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import (  # type: ignore[import-untyped]
    GINConv,
    global_add_pool,
    global_mean_pool,
)

logger = logging.getLogger(__name__)


class MiniGINv3(nn.Module):
    """3-layer Graph Isomorphism Network for binary vulnerability detection.

    Args:
        input_dim: Dimensionality of node features. Default ``774``
            (768 GraphCodeBERT mean-pool + 6 structural features).
        hidden_dim: Internal GIN layer width. Default ``384``.
        num_gin_layers: Number of GINConv layers. Default ``3``.
        dropout: Dropout probability. Default ``0.35``.
        num_classes: Classification targets. Default ``2``.
    """

    def __init__(
        self,
        input_dim: int = 774,
        hidden_dim: int = 384,
        num_gin_layers: int = 3,
        dropout: float = 0.35,
        num_classes: int = 2,
    ) -> None:
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.num_gin_layers = num_gin_layers
        self.dropout_rate = dropout

        H = hidden_dim

        # Input projection
        self.input_proj = nn.Linear(input_dim, H)
        self.bn_in = nn.BatchNorm1d(H)

        # GIN layers with 2-layer MLP each
        self.gins = nn.ModuleList()
        self.bns = nn.ModuleList()
        for _ in range(num_gin_layers):
            mlp = nn.Sequential(
                nn.Linear(H, H * 2),
                nn.BatchNorm1d(H * 2),
                nn.ReLU(),
                nn.Dropout(dropout / 2),
                nn.Linear(H * 2, H),
            )
            self.gins.append(GINConv(mlp, train_eps=True))
            self.bns.append(nn.BatchNorm1d(H))

        self.dropout = nn.Dropout(dropout)

        # Dual pooling: mean + add -> 2H-dim graph embedding
        pool_dim = H * 2

        # Classification head
        self.classifier = nn.Sequential(
            nn.Linear(pool_dim, H),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(H, num_classes),
        )

        # Confidence estimation head
        self.confidence_head = nn.Sequential(
            nn.Linear(pool_dim, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> tuple[Tensor, Tensor]:
        """Forward pass.

        Returns:
            ``(logits, confidence)`` where logits has shape ``(B, 2)``
            and confidence has shape ``(B, 1)``.
        """
        h = F.relu(self.bn_in(self.input_proj(x)))

        # GIN layers with residual connections
        prev = h
        for gin, bn in zip(self.gins, self.bns):
            h_new = bn(gin(h, edge_index))
            h_new = F.relu(h_new)
            h_new = self.dropout(h_new)
            h = h_new + prev  # residual
            prev = h

        # Dual pooling
        mean_pool = global_mean_pool(h, batch)
        add_pool = global_add_pool(h, batch)
        graph_emb = torch.cat([mean_pool, add_pool], dim=-1)

        logits = self.classifier(graph_emb)
        confidence = self.confidence_head(graph_emb)
        return logits, confidence

    @torch.no_grad()
    def predict(
        self,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> tuple[int, float, float]:
        """Single-graph prediction (inference mode).

        Returns:
            ``(predicted_class, probability, confidence)``
        """
        self.eval()
        logits, confidence = self.forward(x, edge_index, batch)
        probs = F.softmax(logits, dim=-1)
        pred_class = int(probs.argmax(dim=-1).item())
        pred_prob = float(probs[0, pred_class].item())
        conf = float(confidence.squeeze(-1).item())
        return pred_class, pred_prob, conf

    def get_attention_weights(self) -> dict[str, None]:
        """GIN has no attention weights (uses sum aggregation).

        Returns an empty dict for interface compatibility with MiniGAT.
        """
        return {}

    def parameter_count(self) -> dict[str, int]:
        """Count model parameters."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {"total": total, "trainable": trainable}
