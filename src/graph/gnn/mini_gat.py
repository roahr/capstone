"""
Mini-GAT: A compact Graph Attention Network for vulnerability detection.

Architecture overview::

    Input: 773-dim  (768 GraphCodeBERT + 5 hand-crafted graph features)
       |
    Linear 773 -> 256 + ReLU
       |
    GATConv (256 -> 256, 4 heads, concat -> 256)
       |
    Dropout 0.3
       |
    GATConv (256 -> 128, 4 heads, concat -> 128)
       |
    Global Mean Pooling -> 128-dim graph embedding
       |
    +-- Head 1 (Classification): Linear 128 -> 2  (safe / vulnerable)
    +-- Head 2 (Confidence):     Linear 128 -> 1, Sigmoid

The model outputs both a vulnerability classification and a learned
confidence score, enabling downstream conformal prediction to decide
whether the result should be escalated to the LLM stage.
"""

from __future__ import annotations

import logging
from typing import Any

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch import Tensor
from torch_geometric.nn import GATConv, global_mean_pool  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# --- Architectural constants ------------------------------------------------

INPUT_DIM: int = 773       # 768 (GraphCodeBERT) + 5 (graph features)
HIDDEN_DIM: int = 256
OUTPUT_DIM: int = 128
NUM_HEADS_L1: int = 4
NUM_HEADS_L2: int = 4
DROPOUT: float = 0.3
NUM_CLASSES: int = 2       # safe=0, vulnerable=1


class MiniGAT(nn.Module):
    """
    Two-layer Graph Attention Network for binary vulnerability classification.

    The model accepts node feature matrices whose last five columns contain
    hand-crafted graph-structural features (e.g., in-degree, out-degree,
    betweenness centrality, PageRank, clustering coefficient), while the
    first 768 columns are GraphCodeBERT embeddings.

    Args:
        input_dim: Dimensionality of node features. Default ``773``.
        hidden_dim: Width of the first GAT layer. Default ``256``.
        output_dim: Width of the second GAT layer / graph embedding.
            Default ``128``.
        num_heads_l1: Attention heads in GAT layer 1. Default ``4``.
        num_heads_l2: Attention heads in GAT layer 2. Default ``4``.
        dropout: Dropout probability applied between GAT layers.
            Default ``0.3``.
        num_classes: Number of classification targets. Default ``2``.
    """

    def __init__(
        self,
        input_dim: int = INPUT_DIM,
        hidden_dim: int = HIDDEN_DIM,
        output_dim: int = OUTPUT_DIM,
        num_heads_l1: int = NUM_HEADS_L1,
        num_heads_l2: int = NUM_HEADS_L2,
        dropout: float = DROPOUT,
        num_classes: int = NUM_CLASSES,
    ) -> None:
        super().__init__()

        self.input_dim = input_dim
        self.hidden_dim = hidden_dim
        self.output_dim = output_dim
        self.dropout = dropout

        # ----- Projection layer ------------------------------------------------
        self.input_proj = nn.Linear(input_dim, hidden_dim)

        # ----- GAT backbone ----------------------------------------------------
        # Layer 1: multi-head attention with concatenation.
        # heads * out_channels must equal hidden_dim so that the output size
        # stays at hidden_dim.  hidden_dim // num_heads_l1 per head, concat
        # back to hidden_dim.
        head_dim_l1 = hidden_dim // num_heads_l1
        self.gat1 = GATConv(
            in_channels=hidden_dim,
            out_channels=head_dim_l1,
            heads=num_heads_l1,
            concat=True,
            dropout=dropout,
        )

        # Layer 2: output_dim // num_heads_l2 per head -> concat to output_dim
        head_dim_l2 = output_dim // num_heads_l2
        self.gat2 = GATConv(
            in_channels=hidden_dim,  # output of gat1 after concat = hidden_dim
            out_channels=head_dim_l2,
            heads=num_heads_l2,
            concat=True,
            dropout=dropout,
        )

        # ----- Task heads ------------------------------------------------------
        self.classifier = nn.Linear(output_dim, num_classes)
        self.confidence_head = nn.Linear(output_dim, 1)

        # Storage for attention weights (populated during forward pass)
        self._attn_weights_l1: Tensor | None = None
        self._attn_weights_l2: Tensor | None = None

        logger.info(
            "MiniGAT initialised: input=%d, hidden=%d, output=%d, "
            "heads=(%d,%d), dropout=%.2f, classes=%d",
            input_dim, hidden_dim, output_dim,
            num_heads_l1, num_heads_l2, dropout, num_classes,
        )

    # ------------------------------------------------------------------
    # Forward
    # ------------------------------------------------------------------

    def forward(
        self,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> tuple[Tensor, Tensor]:
        """
        Full forward pass through the Mini-GAT.

        Args:
            x: Node feature matrix of shape ``(N, input_dim)``.
            edge_index: COO edge index of shape ``(2, E)``.
            batch: Batch vector mapping each node to its graph,
                shape ``(N,)``.

        Returns:
            A tuple ``(class_logits, confidence)`` where:

            * **class_logits** has shape ``(B, num_classes)`` with raw
              logits for each graph in the batch.
            * **confidence** has shape ``(B, 1)`` with values in [0, 1].
        """
        # 1) Project from 773 -> 256
        h = F.relu(self.input_proj(x))

        # 2) GAT Layer 1  (256 -> 256 via 4 heads x 64)
        h, attn1 = self.gat1(h, edge_index, return_attention_weights=True)
        self._attn_weights_l1 = attn1[1]  # (E, heads)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        # 3) GAT Layer 2  (256 -> 128 via 4 heads x 32)
        h, attn2 = self.gat2(h, edge_index, return_attention_weights=True)
        self._attn_weights_l2 = attn2[1]  # (E, heads)
        h = F.relu(h)

        # 4) Global mean pooling -> (B, 128)
        graph_emb = global_mean_pool(h, batch)

        # 5) Task heads
        class_logits = self.classifier(graph_emb)       # (B, 2)
        confidence = torch.sigmoid(self.confidence_head(graph_emb))  # (B, 1)

        return class_logits, confidence

    # ------------------------------------------------------------------
    # Convenience methods
    # ------------------------------------------------------------------

    @torch.no_grad()
    def predict(
        self,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> tuple[int, float, float]:
        """
        Single-graph prediction returning class, probability and confidence.

        The model is automatically set to eval mode for this call.

        Args:
            x: Node features ``(N, input_dim)``.
            edge_index: COO edge index ``(2, E)``.
            batch: Batch vector ``(N,)``.

        Returns:
            A tuple ``(predicted_class, probability, confidence)`` where:

            * **predicted_class** is ``0`` (safe) or ``1`` (vulnerable).
            * **probability** is the softmax probability of the predicted
              class.
            * **confidence** is the learned confidence score in [0, 1].
        """
        was_training = self.training
        self.eval()

        logits, conf = self.forward(x, edge_index, batch)
        probs = F.softmax(logits, dim=-1)
        pred_class = int(probs.argmax(dim=-1).item())
        pred_prob = float(probs[0, pred_class].item())
        conf_val = float(conf.squeeze().item())

        if was_training:
            self.train()

        return pred_class, pred_prob, conf_val

    def get_attention_weights(self) -> dict[str, Tensor | None]:
        """
        Retrieve the most recently computed attention weight tensors.

        Useful for explainability: the weights reveal which edges (and
        therefore which code regions) the model attends to most strongly.

        Returns:
            A dict with keys ``"layer_1"`` and ``"layer_2"``, each
            mapping to a tensor of shape ``(E, heads)`` or ``None`` if
            no forward pass has been executed yet.
        """
        return {
            "layer_1": self._attn_weights_l1,
            "layer_2": self._attn_weights_l2,
        }

    def get_graph_embedding(
        self,
        x: Tensor,
        edge_index: Tensor,
        batch: Tensor,
    ) -> Tensor:
        """
        Return the 128-dim graph-level embedding (before the task heads).

        Useful for downstream analysis, clustering, or as input to the
        conformal prediction module.

        Args:
            x: Node features ``(N, input_dim)``.
            edge_index: COO edge index ``(2, E)``.
            batch: Batch vector ``(N,)``.

        Returns:
            Tensor of shape ``(B, output_dim)``.
        """
        h = F.relu(self.input_proj(x))

        h, _ = self.gat1(h, edge_index, return_attention_weights=True)
        h = F.relu(h)
        h = F.dropout(h, p=self.dropout, training=self.training)

        h, _ = self.gat2(h, edge_index, return_attention_weights=True)
        h = F.relu(h)

        return global_mean_pool(h, batch)

    def parameter_count(self) -> dict[str, int]:
        """Return trainable and total parameter counts."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(p.numel() for p in self.parameters() if p.requires_grad)
        return {"total": total, "trainable": trainable}
