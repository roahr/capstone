"""
GraphCodeBERT embedding pipeline for code vulnerability analysis.

Provides vector representations of source code using Microsoft's GraphCodeBERT
model, which captures both semantic and structural information from code.
These embeddings serve as node features for the GNN-based vulnerability
detection model (Mini-GAT).
"""

from __future__ import annotations

import hashlib
import logging
from collections import OrderedDict
from typing import Any

import networkx as nx
import torch
from transformers import AutoModel, AutoTokenizer  # type: ignore[import-untyped]

logger = logging.getLogger(__name__)

# Default model checkpoint for GraphCodeBERT
_DEFAULT_MODEL = "microsoft/graphcodebert-base"

# GraphCodeBERT output dimension
EMBEDDING_DIM: int = 768

# Maximum sequence length (tokens) accepted by the transformer
_MAX_SEQ_LENGTH: int = 512

# Batch size for node-level embedding to limit GPU/CPU memory usage
_DEFAULT_BATCH_SIZE: int = 32

# Maximum number of cached embeddings before LRU eviction
_DEFAULT_CACHE_SIZE: int = 4096


class _LRUCache:
    """Simple LRU cache backed by an OrderedDict."""

    def __init__(self, maxsize: int = _DEFAULT_CACHE_SIZE) -> None:
        self._cache: OrderedDict[str, torch.Tensor] = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: str) -> torch.Tensor | None:
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, value: torch.Tensor) -> None:
        if key in self._cache:
            self._cache.move_to_end(key)
        else:
            if len(self._cache) >= self._maxsize:
                self._cache.popitem(last=False)
        self._cache[key] = value

    def clear(self) -> None:
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


class CodeEmbedder:
    """
    Produces fixed-size vector embeddings of source code using GraphCodeBERT.

    GraphCodeBERT is a pre-trained model that jointly learns representations
    from code, natural language comments, and data-flow graphs. The 768-dim
    CLS token embedding captures rich semantic and structural information
    suitable for downstream vulnerability detection tasks.

    Usage::

        embedder = CodeEmbedder(device="cuda")
        vec = embedder.embed_code("def foo(): return 42")
        assert vec.shape == (768,)

        # Embed every node in a NetworkX graph
        node_matrix = embedder.embed_nodes(graph)
        assert node_matrix.shape[0] == graph.number_of_nodes()

    Args:
        model_name: HuggingFace model identifier. Defaults to
            ``"microsoft/graphcodebert-base"``.
        device: PyTorch device string (``"cpu"`` or ``"cuda"``).
        cache_size: Maximum number of embeddings to keep in the LRU cache.
        batch_size: Number of snippets to embed in a single forward pass.
    """

    def __init__(
        self,
        model_name: str = _DEFAULT_MODEL,
        device: str = "cpu",
        cache_size: int = _DEFAULT_CACHE_SIZE,
        batch_size: int = _DEFAULT_BATCH_SIZE,
    ) -> None:
        self._device = torch.device(device)
        self._batch_size = batch_size
        self._cache = _LRUCache(maxsize=cache_size)

        logger.info("Loading tokenizer and model: %s", model_name)
        self._tokenizer = AutoTokenizer.from_pretrained(model_name)
        self._model = AutoModel.from_pretrained(model_name)
        self._model.to(self._device)
        self._model.eval()
        logger.info(
            "Model loaded on %s (params: %s)",
            self._device,
            f"{sum(p.numel() for p in self._model.parameters()):,}",
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def embed_code(self, code_snippet: str) -> torch.Tensor:
        """
        Embed a single code snippet into a 768-dimensional vector.

        Long snippets are truncated to ``_MAX_SEQ_LENGTH`` tokens. Results
        are cached so repeated calls with the same snippet are free.

        Args:
            code_snippet: Source code text.

        Returns:
            A 1-D ``torch.Tensor`` of shape ``(768,)`` on CPU.
        """
        cache_key = self._snippet_hash(code_snippet)
        cached = self._cache.get(cache_key)
        if cached is not None:
            return cached

        embedding = self._forward_batch([code_snippet]).squeeze(0)
        self._cache.put(cache_key, embedding)
        return embedding

    def embed_nodes(self, graph: nx.DiGraph) -> torch.Tensor:
        """
        Embed all nodes of a directed graph, returning a stacked tensor.

        Each node in *graph* is expected to carry a ``"code"`` attribute
        containing the source code snippet for that node. Nodes without
        a ``"code"`` attribute receive a zero vector.

        Args:
            graph: A NetworkX ``DiGraph`` whose nodes may have a
                ``"code"`` data attribute.

        Returns:
            A ``torch.Tensor`` of shape ``(num_nodes, 768)`` on CPU,
            where row *i* corresponds to the *i*-th node in
            ``list(graph.nodes())``.
        """
        nodes: list[Any] = list(graph.nodes())
        if not nodes:
            return torch.zeros(0, EMBEDDING_DIM)

        snippets: list[str] = []
        snippet_indices: list[int] = []
        zero_indices: list[int] = []

        for idx, node in enumerate(nodes):
            code: str | None = graph.nodes[node].get("code")
            if code:
                snippets.append(code)
                snippet_indices.append(idx)
            else:
                zero_indices.append(idx)

        # Pre-allocate the result tensor
        result = torch.zeros(len(nodes), EMBEDDING_DIM)

        if not snippets:
            return result

        # Check the cache first, collect misses
        uncached_snippets: list[str] = []
        uncached_positions: list[int] = []  # position within snippet_indices list

        for pos, snippet in enumerate(snippets):
            cache_key = self._snippet_hash(snippet)
            cached = self._cache.get(cache_key)
            if cached is not None:
                result[snippet_indices[pos]] = cached
            else:
                uncached_snippets.append(snippet)
                uncached_positions.append(pos)

        # Batch-embed all cache misses
        if uncached_snippets:
            embeddings = self._forward_batch(uncached_snippets)
            for batch_idx, pos in enumerate(uncached_positions):
                emb = embeddings[batch_idx]
                node_idx = snippet_indices[pos]
                result[node_idx] = emb
                self._cache.put(
                    self._snippet_hash(uncached_snippets[batch_idx]), emb
                )

        return result

    def clear_cache(self) -> None:
        """Evict all cached embeddings."""
        self._cache.clear()

    @property
    def cache_size(self) -> int:
        """Number of embeddings currently cached."""
        return len(self._cache)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @torch.no_grad()
    def _forward_batch(self, snippets: list[str]) -> torch.Tensor:
        """
        Run the transformer on a list of snippets, returning CLS embeddings.

        Processes snippets in mini-batches of ``self._batch_size`` to
        bound peak memory usage.

        Returns:
            Tensor of shape ``(len(snippets), 768)`` on CPU.
        """
        all_embeddings: list[torch.Tensor] = []

        for start in range(0, len(snippets), self._batch_size):
            batch = snippets[start : start + self._batch_size]
            encoded = self._tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=_MAX_SEQ_LENGTH,
                return_tensors="pt",
            )
            encoded = {k: v.to(self._device) for k, v in encoded.items()}

            outputs = self._model(**encoded)

            # CLS token is the first token of the last hidden state
            cls_embeddings: torch.Tensor = outputs.last_hidden_state[:, 0, :]
            all_embeddings.append(cls_embeddings.cpu())

        return torch.cat(all_embeddings, dim=0)

    @staticmethod
    def _snippet_hash(snippet: str) -> str:
        """Compute a deterministic hash key for a code snippet."""
        return hashlib.sha256(snippet.encode("utf-8")).hexdigest()
