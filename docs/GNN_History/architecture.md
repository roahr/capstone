# GNN Architecture: From GAT to GIN

## Architecture Evolution

### V2: Mini-GAT (Abandoned)

```
Input (773) -> GATConv(4 heads, 256) -> GATConv(4 heads, 128) -> GlobalMeanPool -> FC(2)
```

- **Parameters**: 298K
- **Aggregation**: Weighted mean (attention-based)
- **Problem**: GAT uses weighted-mean aggregation, which is not injective — structurally distinct subgraphs can produce identical representations. This limits the model's ability to distinguish vulnerability-relevant code patterns.
- **Reference**: Xu et al. 2019, "How Powerful are Graph Neural Networks?" (ICLR) proved that mean/max aggregation is strictly less expressive than sum aggregation.

### V3-V5: MiniGINv3 (Current)

```
Input (774) -> Linear(384) + BN + ReLU
            -> GINConv(MLP: 384->768->384) + BN + ReLU + Dropout + Residual  x3
            -> DualPool(MeanPool + AddPool) -> 768-dim
            -> Classifier(768->384->2) + ConfidenceHead(768->1->Sigmoid)
```

- **Parameters**: 2,375,046 (2.4M)
- **Aggregation**: Sum (injective, WL-test equivalent)
- **Key design choices**:
  - **3 GIN layers**: Each with 2-layer MLP inside (384->768->384), `train_eps=True`
  - **Residual connections**: `h = h_new + h_prev` after each GIN layer
  - **BatchNorm**: After each GIN layer (before ReLU)
  - **Dual pooling**: `graph_emb = cat(global_mean_pool(h), global_add_pool(h))` -> 768-dim
  - **Confidence head**: Separate sigmoid head estimating prediction confidence (auxiliary loss)

## Why GIN Over GAT

| Property | GAT | GIN |
|----------|-----|-----|
| Aggregation | Weighted mean | Sum |
| Injectivity | No (can conflate distinct neighborhoods) | Yes (provably injective) |
| WL-test equivalence | No (strictly weaker) | Yes (as powerful as 1-WL) |
| Expressiveness | Cannot distinguish regular graphs | Distinguishes all graphs 1-WL can |
| Vulnerability detection | Misses structural patterns | Captures control flow differences |

For vulnerability detection, code graphs often differ in subtle structural ways (e.g., missing bounds check = one fewer edge). GIN's injective aggregation preserves these differences.

## Input Features (774-dimensional)

### GraphCodeBERT Embeddings (768 dims)

- Model: `microsoft/graphcodebert-base` (RoBERTa-based, pre-trained on code)
- Extraction: Mean pooling over token embeddings (not CLS token — avoids missing pooler)
- Per-node: Each graph node's text is tokenized and embedded independently
- Max tokens per node: 128

### Structural Features (6 dims)

| Feature | Range | Description |
|---------|-------|-------------|
| `in_degree_norm` | [0, 1] | Normalized in-degree of the node |
| `out_degree_norm` | [0, 1] | Normalized out-degree of the node |
| `is_sink` | {0, 1} | 1 if node text matches any of 54 sink patterns |
| `is_source` | {0, 1} | 1 if node text matches any of 42 source patterns |
| `depth_norm` | [0, 1] | Normalized shortest-path distance from root |
| `language_id` | {0.0, 0.2, 0.4, 0.6, 0.8} | Language encoding (py=0, js=0.2, java=0.4, c=0.6, go=0.8) |

**V2 had 5 features** (no `language_id`), giving input_dim=773. V3+ has 6, giving 774.

## Graph Construction

### Node Extraction
1. **Tree-sitter mode** (preferred): Parse AST, extract statement-level nodes (function_definition, if_statement, return_statement, call_expression, etc.)
2. **Regex fallback**: Split code into non-empty, non-comment lines; each line becomes a node

### Edge Types
- **AST edges**: Parent-child from indent structure (tree-sitter) or sequential (regex)
- **AST skip edges**: Connect nodes 2 positions apart (captures longer-range AST dependencies)
- **CFG edges**: Control flow (if/for/while branches, return/break jumps)
- **DDG edges**: Data dependency (variable def-use within window of 5-8 nodes)

### Constraints
- Max nodes: 300 per graph
- Min code length: 20 characters (filter trivial samples)
- Min code lines: 3 lines (filter snippets)

## Sink and Source Patterns

**54 sink patterns** (security-sensitive functions that consume data):
```
execute, exec, system, popen, strcpy, strcat, memcpy, gets, scanf, malloc,
free, eval, innerHTML, document.write, cursor.execute, pickle.loads, yaml.load,
subprocess, os.system, render_template_string, child_process, ...
```

**42 source patterns** (functions that produce untrusted input):
```
request, getParameter, argv, stdin, environ, fgets, recv, socket,
flask.request, django.request, req.body, req.params, process.env, ...
```

These patterns create binary node features that help the model identify taint-relevant nodes without requiring full taint analysis.

## Training Configuration

| Parameter | V3 | V4 | V5 |
|-----------|----|----|-----|
| Learning rate | 3e-4 | 3e-4 | 3e-4 |
| LR warmup | 5 epochs | 5 epochs | 5 epochs |
| LR schedule | Cosine decay | Cosine decay | Cosine decay |
| Batch size | 64 | 64 | 64 |
| Dropout | 0.4 | 0.35 | 0.35 |
| Weight decay | 1e-3 | 1e-3 | 1e-3 |
| Class weight (vuln) | 1.5 | 1.5 | 1.5 |
| Label smoothing | 0.1 | 0.1 | **0.0** |
| Patience | 25 | 20 | 20 |
| Grad clip | 0.5 | 0.5 | 0.5 |
| Loss | CE + smooth | CE + smooth | CE (no smooth) |

### Auxiliary Confidence Loss

In addition to the classification cross-entropy, training includes an auxiliary loss:
```python
loss += 0.1 * BCE(confidence.squeeze(-1), correct)
```
Where `correct = (argmax(logits) == true_label).float()`. This trains the confidence head to predict whether the classifier is correct, providing a secondary uncertainty signal.
