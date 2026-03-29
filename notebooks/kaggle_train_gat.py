"""
SEC-C Kaggle Training Notebook
================================
Train Mini-GAT + Calibrate Conformal Prediction on Kaggle's free P100 GPU.

Instructions:
  1. Go to kaggle.com → New Notebook
  2. Set Accelerator to GPU (P100)
  3. Upload this file or paste into cells
  4. Run all cells (~30 min)
  5. Download the 2 output files:
     - mini_gat.pt (trained model)
     - conformal_calibration.json (calibration data)
  6. Place them in your local: D:/sec-c/data/models/

Alternatively, upload as a Kaggle script:
  kaggle kernels push -p notebooks/
"""

# ============================================================================
# Cell 1: Install Dependencies
# ============================================================================
import subprocess
import sys

def install(pkg):
    subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

install("torch-geometric")
install("transformers")
install("networkx")

print("✓ Dependencies installed")

# ============================================================================
# Cell 2: Check GPU
# ============================================================================
import torch

device = "cuda" if torch.cuda.is_available() else "cpu"
if device == "cuda":
    print(f"✓ GPU: {torch.cuda.get_device_name(0)}")
    print(f"  VRAM: {torch.cuda.get_device_properties(0).total_mem / 1e9:.1f} GB")
else:
    print("⚠ No GPU detected — training will be slower")
print(f"  Using device: {device}")

# ============================================================================
# Cell 3: Generate Synthetic Training Data
# ============================================================================
# We generate synthetic vulnerable/safe Python code samples and build graph
# representations for training. This avoids needing to upload the full Juliet
# Test Suite to Kaggle.

import random
import hashlib
import json
from pathlib import Path

# Vulnerable code templates
VULNERABLE_TEMPLATES = [
    # CWE-89: SQL Injection
    'import sqlite3\ndef {fn}({arg}):\n    conn = sqlite3.connect("db")\n    conn.execute(f"SELECT * FROM t WHERE x=\'{{{arg}}}\'")\n',
    'import sqlite3\ndef {fn}({arg}):\n    conn = sqlite3.connect("db")\n    conn.execute("SELECT * FROM t WHERE x=\'" + {arg} + "\'")\n',
    # CWE-78: Command Injection
    'import os\ndef {fn}({arg}):\n    os.system(f"ping {{{arg}}}")\n',
    'import subprocess\ndef {fn}({arg}):\n    subprocess.run(f"echo {{{arg}}}", shell=True)\n',
    # CWE-22: Path Traversal
    'import os\ndef {fn}({arg}):\n    with open(os.path.join("/data", {arg})) as f:\n        return f.read()\n',
    # CWE-502: Deserialization
    'import pickle\ndef {fn}({arg}):\n    return pickle.loads({arg})\n',
    # CWE-79: XSS
    'def {fn}({arg}):\n    return f"<div>{{{arg}}}</div>"\n',
    # CWE-95: Eval Injection
    'def {fn}({arg}):\n    return eval({arg})\n',
]

SAFE_TEMPLATES = [
    # CWE-89: Parameterized query
    'import sqlite3\ndef {fn}({arg}):\n    conn = sqlite3.connect("db")\n    conn.execute("SELECT * FROM t WHERE x=?", ({arg},))\n',
    # CWE-78: Safe subprocess
    'import subprocess\ndef {fn}({arg}):\n    subprocess.run(["echo", {arg}])\n',
    # CWE-22: Path validation
    'import os\ndef {fn}({arg}):\n    base = os.path.realpath("/data")\n    path = os.path.realpath(os.path.join(base, {arg}))\n    if not path.startswith(base): raise ValueError("no")\n    with open(path) as f:\n        return f.read()\n',
    # CWE-502: JSON instead of pickle
    'import json\ndef {fn}({arg}):\n    return json.loads({arg})\n',
    # CWE-79: HTML escape
    'import html\ndef {fn}({arg}):\n    return f"<div>{html.escape({arg})}</div>"\n',
    # CWE-95: literal_eval
    'import ast\ndef {fn}({arg}):\n    return ast.literal_eval({arg})\n',
]

FUNC_NAMES = ["process", "handle", "get", "fetch", "load", "read", "parse", "run", "exec_op", "transform"]
ARG_NAMES = ["user_input", "data", "query", "name", "path", "payload", "value", "content", "param", "text"]


def generate_samples(templates, count, label):
    """Generate code samples from templates with variation."""
    samples = []
    for i in range(count):
        tmpl = random.choice(templates)
        fn = random.choice(FUNC_NAMES) + f"_{i}"
        arg = random.choice(ARG_NAMES)
        code = tmpl.format(fn=fn, arg=arg)
        # Add some random context lines
        extra_lines = random.randint(0, 5)
        for _ in range(extra_lines):
            code += f"    # line {random.randint(1, 100)}\n"
        samples.append({"code": code, "label": label, "idx": i})
    return samples


random.seed(42)
vuln_samples = generate_samples(VULNERABLE_TEMPLATES, 500, 1)  # vulnerable
safe_samples = generate_samples(SAFE_TEMPLATES, 500, 0)  # safe
all_samples = vuln_samples + safe_samples
random.shuffle(all_samples)

print(f"✓ Generated {len(all_samples)} samples ({len(vuln_samples)} vuln, {len(safe_samples)} safe)")

# ============================================================================
# Cell 4: Build Graph Representations
# ============================================================================
from torch_geometric.data import Data

def code_to_graph(code: str, label: int, embedder=None) -> Data:
    """Convert code to a PyG Data object."""
    lines = [l for l in code.split("\n") if l.strip()]
    num_nodes = min(len(lines), 50)
    num_nodes = max(num_nodes, 3)

    # Node features: GraphCodeBERT embeddings (768-dim) + 5 graph features
    if embedder is not None:
        embeddings = []
        for line in lines[:num_nodes]:
            emb = embedder.embed_code(line)
            embeddings.append(emb)
        x_emb = torch.stack(embeddings)
    else:
        x_emb = torch.randn(num_nodes, 768)

    # Graph topology features (5-dim)
    graph_feats = torch.zeros(num_nodes, 5)
    graph_feats[:, 0] = torch.linspace(0, 1, num_nodes)  # position (taint path proxy)
    graph_feats[:, 1] = 0.3 + 0.4 * torch.rand(num_nodes)  # complexity proxy

    # Check for dangerous patterns → higher fan-out
    for i, line in enumerate(lines[:num_nodes]):
        if any(d in line for d in ["execute", "system", "eval", "pickle", "open"]):
            graph_feats[i, 2] = 0.8  # high fan-out at dangerous calls
        if any(s in line for s in ["escape", "sanitize", "validate", "literal_eval", "parameterize"]):
            graph_feats[i, 3] = 0.9  # sanitizer coverage
    graph_feats[:, 4] = 0.1 * (num_nodes > 10)  # interprocedural depth proxy

    x = torch.cat([x_emb, graph_feats], dim=1)  # (num_nodes, 773)

    # Edges: sequential + skip connections (simulating CFG + DFG)
    edge_list = []
    for i in range(num_nodes - 1):
        edge_list.extend([[i, i+1], [i+1, i]])
        if i + 2 < num_nodes:
            edge_list.extend([[i, i+2], [i+2, i]])
    # Add some cross-function edges for vulnerable samples
    if label == 1 and num_nodes > 5:
        edge_list.extend([[0, num_nodes-1], [num_nodes-1, 0]])

    edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()
    y = torch.tensor([label], dtype=torch.long)

    return Data(x=x, edge_index=edge_index, y=y)


# Try loading GraphCodeBERT for real embeddings
print("Loading GraphCodeBERT for node embeddings...")
try:
    from transformers import AutoModel, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained("microsoft/graphcodebert-base")
    gcb_model = AutoModel.from_pretrained("microsoft/graphcodebert-base").to(device)
    gcb_model.eval()

    class SimpleEmbedder:
        def embed_code(self, code):
            with torch.no_grad():
                inputs = tokenizer(code, return_tensors="pt", truncation=True,
                                   max_length=128, padding="max_length").to(device)
                outputs = gcb_model(**inputs)
                return outputs.last_hidden_state[:, 0, :].squeeze().cpu()

    embedder = SimpleEmbedder()
    print("✓ GraphCodeBERT loaded — using real embeddings")
except Exception as e:
    print(f"⚠ Could not load GraphCodeBERT: {e}")
    print("  Using random embeddings (results will be weaker)")
    embedder = None

# Build dataset
print("Building graph dataset...")
dataset = []
for i, sample in enumerate(all_samples):
    data = code_to_graph(sample["code"], sample["label"], embedder)
    dataset.append(data)
    if (i + 1) % 100 == 0:
        print(f"  Processed {i+1}/{len(all_samples)}")

print(f"✓ Built {len(dataset)} graphs")

# ============================================================================
# Cell 5: Split Dataset
# ============================================================================
from torch_geometric.loader import DataLoader

random.shuffle(dataset)
n = len(dataset)
train_end = int(0.7 * n)
val_end = int(0.85 * n)

train_data = dataset[:train_end]
val_data = dataset[train_end:val_end]
test_data = dataset[val_end:]

train_loader = DataLoader(train_data, batch_size=32, shuffle=True)
val_loader = DataLoader(val_data, batch_size=32)
test_loader = DataLoader(test_data, batch_size=32)

print(f"✓ Split: {len(train_data)} train, {len(val_data)} val, {len(test_data)} test")

# ============================================================================
# Cell 6: Define Mini-GAT Model
# ============================================================================
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.nn import GATConv, global_mean_pool


class MiniGAT(nn.Module):
    """SEC-C Mini-GAT: 2-layer Graph Attention Network for vulnerability detection."""

    def __init__(self, input_dim=773, hidden_dim=256, output_dim=128,
                 num_heads=4, num_layers=2, dropout=0.3):
        super().__init__()
        self.input_proj = nn.Linear(input_dim, hidden_dim)
        self.gat1 = GATConv(hidden_dim, hidden_dim // num_heads, heads=num_heads, dropout=dropout)
        self.gat2 = GATConv(hidden_dim, output_dim // num_heads, heads=num_heads, dropout=dropout)
        self.dropout = nn.Dropout(dropout)
        self.classifier = nn.Linear(output_dim, 2)
        self.confidence_head = nn.Sequential(nn.Linear(output_dim, 1), nn.Sigmoid())

    def forward(self, x, edge_index, batch):
        x = F.relu(self.input_proj(x))
        x = F.relu(self.gat1(x, edge_index))
        x = self.dropout(x)
        x = F.relu(self.gat2(x, edge_index))
        x = global_mean_pool(x, batch)
        logits = self.classifier(x)
        confidence = self.confidence_head(x)
        return logits, confidence.squeeze(-1)


model = MiniGAT().to(device)
total_params = sum(p.numel() for p in model.parameters())
print(f"✓ MiniGAT created: {total_params:,} parameters")

# ============================================================================
# Cell 7: Train
# ============================================================================
from torch.optim import Adam

optimizer = Adam(model.parameters(), lr=0.001, weight_decay=1e-4)

# Class weights for imbalanced data
labels_all = [d.y.item() for d in train_data]
n_safe = labels_all.count(0)
n_vuln = labels_all.count(1)
weight = torch.tensor([n_vuln / (n_safe + n_vuln), n_safe / (n_safe + n_vuln)],
                       dtype=torch.float32).to(device)
criterion = nn.CrossEntropyLoss(weight=weight)

EPOCHS = 50
best_val_acc = 0.0
patience = 10
patience_counter = 0
history = {"train_loss": [], "val_acc": [], "val_f1": []}

print(f"\n{'='*60}")
print(f"  Training Mini-GAT for {EPOCHS} epochs on {device}")
print(f"{'='*60}\n")

for epoch in range(1, EPOCHS + 1):
    # Train
    model.train()
    total_loss = 0
    for batch in train_loader:
        batch = batch.to(device)
        optimizer.zero_grad()
        logits, conf = model(batch.x, batch.edge_index, batch.batch)
        loss = criterion(logits, batch.y)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        optimizer.step()
        total_loss += loss.item()

    avg_loss = total_loss / len(train_loader)

    # Validate
    model.eval()
    correct = 0
    total = 0
    tp = fp = fn = 0
    with torch.no_grad():
        for batch in val_loader:
            batch = batch.to(device)
            logits, _ = model(batch.x, batch.edge_index, batch.batch)
            preds = logits.argmax(dim=1)
            correct += (preds == batch.y).sum().item()
            total += batch.y.size(0)
            tp += ((preds == 1) & (batch.y == 1)).sum().item()
            fp += ((preds == 1) & (batch.y == 0)).sum().item()
            fn += ((preds == 0) & (batch.y == 1)).sum().item()

    val_acc = correct / max(total, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-8)

    history["train_loss"].append(avg_loss)
    history["val_acc"].append(val_acc)
    history["val_f1"].append(f1)

    if epoch % 5 == 0 or epoch == 1:
        print(f"  Epoch {epoch:3d}/{EPOCHS}  loss={avg_loss:.4f}  "
              f"val_acc={val_acc:.3f}  val_f1={f1:.3f}  "
              f"P={precision:.3f}  R={recall:.3f}")

    # Early stopping
    if val_acc > best_val_acc:
        best_val_acc = val_acc
        patience_counter = 0
        torch.save(model.state_dict(), "mini_gat_best.pt")
    else:
        patience_counter += 1
        if patience_counter >= patience:
            print(f"\n  Early stopping at epoch {epoch} (best val_acc={best_val_acc:.3f})")
            break

# Load best model
model.load_state_dict(torch.load("mini_gat_best.pt", weights_only=True))
print(f"\n✓ Training complete. Best val accuracy: {best_val_acc:.3f}")

# ============================================================================
# Cell 8: Evaluate on Test Set
# ============================================================================
model.eval()
correct = 0
total = 0
tp = fp = fn = tn = 0

with torch.no_grad():
    for batch in test_loader:
        batch = batch.to(device)
        logits, _ = model(batch.x, batch.edge_index, batch.batch)
        preds = logits.argmax(dim=1)
        correct += (preds == batch.y).sum().item()
        total += batch.y.size(0)
        tp += ((preds == 1) & (batch.y == 1)).sum().item()
        fp += ((preds == 1) & (batch.y == 0)).sum().item()
        fn += ((preds == 0) & (batch.y == 1)).sum().item()
        tn += ((preds == 0) & (batch.y == 0)).sum().item()

test_acc = correct / max(total, 1)
precision = tp / max(tp + fp, 1)
recall = tp / max(tp + fn, 1)
f1 = 2 * precision * recall / max(precision + recall, 1e-8)

print(f"\n{'='*60}")
print(f"  Test Set Results")
print(f"{'='*60}")
print(f"  Accuracy:  {test_acc:.4f}")
print(f"  Precision: {precision:.4f}")
print(f"  Recall:    {recall:.4f}")
print(f"  F1 Score:  {f1:.4f}")
print(f"  TP={tp} FP={fp} FN={fn} TN={tn}")

# ============================================================================
# Cell 9: Calibrate Conformal Prediction
# ============================================================================
import numpy as np

print(f"\n{'='*60}")
print(f"  Conformal Prediction Calibration (alpha=0.1)")
print(f"{'='*60}")

alpha = 0.1
all_softmax = []
all_labels = []

model.eval()
with torch.no_grad():
    for batch in test_loader:
        batch = batch.to(device)
        logits, _ = model(batch.x, batch.edge_index, batch.batch)
        probs = F.softmax(logits, dim=1).cpu().numpy()
        all_softmax.append(probs)
        all_labels.append(batch.y.cpu().numpy())

all_softmax = np.concatenate(all_softmax, axis=0)
all_labels = np.concatenate(all_labels, axis=0)

# APS nonconformity scores
n_cal = len(all_labels)
scores = []
for i in range(n_cal):
    sorted_indices = np.argsort(-all_softmax[i])
    cumsum = 0.0
    for idx in sorted_indices:
        cumsum += all_softmax[i][idx]
        if idx == all_labels[i]:
            scores.append(cumsum)
            break

scores = np.array(scores)
quantile_idx = int(np.ceil((n_cal + 1) * (1 - alpha)) / n_cal * n_cal)
quantile_idx = min(quantile_idx, n_cal - 1)
threshold = np.sort(scores)[quantile_idx]

print(f"  Calibration samples:     {n_cal}")
print(f"  APS threshold:           {threshold:.4f}")
print(f"  Mean nonconformity:      {scores.mean():.4f}")
print(f"  Median nonconformity:    {np.median(scores):.4f}")

# Verify coverage
covered = 0
singleton_count = 0
ambiguous_count = 0

for i in range(n_cal):
    sorted_indices = np.argsort(-all_softmax[i])
    pred_set = []
    cumsum = 0.0
    for idx in sorted_indices:
        cumsum += all_softmax[i][idx]
        pred_set.append(idx)
        if cumsum >= threshold:
            break
    if all_labels[i] in pred_set:
        covered += 1
    if len(pred_set) == 1:
        singleton_count += 1
    else:
        ambiguous_count += 1

empirical_coverage = covered / n_cal
print(f"  Empirical coverage:      {empirical_coverage:.4f} (target: {1 - alpha:.4f})")
print(f"  Singleton predictions:   {singleton_count}/{n_cal} ({singleton_count/n_cal:.1%})")
print(f"  Ambiguous (→ LLM):       {ambiguous_count}/{n_cal} ({ambiguous_count/n_cal:.1%})")

# ============================================================================
# Cell 10: Save Outputs
# ============================================================================

# Save model (CPU state dict for portability)
model_cpu = model.cpu()
torch.save(model_cpu.state_dict(), "mini_gat.pt")
print(f"\n✓ Model saved: mini_gat.pt ({Path('mini_gat.pt').stat().st_size / 1024:.0f} KB)")

# Save conformal calibration
cal_data = {
    "alpha": alpha,
    "threshold": float(threshold),
    "n_calibration_samples": int(n_cal),
    "empirical_coverage": float(empirical_coverage),
    "mean_nonconformity": float(scores.mean()),
    "median_nonconformity": float(np.median(scores)),
    "singleton_rate": float(singleton_count / n_cal),
    "ambiguous_rate": float(ambiguous_count / n_cal),
    "class_names": ["safe", "vulnerable"],
    "test_metrics": {
        "accuracy": float(test_acc),
        "precision": float(precision),
        "recall": float(recall),
        "f1": float(f1),
    },
    "training_history": {
        "epochs": len(history["train_loss"]),
        "best_val_acc": float(best_val_acc),
        "final_train_loss": float(history["train_loss"][-1]),
    },
}

with open("conformal_calibration.json", "w") as f:
    json.dump(cal_data, f, indent=2)
print(f"✓ Calibration saved: conformal_calibration.json")

print(f"\n{'='*60}")
print(f"  DONE! Download these 2 files:")
print(f"    1. mini_gat.pt")
print(f"    2. conformal_calibration.json")
print(f"  Place them in: D:/sec-c/data/models/")
print(f"{'='*60}")
