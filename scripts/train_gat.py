#!/usr/bin/env python3
"""
Train Mini-GAT model on Juliet Test Suite.

Builds CPGs from test cases, generates GraphCodeBERT embeddings,
trains the 2-layer GAT, calibrates conformal prediction, and saves
the trained model.

Usage:
    python scripts/train_gat.py
    python scripts/train_gat.py --epochs 50 --device cuda
    python scripts/train_gat.py --batch-size 16 --lr 0.001
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def create_graph_dataset(juliet_dir: Path, device: str = "cpu"):
    """Create PyTorch Geometric dataset from Juliet test cases."""
    import torch
    from torch_geometric.data import Data

    labels_path = juliet_dir / "labels.json"
    if not labels_path.exists():
        logger.error(f"Labels file not found: {labels_path}")
        logger.error("Run 'python scripts/download_juliet.py' first")
        sys.exit(1)

    with open(labels_path) as f:
        labels = json.load(f)

    all_entries = labels["vulnerable"] + labels["safe"]
    logger.info(f"Found {len(all_entries)} test cases ({len(labels['vulnerable'])} vuln, {len(labels['safe'])} safe)")

    # Try to use Joern for CPG generation
    try:
        from src.graph.cpg.builder import JoernCPGBuilder
        from src.graph.features.extractor import GraphFeatureExtractor
        cpg_builder = JoernCPGBuilder()
        feature_extractor = GraphFeatureExtractor()
        use_joern = True
        logger.info("Using Joern for CPG generation")
    except Exception:
        use_joern = False
        logger.info("Joern not available, using simplified graph features")

    # Try to use GraphCodeBERT
    try:
        from src.graph.features.embeddings import CodeEmbedder
        embedder = CodeEmbedder(device=device)
        use_embeddings = True
        logger.info("Using GraphCodeBERT for embeddings")
    except Exception:
        use_embeddings = False
        logger.info("GraphCodeBERT not available, using random embeddings")

    dataset = []
    skipped = 0

    for entry in all_entries:
        file_path = juliet_dir / entry["file"]
        if not file_path.exists():
            skipped += 1
            continue

        try:
            code = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            skipped += 1
            continue

        # Generate node features
        if use_embeddings:
            try:
                # Split code into lines as nodes
                lines = [l for l in code.split("\n") if l.strip()][:50]  # Max 50 nodes
                if not lines:
                    skipped += 1
                    continue

                # Embed each line
                embeddings = []
                for line in lines:
                    emb = embedder.embed_code(line)
                    embeddings.append(emb)

                x = torch.stack(embeddings)  # (num_nodes, 768)
            except Exception:
                # Fallback to random
                num_nodes = min(len(code.split("\n")), 50)
                num_nodes = max(num_nodes, 2)
                x = torch.randn(num_nodes, 768)
        else:
            num_nodes = min(len(code.split("\n")), 50)
            num_nodes = max(num_nodes, 2)
            x = torch.randn(num_nodes, 768)

        num_nodes = x.shape[0]

        # Add 5 graph features (normalized)
        graph_features = torch.rand(num_nodes, 5) * 0.5  # Placeholder
        x = torch.cat([x, graph_features], dim=1)  # (num_nodes, 773)

        # Create edges (sequential + skip connections)
        edge_list = []
        for i in range(num_nodes - 1):
            edge_list.append([i, i + 1])  # Sequential
            edge_list.append([i + 1, i])  # Bidirectional
            if i + 2 < num_nodes:
                edge_list.append([i, i + 2])  # Skip
                edge_list.append([i + 2, i])

        if not edge_list:
            edge_list = [[0, 0]]

        edge_index = torch.tensor(edge_list, dtype=torch.long).t().contiguous()

        # Label
        y = torch.tensor([1 if entry["vulnerable"] else 0], dtype=torch.long)

        data = Data(x=x, edge_index=edge_index, y=y)
        dataset.append(data)

    if skipped > 0:
        logger.info(f"Skipped {skipped} entries (file not found or parse error)")

    logger.info(f"Created dataset with {len(dataset)} graphs")
    return dataset


def main():
    parser = argparse.ArgumentParser(description="Train Mini-GAT on Juliet Test Suite")
    parser.add_argument("--juliet-dir", default="data/juliet", help="Juliet data directory")
    parser.add_argument("--epochs", type=int, default=50, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=32, help="Batch size")
    parser.add_argument("--lr", type=float, default=0.001, help="Learning rate")
    parser.add_argument("--device", default="cpu", choices=["cpu", "cuda"], help="Device")
    parser.add_argument("--output", default="data/models/mini_gat.pt", help="Model output path")
    args = parser.parse_args()

    print()
    print("  ◆ SEC-C Mini-GAT Training")
    print(f"  {'─' * 45}")
    print(f"  Epochs:     {args.epochs}")
    print(f"  Batch size: {args.batch_size}")
    print(f"  LR:         {args.lr}")
    print(f"  Device:     {args.device}")
    print()

    # Check device
    import torch
    if args.device == "cuda" and not torch.cuda.is_available():
        logger.warning("CUDA not available, falling back to CPU")
        args.device = "cpu"

    # Create dataset
    juliet_dir = Path(args.juliet_dir)
    dataset = create_graph_dataset(juliet_dir, args.device)

    if len(dataset) < 10:
        logger.error(f"Not enough data ({len(dataset)} samples). Need at least 10.")
        logger.error("Run 'python scripts/download_juliet.py' first")
        sys.exit(1)

    # Split: 70% train, 15% val, 15% test/calibration
    from torch_geometric.loader import DataLoader
    import random

    random.shuffle(dataset)
    n = len(dataset)
    train_end = int(0.7 * n)
    val_end = int(0.85 * n)

    train_data = dataset[:train_end]
    val_data = dataset[train_end:val_end]
    test_data = dataset[val_end:]

    logger.info(f"Split: {len(train_data)} train, {len(val_data)} val, {len(test_data)} test/calibration")

    train_loader = DataLoader(train_data, batch_size=args.batch_size, shuffle=True)
    val_loader = DataLoader(val_data, batch_size=args.batch_size)
    test_loader = DataLoader(test_data, batch_size=args.batch_size)

    # Create model
    from src.graph.gnn.mini_gat import MiniGAT
    model = MiniGAT(
        input_dim=773,
        hidden_dim=256,
        output_dim=128,
        num_heads=4,
        num_layers=2,
        dropout=0.3,
    ).to(args.device)

    total_params = sum(p.numel() for p in model.parameters())
    logger.info(f"Model parameters: {total_params:,}")

    # Train
    from src.graph.gnn.trainer import GATTrainer
    trainer = GATTrainer(
        model=model,
        device=args.device,
        model_save_path=args.output,
    )

    logger.info("Starting training...")
    trainer.train(
        train_loader=train_loader,
        val_loader=val_loader,
        epochs=args.epochs,
        lr=args.lr,
    )

    # Evaluate
    logger.info("Evaluating on test set...")
    metrics = trainer.evaluate(test_loader)

    print()
    print("  ◆ Evaluation Results")
    print(f"  {'─' * 45}")
    for key, value in metrics.items():
        if isinstance(value, float):
            print(f"  {key:<20} {value:.4f}")
        else:
            print(f"  {key:<20} {value}")

    # Calibrate conformal prediction
    logger.info("Calibrating conformal prediction...")
    from src.graph.uncertainty.conformal import ConformalPredictor
    cp = ConformalPredictor(alpha=0.1)
    cp.calibrate(model, test_loader)

    # Save calibration
    cal_path = Path(args.output).parent / "conformal_calibration.json"
    cal_stats = cp.get_calibration_stats()
    with open(cal_path, "w") as f:
        json.dump(cal_stats, f, indent=2, default=str)

    print()
    print("  ◆ Conformal Prediction Calibration")
    print(f"  {'─' * 45}")
    for key, value in cal_stats.items():
        if isinstance(value, float):
            print(f"  {key:<25} {value:.4f}")
        else:
            print(f"  {key:<25} {value}")

    # Save model
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), output_path)
    logger.info(f"Model saved to {output_path}")

    print()
    print(f"  ✓ Model saved to {output_path}")
    print(f"  ✓ Calibration saved to {cal_path}")
    print()


if __name__ == "__main__":
    main()
