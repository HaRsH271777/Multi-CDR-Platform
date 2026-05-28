"""Tune Isolation Forest contamination values on synthetic feature vectors."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detection.anomaly.isolation_forest import EntityBehaviorModel


@dataclass
class TuningResult:
    contamination: float
    precision: float
    recall: float
    f1: float


def generate_data(seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    normal = rng.normal(loc=1.0, scale=0.2, size=(150, 6))
    anomalies = rng.normal(loc=8.0, scale=0.5, size=(50, 6))
    features = np.vstack([normal, anomalies])
    labels = np.array([0] * len(normal) + [1] * len(anomalies))
    return features, labels


def evaluate_model(contamination: float, features: np.ndarray, labels: np.ndarray) -> TuningResult:
    model = EntityBehaviorModel(contamination=contamination)
    train_features = features[labels == 0]
    model.train(train_features)

    scaled = model.scaler.transform(features)
    predictions = model.model.predict(scaled)
    predicted_anomalies = predictions == -1

    tp = int(((labels == 1) & predicted_anomalies).sum())
    fp = int(((labels == 0) & predicted_anomalies).sum())
    fn = int(((labels == 1) & ~predicted_anomalies).sum())

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return TuningResult(
        contamination=contamination,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1=round(f1, 4),
    )


def run_tuning() -> dict:
    features, labels = generate_data(seed=42)
    results = [
        evaluate_model(0.01, features, labels),
        evaluate_model(0.05, features, labels),
        evaluate_model(0.10, features, labels),
    ]

    best = max(results, key=lambda item: item.f1)
    payload = {
        "tuning_date": datetime.now(timezone.utc).isoformat(),
        "random_seed": 42,
        "results": [result.__dict__ for result in results],
        "selected_contamination": best.contamination,
        "selection_reason": "Selected the contamination value with the highest F1 score.",
    }

    output = Path("evaluation/results/anomaly_tuning.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


if __name__ == "__main__":
    run_tuning()
