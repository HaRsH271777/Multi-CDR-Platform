"""
Run this script to produce detection metrics for the MC-CDR evaluation.
Results are saved to evaluation/results/ and should be committed to the repo.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csnl.normalizers.aws_normalizer import normalize_aws_event
from detection.engine import DetectionEngine

logger = logging.getLogger(__name__)


def run_evaluation(dataset_path: Path) -> dict:
    engine = DetectionEngine(Path("detection/rules"))

    tp = fp = tn = fn = 0
    per_scenario: dict[str, dict[str, int]] = {}
    total = benign = attack = skipped = 0

    with open(dataset_path, "r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            total += 1
            raw_event = json.loads(line)
            ground_truth = raw_event.get("label", "benign")
            scenario = raw_event.get("scenario", "unknown")
            if ground_truth == "attack":
                attack += 1
            else:
                benign += 1

            normalized = normalize_aws_event(
                raw_event, collected_at=datetime.now(timezone.utc)
            )
            if normalized is None:
                skipped += 1
                continue

            detections = engine.process(normalized)
            predicted_attack = len(detections) > 0

            counts = per_scenario.setdefault(
                scenario, {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
            )
            if ground_truth == "attack" and predicted_attack:
                tp += 1
                counts["tp"] += 1
            elif ground_truth == "benign" and predicted_attack:
                fp += 1
                counts["fp"] += 1
            elif ground_truth == "attack" and not predicted_attack:
                fn += 1
                counts["fn"] += 1
            else:
                tn += 1
                counts["tn"] += 1

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) > 0 else 0

    results = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path.as_posix()),
        "dataset_stats": {
            "total": total,
            "benign": benign,
            "attack": attack,
            "skipped": skipped,
        },
        "overall": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "precision": round(precision, 4),
            "f1_score": round(f1, 4),
        },
        "per_scenario": per_scenario,
    }

    output = Path("evaluation/results")
    output.mkdir(parents=True, exist_ok=True)
    output_path = output / "detection_results.json"
    output_path.write_text(json.dumps(results, indent=2), encoding="utf-8")

    logger.info("Skipped %d events during normalization", skipped)
    return results


if __name__ == "__main__":
    run_evaluation(dataset_path=Path("evaluation/data/dataset.jsonl"))
