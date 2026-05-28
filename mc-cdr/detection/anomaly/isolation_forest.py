import logging
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


class EntityBehaviorModel:
    """Isolation Forest model for per-entity behavioral baselines."""

    FEATURE_NAMES = [
        "event_count",
        "unique_event_types",
        "unique_regions",
        "high_severity_ratio",
        "unique_targets",
        "off_hours_ratio",
    ]

    def __init__(self, contamination: float = 0.05):
        # DECISION: Use 0.05 to reflect a conservative 5% anomaly rate in baseline.
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def build_feature_vector(self, events: list) -> np.ndarray:
        """Build a six-feature vector from a list of normalized events."""
        if not events:
            return np.zeros(len(self.FEATURE_NAMES))

        total = len(events)
        event_types = set(e.event_type for e in events)
        regions = set(e.target.region for e in events if e.target.region)
        high_sev = sum(1 for e in events if e.severity in ("high", "critical"))
        targets = set(e.target.id for e in events)
        off_hours = sum(
            1 for e in events if e.timestamp.hour < 9 or e.timestamp.hour > 17
        )

        return np.array(
            [
                total,
                len(event_types),
                len(regions),
                high_sev / total,
                len(targets),
                off_hours / total,
            ]
        )

    def train(self, feature_matrix: np.ndarray) -> None:
        """Train the model using benign feature vectors."""
        scaled = self.scaler.fit_transform(feature_matrix)
        self.model.fit(scaled)
        self.is_trained = True
        logger.info("Trained anomaly model on %d samples", len(feature_matrix))

    def score(self, feature_vector: np.ndarray) -> float:
        """Return the Isolation Forest score for a single feature vector."""
        if not self.is_trained:
            return 0.0
        scaled = self.scaler.transform(feature_vector.reshape(1, -1))
        return float(self.model.score_samples(scaled)[0])

    def save(self, path: Path) -> None:
        """Persist the model and scaler to disk."""
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load(self, path: Path) -> None:
        """Load a saved model and scaler from disk."""
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_trained = True
