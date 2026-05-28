from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from detection.anomaly.isolation_forest import EntityBehaviorModel


@dataclass
class DummyTarget:
    id: str
    region: str | None


@dataclass
class DummyEvent:
    event_type: str
    severity: str
    target: DummyTarget
    timestamp: datetime


def build_training_matrix(seed: int = 42) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(loc=1.0, scale=0.2, size=(50, 6))


def test_train_on_benign_vectors():
    model = EntityBehaviorModel()
    feature_matrix = build_training_matrix()
    model.train(feature_matrix)


def test_is_trained_after_train():
    model = EntityBehaviorModel()
    model.train(build_training_matrix())
    assert model.is_trained is True


def test_anomalous_scores_lower():
    model = EntityBehaviorModel()
    matrix = build_training_matrix()
    model.train(matrix)

    normal_vector = matrix[0]
    anomalous_vector = matrix.mean(axis=0) * 10

    normal_score = model.score(normal_vector)
    anomalous_score = model.score(anomalous_vector)

    assert anomalous_score < normal_score


def test_save_and_load_round_trip(tmp_path):
    model = EntityBehaviorModel()
    matrix = build_training_matrix()
    model.train(matrix)

    test_vector = matrix[1]
    original_score = model.score(test_vector)

    path = Path(tmp_path) / "model.joblib"
    model.save(path)

    reloaded = EntityBehaviorModel()
    reloaded.load(path)
    reloaded_score = reloaded.score(test_vector)

    assert abs(original_score - reloaded_score) < 1e-6


def test_score_before_train_returns_zero():
    model = EntityBehaviorModel()
    score = model.score(np.ones(6))
    assert score == 0.0


def test_build_feature_vector_with_events():
    model = EntityBehaviorModel()
    events = [
        DummyEvent(
            event_type="CreateUser",
            severity="high",
            target=DummyTarget(id="t1", region="us-east-1"),
            timestamp=datetime(2026, 5, 1, 2, 0, tzinfo=timezone.utc),
        ),
        DummyEvent(
            event_type="CreateUser",
            severity="low",
            target=DummyTarget(id="t2", region=None),
            timestamp=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        ),
    ]

    vector = model.build_feature_vector(events)

    assert vector.shape == (6,)
    assert vector[0] == 2
    assert vector[1] == 1
    assert vector[2] == 1
    assert vector[3] == 0.5
    assert vector[4] == 2
    assert vector[5] == 0.5


def test_build_feature_vector_empty_list():
    model = EntityBehaviorModel()
    vector = model.build_feature_vector([])
    assert vector.shape == (6,)
    assert np.allclose(vector, np.zeros(6))
