import logging
from datetime import datetime, timezone
from pathlib import Path

import pytest

from csnl.schema import NormalizedEvent, Principal, Target
from detection.engine import DetectionEngine

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"


def make_event(
    event_type: str,
    action: str = "other",
    provider: str = "aws",
    is_root: bool = False,
) -> NormalizedEvent:
    now = datetime.now(timezone.utc)
    return NormalizedEvent(
        timestamp=now,
        ingested_at=now,
        ingestion_latency_ms=0,
        provider=provider,
        event_type=event_type,
        severity="info",
        principal=Principal(
            id="principal-1",
            type="user",
            name="tester",
            account_id="123456789",
            is_root=is_root,
        ),
        target=Target(
            id="target-1",
            type="service",
            name="target",
            region="us-east-1",
        ),
        action=action,
        source_ip="1.2.3.4",
        user_agent="test-agent",
        raw_event={"EventId": "evt-1"},
        enrichments={},
    )


def test_engine_loads_all_rules():
    engine = DetectionEngine(RULES_DIR)
    assert len(engine.rules) == 15


def test_delete_trail_triggers_cloudtrail_disabled():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("DeleteTrail", action="delete")
    detections = engine.process(event)
    assert any(d.rule_id == "cloudtrail_disabled" for d in detections)


def test_get_object_is_benign():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("GetObject", action="read")
    detections = engine.process(event)
    assert detections == []


def test_root_login_triggers_root_account_login():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("ConsoleLogin", action="login", is_root=True)
    detections = engine.process(event)
    assert any(d.rule_id == "root_account_login" for d in detections)


def test_root_access_key_created_triggers_rule():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("CreateAccessKey", action="create", is_root=True)
    detections = engine.process(event)
    assert any(d.rule_id == "root_access_key_created" for d in detections)


def test_azure_diagnostic_delete_triggers_rule():
    engine = DetectionEngine(RULES_DIR)
    event = make_event(
        "Microsoft.Insights/diagnosticSettings/delete",
        action="delete",
        provider="azure",
    )
    detections = engine.process(event)
    assert any(d.rule_id == "azure_diagnostic_deleted" for d in detections)


def test_unknown_event_type_triggers_no_rules():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("UnknownEventType")
    detections = engine.process(event)
    assert detections == []


def test_stats_updated_after_processing():
    engine = DetectionEngine(RULES_DIR)
    engine.process(make_event("DeleteTrail", action="delete"))
    engine.process(make_event("GetObject", action="read"))
    assert engine.stats["events_processed"] == 2


def test_malformed_rule_logs_warning_and_skips(tmp_path, caplog):
    good_rule = tmp_path / "good.yml"
    bad_rule = tmp_path / "bad.yml"
    good_rule.write_text(
        "title: Good Rule\n"
        "logsource:\n  product: cloud\n  service: iam\n"
        "detection:\n  selection:\n    event_type: TestEvent\n  condition: selection\n"
        "falsepositives:\n  - Expected behavior\n"
        "level: low\n"
        "tags:\n  - attack.t0000\n  - attack.discovery\n",
        encoding="utf-8",
    )
    bad_rule.write_text("title: [unterminated", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        engine = DetectionEngine(tmp_path)

    assert len(engine.rules) == 1
    assert any("Failed to load rule" in message for message in caplog.messages)


def test_detection_technique_id_matches_rule_tag():
    engine = DetectionEngine(RULES_DIR)
    event = make_event("DeleteTrail", action="delete")
    detections = engine.process(event)
    assert detections
    assert detections[0].technique_id == "T1562.008"
