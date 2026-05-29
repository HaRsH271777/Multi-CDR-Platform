import logging
from datetime import datetime, timezone
from unittest import mock

from csnl.schema import NormalizedEvent, Principal, Target
from detection.models import Detection
from response.orchestrator import ResponseMode, ResponseOrchestrator


def _make_event(provider: str = "aws") -> NormalizedEvent:
    timestamp = datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc)
    return NormalizedEvent(
        timestamp=timestamp,
        ingested_at=timestamp,
        ingestion_latency_ms=0,
        provider=provider,
        event_type="ConsoleLogin",
        severity="high",
        principal=Principal(
            id="arn:aws:iam::123456789:user/test-user",
            type="user",
            name="test-user",
            account_id="123456789",
            is_root=False,
        ),
        target=Target(
            id="signin.amazonaws.com",
            type="service",
            region="us-east-1",
            arn=None,
        ),
        action="login",
        source_ip="1.2.3.4",
        user_agent="pytest",
        raw_event={},
    )


def _make_detection(event_id, severity: str = "high") -> Detection:
    return Detection(
        event_id=event_id,
        rule_id="test_rule",
        technique_id="T0000",
        tactic="initial-access",
        severity=severity,
        confidence=1.0,
    )


def test_default_mode_is_observe():
    orchestrator = ResponseOrchestrator()
    assert orchestrator.mode == ResponseMode.OBSERVE


def test_observe_mode_appends_dry_run_record():
    orchestrator = ResponseOrchestrator()
    event = _make_event()
    detection = _make_detection(event.event_id, severity="high")

    orchestrator.handle_detection(detection, event)

    assert len(orchestrator.action_log) == 1
    assert orchestrator.action_log[0]["dry_run"] is True


def test_observe_mode_does_not_call_actions():
    orchestrator = ResponseOrchestrator()
    event = _make_event()
    detection = _make_detection(event.event_id, severity="high")

    with mock.patch.object(orchestrator, "_send_alert") as send_alert, mock.patch.object(
        orchestrator, "_execute_containment"
    ) as execute_containment, mock.patch.object(
        orchestrator, "_aws_contain"
    ) as aws_contain, mock.patch.object(
        orchestrator, "_azure_contain"
    ) as azure_contain:
        orchestrator.handle_detection(detection, event)

    send_alert.assert_not_called()
    execute_containment.assert_not_called()
    aws_contain.assert_not_called()
    azure_contain.assert_not_called()


def test_low_severity_detection_is_skipped():
    orchestrator = ResponseOrchestrator()
    event = _make_event()
    detection = _make_detection(event.event_id, severity="low")

    orchestrator.handle_detection(detection, event)

    assert orchestrator.action_log[0]["action_taken"] == "skipped_low_severity"


def test_alert_mode_calls_send_alert():
    orchestrator = ResponseOrchestrator(mode=ResponseMode.ALERT)
    event = _make_event()
    detection = _make_detection(event.event_id, severity="high")

    with mock.patch.object(orchestrator, "_send_alert") as send_alert:
        orchestrator.handle_detection(detection, event)

    send_alert.assert_called_once()


def test_contain_mode_calls_execute_containment():
    orchestrator = ResponseOrchestrator(mode=ResponseMode.CONTAIN)
    event = _make_event()
    detection = _make_detection(event.event_id, severity="high")

    with mock.patch.object(
        orchestrator, "_execute_containment", return_value="contained"
    ) as execute_containment:
        orchestrator.handle_detection(detection, event)

    execute_containment.assert_called_once()


def test_action_log_length_after_three_detections():
    orchestrator = ResponseOrchestrator()
    event = _make_event()

    for _ in range(3):
        detection = _make_detection(event.event_id, severity="high")
        orchestrator.handle_detection(detection, event)

    assert len(orchestrator.action_log) == 3


def test_contain_mode_logs_warning_on_init(caplog):
    caplog.set_level(logging.WARNING)
    ResponseOrchestrator(mode=ResponseMode.CONTAIN)

    assert any(
        "Response mode set to contain — ensure this is intentional" in record.message
        for record in caplog.records
    )
