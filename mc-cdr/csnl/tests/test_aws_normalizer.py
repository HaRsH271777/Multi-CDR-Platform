from datetime import datetime, timezone

import pytest

from csnl.normalizers.aws_normalizer import normalize_aws_event

SAMPLE_CLOUDTRAIL_EVENT = {
    "EventId": "test-123",
    "EventName": "DeleteTrail",
    "EventTime": "2026-05-27T10:00:00Z",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789:user/attacker",
        "userName": "attacker",
        "accountId": "123456789",
    },
    "sourceIPAddress": "1.2.3.4",
    "userAgent": "aws-cli/2.0",
    "awsRegion": "us-east-1",
    "resources": [],
}


def test_delete_trail_is_critical():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(SAMPLE_CLOUDTRAIL_EVENT, collected)
    assert event is not None
    assert event.severity == "critical"
    assert event.action == "delete"


def test_ingestion_latency_measured():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(SAMPLE_CLOUDTRAIL_EVENT, collected)
    assert event.ingestion_latency_ms == 30000  # 30 seconds


def test_raw_event_preserved():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(SAMPLE_CLOUDTRAIL_EVENT, collected)
    assert event.raw_event["EventName"] == "DeleteTrail"


def test_invalid_ip_handled_gracefully():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["sourceIPAddress"] = "AWS Internal"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.source_ip is None  # not a crash


def test_root_account_is_detected():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["userIdentity"] = {"type": "Root"}
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.principal.is_root is True


def test_missing_ip_is_handled():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy.pop("sourceIPAddress", None)
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.source_ip is None


def test_unknown_event_action_defaults_to_other():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["EventName"] = "SomeUnknownAction"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.action == "other"


def test_console_login_is_low_severity():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["EventName"] = "ConsoleLogin"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.severity == "low"


def test_create_access_key_is_medium_severity():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["EventName"] = "CreateAccessKey"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.severity == "medium"


def test_attach_user_policy_is_high_severity():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["EventName"] = "AttachUserPolicy"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.severity == "high"


def test_private_ip_enrichment_true():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["sourceIPAddress"] = "10.0.0.1"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.enrichments["is_private_ip"] is True


def test_public_ip_enrichment_false():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["sourceIPAddress"] = "8.8.8.8"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.enrichments["is_private_ip"] is False


def test_off_hours_enrichment_true():
    event_copy = SAMPLE_CLOUDTRAIL_EVENT.copy()
    event_copy["EventTime"] = "2026-05-27T02:00:00Z"
    collected = datetime(2026, 5, 27, 2, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(event_copy, collected)
    assert event.enrichments["is_off_hours"] is True


def test_raw_event_equals_input_dict():
    input_dict = SAMPLE_CLOUDTRAIL_EVENT.copy()
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_aws_event(input_dict, collected)
    assert event.raw_event == input_dict
