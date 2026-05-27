from datetime import datetime, timezone

from csnl.normalizers.azure_normalizer import normalize_azure_event

BASE_AZURE_EVENT = {
    "TimeGenerated": "2026-05-27T10:00:00Z",
    "Caller": "user@contoso.com",
    "OperationName": "Microsoft.Insights/diagnosticSettings/delete",
    "ActivityStatus": "Succeeded",
    "CallerIpAddress": "1.2.3.4",
    "ResourceId": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Insights/diagnosticSettings/test",
}


def test_diagnostic_settings_delete_is_critical():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(BASE_AZURE_EVENT, collected)
    assert event is not None
    assert event.severity == "critical"


def test_role_assignment_write_is_high():
    event_copy = BASE_AZURE_EVENT.copy()
    event_copy["OperationName"] = "Microsoft.Authorization/roleAssignments/write"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(event_copy, collected)
    assert event.severity == "high"


def test_key_vault_read_is_medium():
    event_copy = BASE_AZURE_EVENT.copy()
    event_copy["OperationName"] = "Microsoft.KeyVault/vaults/secrets/read"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(event_copy, collected)
    assert event.severity == "medium"


def test_missing_ip_is_handled():
    event_copy = BASE_AZURE_EVENT.copy()
    event_copy.pop("CallerIpAddress", None)
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(event_copy, collected)
    assert event.source_ip is None


def test_unknown_operation_action_defaults_to_other():
    event_copy = BASE_AZURE_EVENT.copy()
    event_copy["OperationName"] = "Microsoft.Unknown/operation"
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(event_copy, collected)
    assert event.action == "other"


def test_raw_event_equals_input_dict():
    input_dict = BASE_AZURE_EVENT.copy()
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(input_dict, collected)
    assert event.raw_event == input_dict


def test_normalization_version_defaulted():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(BASE_AZURE_EVENT, collected)
    assert event.normalization_version == "1.0"


def test_ingestion_latency_is_non_negative_int():
    collected = datetime(2026, 5, 27, 10, 0, 30, tzinfo=timezone.utc)
    event = normalize_azure_event(BASE_AZURE_EVENT, collected)
    assert isinstance(event.ingestion_latency_ms, int)
    assert event.ingestion_latency_ms >= 0
