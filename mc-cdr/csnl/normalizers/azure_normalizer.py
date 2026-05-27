from datetime import datetime, timezone
import logging

from csnl.enrichment import enrich
from csnl.schema import NormalizedEvent, Principal, Target

logger = logging.getLogger(__name__)

AZURE_ACTION_MAP = {
    "Microsoft.Compute/virtualMachines/write": "create",
    "Microsoft.Compute/virtualMachines/delete": "delete",
    "Microsoft.Compute/virtualMachines/read": "read",
    "Microsoft.Storage/storageAccounts/write": "create",
    "Microsoft.Storage/storageAccounts/delete": "delete",
    "Microsoft.Authorization/roleAssignments/write": "create",
    "Microsoft.Authorization/roleAssignments/delete": "delete",
    "Microsoft.KeyVault/vaults/secrets/read": "read",
    "Microsoft.AAD/users/write": "update",
    "Microsoft.AAD/users/delete": "delete",
    "Microsoft.Network/networkSecurityGroups/write": "update",
    "Microsoft.Insights/diagnosticSettings/delete": "delete",
}

AZURE_SEVERITY_RULES = [
    ({"Microsoft.Insights/diagnosticSettings/delete"}, "critical"),
    (
        {
            "Microsoft.Authorization/roleAssignments/write",
            "Microsoft.AAD/users/write",
            "Microsoft.AAD/users/delete",
        },
        "high",
    ),
    ({"Microsoft.KeyVault/vaults/secrets/read"}, "medium"),
    (
        {
            "Microsoft.Compute/virtualMachines/read",
            "Microsoft.Storage/storageAccounts/read",
        },
        "low",
    ),
]


def _infer_target_type(operation_name: str) -> str:
    parts = operation_name.split("/")
    if len(parts) >= 2:
        return parts[1].lower()
    return "resource"


def normalize_azure_event(raw: dict, collected_at: datetime) -> NormalizedEvent | None:
    try:
        event_time_raw = raw.get("TimeGenerated", "")
        event_time = datetime.fromisoformat(str(event_time_raw).replace("Z", "+00:00"))
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        operation_name = raw.get("OperationName", "unknown")
        latency_ms = int((collected_at - event_time).total_seconds() * 1000)

        caller = raw.get("Caller")
        principal = Principal(
            id=caller or "unknown",
            type="user",
            name=caller,
        )

        target = Target(
            id=raw.get("ResourceId", operation_name),
            type=_infer_target_type(operation_name),
            name=raw.get("ResourceGroup"),
        )

        severity = "info"
        operation_lower = str(operation_name).lower()
        for event_set, sev in AZURE_SEVERITY_RULES:
            if operation_name in event_set:
                severity = sev
                break
        if "delete" in operation_lower and "log" in operation_lower:
            severity = "critical"

        event = NormalizedEvent(
            timestamp=event_time,
            ingested_at=collected_at,
            ingestion_latency_ms=max(0, latency_ms),
            provider="azure",
            event_type=operation_name,
            severity=severity,
            principal=principal,
            target=target,
            action=AZURE_ACTION_MAP.get(operation_name, "other"),
            source_ip=raw.get("CallerIpAddress"),
            user_agent=raw.get("UserAgent"),
            raw_event=raw,
        )
        return enrich(event)

    except Exception as e:
        logger.error(
            f"Normalization failed for event {raw.get('OperationName', 'unknown')}: {e}"
        )
        return None
