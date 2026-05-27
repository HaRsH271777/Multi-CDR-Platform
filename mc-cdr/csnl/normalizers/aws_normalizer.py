from datetime import datetime, timezone
import logging

from csnl.enrichment import enrich
from csnl.schema import NormalizedEvent, Principal, Target

logger = logging.getLogger(__name__)

# Explicit action mapping — document every decision here.
# When an interviewer asks "how do you handle PutBucketPolicy?", you point here.
AWS_ACTION_MAP = {
    "PutBucketPolicy": "update",
    "DeleteBucketPolicy": "delete",
    "CreateBucket": "create",
    "GetObject": "read",
    "PutObject": "create",
    "DeleteObject": "delete",
    "ConsoleLogin": "login",
    "AssumeRole": "login",
    "CreateUser": "create",
    "DeleteUser": "delete",
    "AttachUserPolicy": "update",
    "PutUserPolicy": "update",
    "CreateAccessKey": "create",
    "DeleteAccessKey": "delete",
    "CreatePolicy": "create",
    "DeletePolicy": "delete",
    "PutRolePolicy": "update",
    "AttachRolePolicy": "update",
    "RunInstances": "create",
    "TerminateInstances": "delete",
    "AuthorizeSecurityGroupIngress": "update",
    "ModifyInstanceAttribute": "update",
    "StartLogging": "update",
    "StopLogging": "update",  # high severity: tampering
    "DeleteTrail": "delete",  # critical: log destruction
    "GetSecretValue": "read",
    "CreateSecret": "create",
    "CreateVpc": "create",  # VPC creation
    "DeleteVpc": "delete",  # VPC deletion
    "CreateSubnet": "create",  # Subnet creation
    "ModifyNetworkInterfaceAttribute": "update",  # Network interface change
    "CreateSecurityGroup": "create",  # Security group creation
    "DeleteSecurityGroup": "delete",  # Security group deletion
    "PutBucketAcl": "update",  # Bucket ACL change
    "GetCallerIdentity": "read",  # Caller identity lookup
    "ListAccessKeys": "read",  # Access key listing
    "UpdateAccessKey": "update",  # Access key update
}

# Severity rules — explicit and testable
AWS_SEVERITY_RULES = [
    ({"DeleteTrail", "StopLogging", "UpdateTrail"}, "critical"),
    (
        {
            "CreateUser",
            "AttachUserPolicy",
            "PutUserPolicy",
            "PutRolePolicy",
            "AttachRolePolicy",
            "CreatePolicy",
        },
        "high",
    ),
    ({"AssumeRole", "CreateAccessKey", "GetSecretValue"}, "medium"),
    ({"ConsoleLogin"}, "low"),
]


def normalize_aws_event(raw: dict, collected_at: datetime) -> NormalizedEvent | None:
    try:
        event_time = datetime.fromisoformat(
            raw.get("EventTime", raw.get("eventTime", "")).replace("Z", "+00:00")
        )
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        event_name = raw.get("EventName", raw.get("eventName", "unknown"))
        latency_ms = int((collected_at - event_time).total_seconds() * 1000)

        # Extract principal
        user_identity = raw.get("userIdentity", {})
        principal = Principal(
            id=user_identity.get("arn", user_identity.get("principalId", "unknown")),
            type=user_identity.get("type", "unknown").lower(),
            name=user_identity.get("userName"),
            account_id=user_identity.get("accountId"),
            is_root=user_identity.get("type") == "Root",
        )

        # Extract target
        resources = raw.get("resources", [])
        if resources:
            r = resources[0]
            target = Target(
                id=r.get("ARN", "unknown"),
                type=r.get("type", "unknown").replace("AWS::", "").lower(),
                arn=r.get("ARN"),
                region=raw.get("awsRegion"),
            )
        else:
            target = Target(
                id=raw.get("eventSource", "unknown"),
                type="service",
                region=raw.get("awsRegion"),
            )

        # Severity
        severity = "info"
        for event_set, sev in AWS_SEVERITY_RULES:
            if event_name in event_set:
                severity = sev
                break

        event = NormalizedEvent(
            timestamp=event_time,
            ingested_at=collected_at,
            ingestion_latency_ms=max(0, latency_ms),
            provider="aws",
            event_type=event_name,
            severity=severity,
            principal=principal,
            target=target,
            action=AWS_ACTION_MAP.get(event_name, "other"),
            source_ip=raw.get("sourceIPAddress"),
            user_agent=raw.get("userAgent"),
            raw_event=raw,
        )
        return enrich(event)

    except Exception as e:
        logger.error(
            f"Normalization failed for event {raw.get('EventId', 'unknown')}: {e}"
        )
        return None
