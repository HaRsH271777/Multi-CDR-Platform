"""Run a synthetic latency benchmark for MC-CDR response orchestration."""

import json
import logging
import sys
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from csnl.normalizers.aws_normalizer import normalize_aws_event
from csnl.normalizers.azure_normalizer import normalize_azure_event
from detection.engine import DetectionEngine
from response.latency_tracker import LatencyRecord, LatencyTracker

logger = logging.getLogger(__name__)


def _aws_event(index: int, timestamp: datetime) -> dict:
    return {
        "EventId": str(uuid.uuid4()),
        "EventName": "ConsoleLogin" if index % 2 == 0 else "GetObject",
        "EventTime": timestamp.isoformat(),
        "userIdentity": {
            "type": "IAMUser",
            "arn": f"arn:aws:iam::123456789:user/user_{index}",
            "userName": f"user_{index}",
            "accountId": "123456789",
        },
        "sourceIPAddress": "10.0.0.1",
        "awsRegion": "us-east-1",
        "resources": [],
    }


def _azure_event(index: int, timestamp: datetime) -> dict:
    operation = (
        "Microsoft.Insights/diagnosticSettings/delete"
        if index % 2 == 0
        else "Microsoft.Authorization/roleAssignments/write"
    )
    return {
        "TimeGenerated": timestamp.isoformat(),
        "Caller": f"user{index}@contoso.com",
        "OperationName": operation,
        "ActivityStatus": "Succeeded",
        "CallerIpAddress": "10.1.0.1",
        "ResourceId": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Insights/diagnosticSettings/test",
        "ResourceGroup": "rg",
    }


def _record_latency(
    tracker: LatencyTracker,
    provider: str,
    detection_id: str,
    event_start: float,
    detection_time: float,
    response_time: float,
) -> None:
    tracker.record(
        LatencyRecord(
            detection_id=detection_id,
            event_timestamp=event_start,
            detection_timestamp=detection_time,
            response_timestamp=response_time,
            provider=provider,
        )
    )


def run_latency_benchmark() -> dict:
    engine = DetectionEngine(Path("detection/rules"))
    tracker = LatencyTracker()
    base_time = datetime(2026, 5, 1, tzinfo=timezone.utc)

    for i in range(500):
        raw_event = _aws_event(i, base_time + timedelta(seconds=i))
        event_start = time.perf_counter()
        normalized = normalize_aws_event(
            raw_event, collected_at=datetime.now(timezone.utc)
        )
        if normalized is None:
            logger.warning("Skipped AWS event %d during normalization", i)
            continue
        engine.process(normalized)
        detection_time = time.perf_counter()
        response_time = time.perf_counter()
        _record_latency(
            tracker,
            normalized.provider,
            str(uuid.uuid4()),
            event_start,
            detection_time,
            response_time,
        )

    for i in range(500):
        raw_event = _azure_event(i, base_time + timedelta(seconds=i))
        event_start = time.perf_counter()
        normalized = normalize_azure_event(
            raw_event, collected_at=datetime.now(timezone.utc)
        )
        if normalized is None:
            logger.warning("Skipped Azure event %d during normalization", i)
            continue
        engine.process(normalized)
        detection_time = time.perf_counter()
        response_time = time.perf_counter()
        _record_latency(
            tracker,
            normalized.provider,
            str(uuid.uuid4()),
            event_start,
            detection_time,
            response_time,
        )

    report = tracker.report()
    output = Path("evaluation/results")
    output.mkdir(parents=True, exist_ok=True)
    output_path = output / "latency_results.json"
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


if __name__ == "__main__":
    run_latency_benchmark()
