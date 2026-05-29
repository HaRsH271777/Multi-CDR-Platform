from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ResponseMode(Enum):
    OBSERVE = "observe"
    ALERT = "alert"
    CONTAIN = "contain"
    REMEDIATE = "remediate"


class ResponseOrchestrator:
    def __init__(self, mode: ResponseMode = ResponseMode.OBSERVE):
        self.mode = mode
        assert (
            mode == ResponseMode.OBSERVE
            or (
                logger.warning(
                    "Response mode set to %s — ensure this is intentional", mode.value
                )
                or True
            )
        )
        self.action_log: list[dict] = []

    def handle_detection(self, detection, event) -> None:
        action_record = {
            "detection_id": str(detection.detection_id),
            "event_provider": event.provider,
            "severity": detection.severity,
            "mode": self.mode.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_taken": None,
            "dry_run": self.mode == ResponseMode.OBSERVE,
        }

        if detection.severity not in ("high", "critical"):
            action_record["action_taken"] = "skipped_low_severity"
            self.action_log.append(action_record)
            return

        if self.mode == ResponseMode.OBSERVE:
            action_record["action_taken"] = "dry_run_logged"
            logger.info(
                "[DRY RUN] Would respond to %s on %s for %s",
                detection.rule_id,
                event.provider,
                event.principal.id,
            )
        elif self.mode == ResponseMode.ALERT:
            self._send_alert(detection, event)
            action_record["action_taken"] = "alert_sent"
        elif self.mode == ResponseMode.CONTAIN:
            result = self._execute_containment(detection, event)
            action_record["action_taken"] = result
        else:
            action_record["action_taken"] = "no_action_for_mode"

        self.action_log.append(action_record)

    def _send_alert(self, detection, event) -> None:
        logger.warning(
            "ALERT: %s fired on %s for principal %s",
            detection.rule_id,
            event.provider,
            event.principal.id,
        )

    def _execute_containment(self, detection, event) -> str:
        if event.provider == "aws":
            return self._aws_contain(detection, event)
        if event.provider == "azure":
            return self._azure_contain(detection, event)
        return "no_action_for_provider"

    def _aws_contain(self, detection, event) -> str:
        action = detection.rule_id
        provider = event.provider
        logger.info("[STUB] Would execute %s on %s", action, provider)
        return "stub_executed"

    def _azure_contain(self, detection, event) -> str:
        action = detection.rule_id
        provider = event.provider
        logger.info("[STUB] Would execute %s on %s", action, provider)
        return "stub_executed"
