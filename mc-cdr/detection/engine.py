import logging
from pathlib import Path

import yaml

from csnl.schema import NormalizedEvent
from detection.models import Detection

logger = logging.getLogger(__name__)


class DetectionRule:
    def __init__(self, rule_path: Path):
        with open(rule_path, "r", encoding="utf-8") as handle:
            self.config = yaml.safe_load(handle)
        self.rule_id = rule_path.stem
        self.title = self.config["title"]
        self.severity = self.config["level"]
        self.technique = self.config["tags"][0].replace("attack.", "").upper()
        self.tactic = (
            self.config["tags"][1].replace("attack.", "")
            if len(self.config["tags"]) > 1
            else "unknown"
        )

    def matches(self, event: NormalizedEvent) -> bool:
        """Return True when all selection fields match the event."""
        selection = self.config["detection"]["selection"]
        for field, expected in selection.items():
            actual = self._get_field(event, field)
            if isinstance(expected, list):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True

    def _get_field(self, event: NormalizedEvent, field: str):
        """Resolve dot-notation field names against a NormalizedEvent."""
        parts = field.split(".")
        obj = event.model_dump()
        for part in parts:
            if isinstance(obj, dict):
                obj = obj.get(part)
            else:
                return None
        return obj


class DetectionEngine:
    def __init__(self, rules_dir: Path):
        self.rules: list[DetectionRule] = []
        self.stats = {
            "events_processed": 0,
            "detections_raised": 0,
            "rule_hits": {},
        }
        self._load_rules(rules_dir)
        logger.info("Loaded %d detection rules", len(self.rules))

    def _load_rules(self, rules_dir: Path) -> None:
        """Load Sigma-style rule definitions from a directory."""
        for rule_file in rules_dir.glob("*.yml"):
            try:
                rule = DetectionRule(rule_file)
                self.rules.append(rule)
                self.stats["rule_hits"][rule.rule_id] = 0
            except Exception as exc:
                logger.warning("Failed to load rule %s: %s", rule_file, exc)

    def process(self, event: NormalizedEvent) -> list[Detection]:
        """Evaluate an event against all rules and return detections."""
        self.stats["events_processed"] += 1
        detections: list[Detection] = []

        for rule in self.rules:
            try:
                if rule.matches(event):
                    detection = Detection(
                        event_id=event.event_id,
                        rule_id=rule.rule_id,
                        technique_id=rule.technique,
                        tactic=rule.tactic,
                        severity=rule.severity,
                        confidence=1.0,
                        details={
                            "rule_title": rule.title,
                            "matched_event_type": event.event_type,
                            "provider": event.provider,
                        },
                    )
                    detections.append(detection)
                    self.stats["detections_raised"] += 1
                    self.stats["rule_hits"][rule.rule_id] += 1
            except Exception as exc:
                logger.error("Rule %s evaluation error: %s", rule.rule_id, exc)

        return detections
