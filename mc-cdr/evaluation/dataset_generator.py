"""
Synthetic dataset generator for MC-CDR evaluation.

Random seed: 42.
Attack scenarios: privilege_escalation (T1078.004), cloudtrail_tampering (T1562.008),
credential_access (T1555), new_admin_user (T1136), root_login (T1078.004).
This dataset is entirely synthetic.
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)


class AttackScenarioGenerator:
    BENIGN_EVENTS = [
        "GetObject",
        "PutObject",
        "DescribeInstances",
        "ListBuckets",
        "GetUser",
        "ListRoles",
        "ConsoleLogin",
    ]
    REGIONS = ["us-east-1", "us-west-2"]

    def _principal(self, user_id: str, identity_type: str = "IAMUser") -> dict:
        if identity_type == "Root":
            arn = "arn:aws:iam::123456789:root"
        else:
            arn = f"arn:aws:iam::123456789:user/{user_id}"
        return {
            "type": identity_type,
            "arn": arn,
            "userName": user_id,
            "accountId": "123456789",
        }

    def generate_benign_event(self, user_id: str, timestamp: datetime) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": random.choice(self.BENIGN_EVENTS),
            "EventTime": timestamp.isoformat(),
            "label": "benign",
            "scenario": "normal_operations",
            "userIdentity": self._principal(user_id),
            "sourceIPAddress": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            "awsRegion": random.choice(self.REGIONS),
            "resources": [],
        }

    def generate_privilege_escalation_scenario(
        self, attacker_id: str, start_time: datetime
    ) -> list[dict]:
        events = []
        t = start_time

        for event_name, region in [
            ("AttachUserPolicy", "us-east-1"),
            ("CreatePolicy", "us-east-1"),
            ("AttachRolePolicy", "us-east-1"),
            ("GetSecretValue", "us-west-2"),
        ]:
            t += timedelta(seconds=random.randint(30, 120))
            events.append(
                {
                    "EventId": str(uuid.uuid4()),
                    "EventName": event_name,
                    "EventTime": t.isoformat(),
                    "label": "attack",
                    "scenario": "privilege_escalation",
                    "technique": "T1078.004",
                    "userIdentity": self._principal(attacker_id),
                    "sourceIPAddress": "198.51.100.1",
                    "awsRegion": region,
                    "resources": [
                        {
                            "ARN": "arn:aws:iam::123456789:policy/AdminPolicy",
                            "type": "AWS::IAM::Policy",
                        }
                    ],
                }
            )

        return events

    def generate_cloudtrail_tampering_event(
        self, attacker_id: str, timestamp: datetime
    ) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": "StopLogging",
            "EventTime": timestamp.isoformat(),
            "label": "attack",
            "scenario": "cloudtrail_tampering",
            "technique": "T1562.008",
            "userIdentity": self._principal(attacker_id),
            "sourceIPAddress": "198.51.100.2",
            "awsRegion": random.choice(self.REGIONS),
            "resources": [],
        }

    def generate_credential_access_event(
        self, attacker_id: str, timestamp: datetime
    ) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": "GetSecretValue",
            "EventTime": timestamp.isoformat(),
            "label": "attack",
            "scenario": "credential_access",
            "technique": "T1555",
            "userIdentity": self._principal(attacker_id),
            "sourceIPAddress": "198.51.100.3",
            "awsRegion": random.choice(self.REGIONS),
            "resources": [
                {
                    "ARN": "arn:aws:secretsmanager:us-east-1:123456789:secret:test",
                    "type": "AWS::SecretsManager::Secret",
                }
            ],
        }

    def generate_new_admin_user_event(self, attacker_id: str, timestamp: datetime) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": "CreateUser",
            "EventTime": timestamp.isoformat(),
            "label": "attack",
            "scenario": "new_admin_user",
            "technique": "T1136",
            "userIdentity": self._principal(attacker_id),
            "sourceIPAddress": "198.51.100.4",
            "awsRegion": random.choice(self.REGIONS),
            "resources": [
                {
                    "ARN": f"arn:aws:iam::123456789:user/{attacker_id}",
                    "type": "AWS::IAM::User",
                }
            ],
        }

    def generate_root_login_event(self, timestamp: datetime) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": "ConsoleLogin",
            "EventTime": timestamp.isoformat(),
            "label": "attack",
            "scenario": "root_login",
            "technique": "T1078.004",
            "userIdentity": self._principal("root", identity_type="Root"),
            "sourceIPAddress": "198.51.100.5",
            "awsRegion": random.choice(self.REGIONS),
            "resources": [],
        }

    def generate_dataset(
        self,
        n_benign: int = 10000,
        n_attack_scenarios: int = 100,
        output_path: Path = Path("evaluation/data/dataset.jsonl"),
    ) -> dict:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        all_events: list[dict] = []
        start = datetime(2026, 5, 1, tzinfo=timezone.utc)

        users = [f"user_{i}" for i in range(20)]
        for _ in range(n_benign):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_benign_event(random.choice(users), ts))

        for i in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.extend(self.generate_privilege_escalation_scenario(f"attacker_{i}", ts))

        for i in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_cloudtrail_tampering_event(f"attacker_{i}", ts))

        for i in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_credential_access_event(f"attacker_{i}", ts))

        for i in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_new_admin_user_event(f"attacker_{i}", ts))

        for _ in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_root_login_event(ts))

        all_events.sort(key=lambda e: e["EventTime"])
        subset = all_events[:100]
        random.shuffle(subset)
        all_events[:100] = subset

        with open(output_path, "w", encoding="utf-8") as handle:
            for event in all_events:
                handle.write(json.dumps(event) + "\n")

        stats = {
            "total_events": len(all_events),
            "benign_count": sum(1 for e in all_events if e["label"] == "benign"),
            "attack_count": sum(1 for e in all_events if e["label"] == "attack"),
            "attack_chains": n_attack_scenarios * 5,
            "scenarios": sorted(
                set(e["scenario"] for e in all_events if e["label"] == "attack")
            ),
            "random_seed": 42,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

        stats_path = output_path.parent / "dataset_stats.json"
        stats_path.write_text(json.dumps(stats, indent=2), encoding="utf-8")
        return stats


if __name__ == "__main__":
    generator = AttackScenarioGenerator()
    generator.generate_dataset()
