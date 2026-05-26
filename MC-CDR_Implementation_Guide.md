# MC-CDR: Multi-Cloud Detection and Response Platform
## Honest Implementation Guide

> **How to use this guide:** The original research proposal presents polished metrics as targets, not measured results. This guide tells you *exactly* what to build, *in what order*, and *how to measure results honestly* — so every number you put on your resume can be defended in an interview.

---

## Table of Contents

1. [Reality Check: Scope Calibration](#1-reality-check-scope-calibration)
2. [Prerequisites](#2-prerequisites)
3. [Phase 0: Infrastructure Setup](#3-phase-0-infrastructure-setup)
4. [Phase 1: Ingestion Layer](#4-phase-1-ingestion-layer)
5. [Phase 2: Cloud Security Normalization Layer (CSNL)](#5-phase-2-cloud-security-normalization-layer-csnl)
6. [Phase 3: Detection Engine](#6-phase-3-detection-engine)
7. [Phase 4: Response Orchestration](#7-phase-4-response-orchestration)
8. [Phase 5: Evaluation Framework (The Honest Part)](#8-phase-5-evaluation-framework-the-honest-part)
9. [Addressing the Paper's Loopholes](#9-addressing-the-papers-loopholes)
10. [Resume Framing by Build Stage](#10-resume-framing-by-build-stage)
11. [Interview Defense Cheatsheet](#11-interview-defense-cheatsheet)

---

## 1. Reality Check: Scope Calibration

Before writing a single line of code, decide which build tier you are targeting. Be honest with yourself — a partially built but deeply understood system is worth more than a fully cloned repo you cannot explain.

### Tier 1 — Solo Developer (3–4 months, strong portfolio)

Build:
- AWS only (CloudTrail logs)
- CSNL normalization pipeline
- 10–15 detection rules (not 47)
- Manual or semi-automated response (not full playbook engine)
- SQLite or Postgres for storage (no Kafka/TimescaleDB yet)

Honest resume line: *"Designed and implemented a cloud detection pipeline ingesting AWS CloudTrail logs through a custom normalization layer with 12 production-grade detection rules mapped to MITRE ATT&CK."*

### Tier 2 — Team or Extended Solo (6–9 months, strong project)

Build everything in Tier 1, plus:
- Azure integration
- Kafka buffering
- Anomaly detection with Isolation Forest
- Automated response for 2–3 action types
- TimescaleDB for time-series storage

### Tier 3 — Full Paper Implementation (12+ months, research-grade)

All three cloud providers, full ML pipeline, cross-cloud correlation, complete response playbook engine, reproducible evaluation dataset.

> **Recommendation for most developers:** Start at Tier 1, build it well, measure everything, and incrementally add Tier 2 components. A tight Tier 1 with honest benchmarks beats a vague Tier 3 claim every time.

---

## 2. Prerequisites

### Accounts and Access

```
AWS:     Free tier account — enable CloudTrail in all regions
Azure:   Free tier — enable Activity Logs and Diagnostic Settings
GCP:     Free tier — enable Cloud Audit Logs
```

**Critical note on permissions:** The paper says "least-privilege service accounts." Define these upfront. Create a dedicated IAM role for MC-CDR with only read access to logs and specific write access for response actions. Document every permission — this becomes a talking point in interviews.

```
AWS IAM permissions required (read):
- cloudtrail:LookupEvents
- cloudtrail:GetTrailStatus
- s3:GetObject (CloudTrail bucket only)
- iam:GetUser, iam:ListUsers (for entity enrichment)

AWS IAM permissions required (response):
- ec2:ModifyInstanceAttribute (SG changes)
- iam:DeleteAccessKey (key revocation)
- wafv2:UpdateWebACL (IP blocking)
```

### Local Development Stack

```bash
# Required
Python 3.11+
Go 1.22+
Docker + Docker Compose
PostgreSQL 15+ (or TimescaleDB)
Node.js 20+ (for dashboard)

# Optional for Tier 2+
Apache Kafka 3.6+
Kubernetes (minikube for local dev)
Terraform 1.7+
```

### Python Dependencies

```bash
pip install \
  boto3 \                  # AWS SDK
  azure-monitor-query \    # Azure logs
  google-cloud-logging \   # GCP logs
  pydantic \               # Schema validation
  sqlalchemy \             # ORM
  scikit-learn \           # Anomaly detection
  pandas \                 # Data manipulation
  fastapi \                # API gateway
  uvicorn \                # ASGI server
  pytest \                 # Testing
  faker                    # Synthetic log generation (for your dataset)
```

---

## 3. Phase 0: Infrastructure Setup

### 3.1 Repository Structure

```
mc-cdr/
├── ingestion/
│   ├── aws/
│   │   ├── cloudtrail_collector.go
│   │   └── s3_reader.go
│   ├── azure/
│   │   └── activity_log_collector.py
│   └── gcp/
│       └── audit_log_collector.py
├── csnl/
│   ├── normalizer.py
│   ├── enrichment.py
│   ├── schema.py
│   └── tests/
├── detection/
│   ├── engine.py
│   ├── rules/
│   │   ├── iam_privilege_escalation.yml
│   │   ├── impossible_travel.yml
│   │   └── ... (your actual rules)
│   ├── anomaly/
│   │   └── isolation_forest.py
│   └── tests/
├── response/
│   ├── orchestrator.py
│   ├── actions/
│   │   ├── aws_actions.py
│   │   └── azure_actions.py
│   └── playbooks/
├── storage/
│   ├── models.py
│   └── migrations/
├── api/
│   └── main.py
├── evaluation/
│   ├── dataset_generator.py    ← critical: your honest dataset
│   ├── benchmarks.py
│   └── results/                ← commit your actual results here
├── docker-compose.yml
├── terraform/
└── README.md
```

### 3.2 Database Schema

Use TimescaleDB (or plain Postgres to start). The paper's CSNL schema is solid — implement it verbatim but add one field the paper omits: `ingestion_latency_ms`. This lets you actually measure your pipeline delay.

```sql
CREATE EXTENSION IF NOT EXISTS timescaledb;

CREATE TABLE normalized_events (
    event_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp       TIMESTAMPTZ NOT NULL,
    ingested_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ingestion_latency_ms INTEGER,          -- paper omits this; you need it
    provider        TEXT NOT NULL CHECK (provider IN ('aws', 'azure', 'gcp')),
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
    principal       JSONB NOT NULL,
    target          JSONB NOT NULL,
    action          TEXT NOT NULL,
    source_ip       INET,
    user_agent      TEXT,
    raw_event       JSONB NOT NULL,
    enrichments     JSONB DEFAULT '{}'
);

SELECT create_hypertable('normalized_events', 'timestamp');
CREATE INDEX ON normalized_events (provider, timestamp DESC);
CREATE INDEX ON normalized_events USING GIN (principal);

CREATE TABLE detections (
    detection_id    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id        UUID REFERENCES normalized_events(event_id),
    detected_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    rule_id         TEXT NOT NULL,
    technique_id    TEXT NOT NULL,  -- e.g. T1078.004
    tactic          TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      FLOAT NOT NULL,
    details         JSONB,
    status          TEXT DEFAULT 'open'
);

CREATE TABLE response_actions (
    action_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    detection_id    UUID REFERENCES detections(detection_id),
    action_type     TEXT NOT NULL,
    provider        TEXT NOT NULL,
    target_resource TEXT NOT NULL,
    initiated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    status          TEXT NOT NULL,
    result          JSONB,
    latency_ms      INTEGER         -- measure this; paper claims sub-30s
);
```

---

## 4. Phase 1: Ingestion Layer

### 4.1 AWS CloudTrail Collector

The paper uses Go for ingestion — good choice for throughput. Here is a production-grade starting point:

```go
// ingestion/aws/cloudtrail_collector.go
package aws

import (
    "context"
    "encoding/json"
    "log"
    "time"

    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail"
    "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
)

type CloudTrailCollector struct {
    client    *cloudtrail.Client
    eventChan chan<- RawEvent
    metrics   *CollectorMetrics
}

type CollectorMetrics struct {
    EventsCollected  int64
    ErrorCount       int64
    LastPollTime     time.Time
    AvgLatencyMs     float64
}

type RawEvent struct {
    Provider    string          `json:"provider"`
    CollectedAt time.Time       `json:"collected_at"`
    RawPayload  json.RawMessage `json:"raw_payload"`
}

func NewCollector(ctx context.Context, eventChan chan<- RawEvent) (*CloudTrailCollector, error) {
    cfg, err := config.LoadDefaultConfig(ctx)
    if err != nil {
        return nil, err
    }
    return &CloudTrailCollector{
        client:    cloudtrail.NewFromConfig(cfg),
        eventChan: eventChan,
        metrics:   &CollectorMetrics{},
    }, nil
}

func (c *CloudTrailCollector) Poll(ctx context.Context, interval time.Duration) {
    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    startTime := time.Now().Add(-interval)

    for {
        select {
        case <-ticker.C:
            endTime := time.Now()
            c.collectEvents(ctx, startTime, endTime)
            startTime = endTime
            c.metrics.LastPollTime = endTime
        case <-ctx.Done():
            log.Println("Collector shutting down")
            return
        }
    }
}

func (c *CloudTrailCollector) collectEvents(ctx context.Context, start, end time.Time) {
    input := &cloudtrail.LookupEventsInput{
        StartTime: &start,
        EndTime:   &end,
    }
    paginator := cloudtrail.NewLookupEventsPaginator(c.client, input)

    for paginator.HasMorePages() {
        page, err := paginator.NextPage(ctx)
        if err != nil {
            c.metrics.ErrorCount++
            log.Printf("Error fetching CloudTrail events: %v", err)
            continue
        }
        for _, event := range page.Events {
            c.processEvent(event)
        }
    }
}

func (c *CloudTrailCollector) processEvent(event types.Event) {
    payload, err := json.Marshal(event)
    if err != nil {
        return
    }
    c.eventChan <- RawEvent{
        Provider:    "aws",
        CollectedAt: time.Now(),
        RawPayload:  payload,
    }
    c.metrics.EventsCollected++
}
```

> **Honest measurement tip:** Log `CollectedAt - event.EventTime` for every event. This gives you the real ingestion latency. The paper claims 1–5 minutes of inherent cloud delivery delay — verify this yourself and report the actual number.

### 4.2 Azure Activity Log Collector

```python
# ingestion/azure/activity_log_collector.py
from azure.monitor.query import LogsQueryClient
from azure.identity import DefaultAzureCredential
from datetime import datetime, timedelta, timezone
import json
import logging

logger = logging.getLogger(__name__)

class AzureActivityLogCollector:
    def __init__(self, workspace_id: str, event_queue):
        self.credential = DefaultAzureCredential()
        self.client = LogsQueryClient(self.credential)
        self.workspace_id = workspace_id
        self.event_queue = event_queue
        self.metrics = {
            "events_collected": 0,
            "errors": 0,
            "last_poll": None
        }

    def poll(self, lookback_minutes: int = 5):
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=lookback_minutes)

        query = """
        AzureActivity
        | where TimeGenerated between (datetime({start}) .. datetime({end}))
        | project TimeGenerated, Caller, OperationName, ResourceGroup,
                  ResourceId, ActivityStatus, Properties, CallerIpAddress
        """.format(
            start=start_time.isoformat(),
            end=end_time.isoformat()
        )

        try:
            response = self.client.query_workspace(
                workspace_id=self.workspace_id,
                query=query,
                timespan=timedelta(minutes=lookback_minutes)
            )
            for table in response.tables:
                for row in table.rows:
                    event = dict(zip(table.columns, row))
                    self.event_queue.put({
                        "provider": "azure",
                        "collected_at": datetime.now(timezone.utc).isoformat(),
                        "raw_payload": event
                    })
                    self.metrics["events_collected"] += 1
            self.metrics["last_poll"] = end_time.isoformat()

        except Exception as e:
            self.metrics["errors"] += 1
            logger.error(f"Azure collection error: {e}")
```

---

## 5. Phase 2: Cloud Security Normalization Layer (CSNL)

This is the most important component — it is what makes the whole platform work. Build it first, test it exhaustively, and document your mapping decisions. These decisions become your interview talking points.

### 5.1 Pydantic Schema (Replaces the paper's pseudocode)

```python
# csnl/schema.py
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Literal, Any
from datetime import datetime
from uuid import UUID, uuid4
import ipaddress

ProviderType = Literal["aws", "azure", "gcp"]
SeverityType = Literal["info", "low", "medium", "high", "critical"]
ActionType   = Literal["create", "read", "update", "delete", "login", "other"]

class Principal(BaseModel):
    id: str
    type: str                    # user | role | service_account | api_key
    name: Optional[str] = None
    account_id: Optional[str] = None
    is_root: bool = False

class Target(BaseModel):
    id: str
    type: str                    # ec2_instance | iam_policy | storage_bucket ...
    name: Optional[str] = None
    region: Optional[str] = None
    arn: Optional[str] = None    # AWS only; stored here for forensics

class NormalizedEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime
    ingestion_latency_ms: int    # always measure this
    provider: ProviderType
    event_type: str
    severity: SeverityType
    principal: Principal
    target: Target
    action: ActionType
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    raw_event: dict              # original log, immutable
    enrichments: dict = Field(default_factory=dict)

    @field_validator("source_ip")
    @classmethod
    def validate_ip(cls, v):
        if v:
            try:
                ipaddress.ip_address(v)
            except ValueError:
                return None
        return v
```

### 5.2 AWS Normalizer

```python
# csnl/normalizers/aws_normalizer.py
from datetime import datetime, timezone
from csnl.schema import NormalizedEvent, Principal, Target
import logging

logger = logging.getLogger(__name__)

# Explicit action mapping — document every decision here.
# When an interviewer asks "how do you handle PutBucketPolicy?", you point here.
AWS_ACTION_MAP = {
    "PutBucketPolicy":          "update",
    "DeleteBucketPolicy":       "delete",
    "CreateBucket":             "create",
    "GetObject":                "read",
    "PutObject":                "create",
    "DeleteObject":             "delete",
    "ConsoleLogin":             "login",
    "AssumeRole":               "login",
    "CreateUser":               "create",
    "DeleteUser":               "delete",
    "AttachUserPolicy":         "update",
    "PutUserPolicy":            "update",
    "CreateAccessKey":          "create",
    "DeleteAccessKey":          "delete",
    "CreatePolicy":             "create",
    "DeletePolicy":             "delete",
    "PutRolePolicy":            "update",
    "AttachRolePolicy":         "update",
    "RunInstances":             "create",
    "TerminateInstances":       "delete",
    "AuthorizeSecurityGroupIngress": "update",
    "ModifyInstanceAttribute":  "update",
    "StartLogging":             "update",
    "StopLogging":              "update",   # high severity: tampering
    "DeleteTrail":              "delete",   # critical: log destruction
    "GetSecretValue":           "read",
    "CreateSecret":             "create",
}

# Severity rules — explicit and testable
AWS_SEVERITY_RULES = [
    ({"DeleteTrail", "StopLogging", "UpdateTrail"}, "critical"),
    ({"CreateUser", "AttachUserPolicy", "PutUserPolicy", "PutRolePolicy",
      "AttachRolePolicy", "CreatePolicy"}, "high"),
    ({"AssumeRole", "CreateAccessKey", "GetSecretValue"}, "medium"),
    ({"ConsoleLogin"}, "low"),
]

def normalize_aws_event(raw: dict, collected_at: datetime) -> NormalizedEvent | None:
    try:
        event_time = datetime.fromisoformat(
            raw.get("EventTime", raw.get("eventTime", "")).replace("Z", "+00:00")
        )
        event_name = raw.get("EventName", raw.get("eventName", "unknown"))
        latency_ms = int((collected_at - event_time).total_seconds() * 1000)

        # Extract principal
        user_identity = raw.get("userIdentity", {})
        principal = Principal(
            id=user_identity.get("arn", user_identity.get("principalId", "unknown")),
            type=user_identity.get("type", "unknown").lower(),
            name=user_identity.get("userName"),
            account_id=user_identity.get("accountId"),
            is_root=user_identity.get("type") == "Root"
        )

        # Extract target
        resources = raw.get("resources", [])
        if resources:
            r = resources[0]
            target = Target(
                id=r.get("ARN", "unknown"),
                type=r.get("type", "unknown").replace("AWS::", "").lower(),
                arn=r.get("ARN"),
                region=raw.get("awsRegion")
            )
        else:
            target = Target(
                id=raw.get("eventSource", "unknown"),
                type="service",
                region=raw.get("awsRegion")
            )

        # Severity
        severity = "info"
        for event_set, sev in AWS_SEVERITY_RULES:
            if event_name in event_set:
                severity = sev
                break

        return NormalizedEvent(
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
            raw_event=raw
        )

    except Exception as e:
        logger.error(f"Normalization failed for event {raw.get('EventId', 'unknown')}: {e}")
        return None
```

> **Key difference from the paper:** The paper's Algorithm 1 shows pseudocode. This is actual production code with explicit mapping tables you can defend. When asked "how do you decide severity?" — you point to `AWS_SEVERITY_RULES`. Document your reasoning in comments.

### 5.3 CSNL Tests (Critical for credibility)

```python
# csnl/tests/test_aws_normalizer.py
import pytest
from datetime import datetime, timezone
from csnl.normalizers.aws_normalizer import normalize_aws_event

SAMPLE_CLOUDTRAIL_EVENT = {
    "EventId": "test-123",
    "EventName": "DeleteTrail",
    "EventTime": "2026-05-27T10:00:00Z",
    "userIdentity": {
        "type": "IAMUser",
        "arn": "arn:aws:iam::123456789:user/attacker",
        "userName": "attacker",
        "accountId": "123456789"
    },
    "sourceIPAddress": "1.2.3.4",
    "userAgent": "aws-cli/2.0",
    "awsRegion": "us-east-1",
    "resources": []
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
    assert event.source_ip is None   # not a crash
```

**Target: 90%+ test coverage on the CSNL module. This is your most defensible metric.**

---

## 6. Phase 3: Detection Engine

### 6.1 How Many Rules to Actually Write

The paper claims 47 rules. For a solo project, write **15–20 high-quality rules** and document them properly. 15 well-tested rules with documented false positive rates are more impressive than 47 undocumented ones.

| Priority | Rule | MITRE Technique | Why Include |
|----------|------|-----------------|-------------|
| 1 | CloudTrail Disabled | T1562.008 | Attacker's first move |
| 2 | Root Account Login | T1078.004 | Easy to detect, low FP |
| 3 | IAM Policy Escalation | T1078.004 | Classic privilege escalation |
| 4 | Access Key Created for Root | T1098.001 | Near-zero legitimate use |
| 5 | Impossible Travel | T1078 | Cross-cloud value add |
| 6 | Mass S3 Object Download | T1530 | Exfiltration signal |
| 7 | Security Group Opened to 0.0.0.0/0 | T1190 | Exposure risk |
| 8 | New Admin User Created | T1136 | Persistence |
| 9 | Secrets Manager Access Spike | T1555 | Credential access |
| 10 | Cross-Account Role Assumption | T1199 | Lateral movement |
| 11 | CloudTrail Log Tampering | T1562.008 | Defense evasion |
| 12 | Bucket Made Public | T1530 | Exfiltration/exposure |
| 13 | Multi-Region Activity Spike | T1078 | Anomalous behavior |
| 14 | Service Account Key Creation (GCP) | T1098.001 | GCP-specific |
| 15 | Azure AD Guest User Added | T1136.003 | Azure-specific |

### 6.2 Rule Engine Implementation

```python
# detection/engine.py
import yaml
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from csnl.schema import NormalizedEvent
from storage.models import Detection

logger = logging.getLogger(__name__)

class DetectionRule:
    def __init__(self, rule_path: Path):
        with open(rule_path) as f:
            self.config = yaml.safe_load(f)
        self.rule_id   = rule_path.stem
        self.title     = self.config["title"]
        self.severity  = self.config["level"]
        self.technique = self.config["tags"][0].replace("attack.", "").upper()
        self.tactic    = self.config["tags"][1].replace("attack.", "") if len(self.config["tags"]) > 1 else "unknown"

    def matches(self, event: NormalizedEvent) -> bool:
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
        """Support dot notation: target.type, principal.is_root, etc."""
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
        self.rules = []
        self.stats = {
            "events_processed": 0,
            "detections_raised": 0,
            "rule_hits": {}
        }
        self._load_rules(rules_dir)
        logger.info(f"Loaded {len(self.rules)} detection rules")

    def _load_rules(self, rules_dir: Path):
        for rule_file in rules_dir.glob("*.yml"):
            try:
                rule = DetectionRule(rule_file)
                self.rules.append(rule)
                self.stats["rule_hits"][rule.rule_id] = 0
            except Exception as e:
                logger.error(f"Failed to load rule {rule_file}: {e}")

    def process(self, event: NormalizedEvent) -> list[Detection]:
        self.stats["events_processed"] += 1
        detections = []

        for rule in self.rules:
            try:
                if rule.matches(event):
                    detection = Detection(
                        event_id=event.event_id,
                        rule_id=rule.rule_id,
                        technique_id=rule.technique,
                        tactic=rule.tactic,
                        severity=rule.severity,
                        confidence=1.0,     # signature rules are deterministic
                        details={
                            "rule_title": rule.title,
                            "matched_event_type": event.event_type,
                            "provider": event.provider
                        }
                    )
                    detections.append(detection)
                    self.stats["detections_raised"] += 1
                    self.stats["rule_hits"][rule.rule_id] += 1
            except Exception as e:
                logger.error(f"Rule {rule.rule_id} evaluation error: {e}")

        return detections
```

### 6.3 Anomaly Detection (Isolation Forest)

The paper mentions Isolation Forest but gives no implementation details. Here is what you actually need to implement and tune:

```python
# detection/anomaly/isolation_forest.py
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class EntityBehaviorModel:
    """
    Trains per-entity behavioral baselines using Isolation Forest.
    
    Feature vector per entity per time window (1 hour):
    - event_count: total events
    - unique_event_types: cardinality of event types
    - unique_regions: number of distinct regions accessed
    - high_severity_ratio: fraction of high/critical events
    - unique_targets: number of distinct resources accessed
    - off_hours_ratio: fraction of events outside 9-5 local time
    """

    FEATURE_NAMES = [
        "event_count",
        "unique_event_types",
        "unique_regions",
        "high_severity_ratio",
        "unique_targets",
        "off_hours_ratio"
    ]

    def __init__(self, contamination: float = 0.05):
        # contamination = expected fraction of anomalies in training data
        # 0.05 means you expect 5% of baseline to be anomalous
        # THIS IS A HYPERPARAMETER — tune it and report what you chose
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def build_feature_vector(self, events: list) -> np.ndarray:
        if not events:
            return np.zeros(len(self.FEATURE_NAMES))

        total = len(events)
        event_types = set(e.event_type for e in events)
        regions = set(
            e.target.region for e in events if e.target.region
        )
        high_sev = sum(
            1 for e in events if e.severity in ("high", "critical")
        )
        targets = set(e.target.id for e in events)
        off_hours = sum(
            1 for e in events
            if e.timestamp.hour < 9 or e.timestamp.hour > 17
        )

        return np.array([
            total,
            len(event_types),
            len(regions),
            high_sev / total,
            len(targets),
            off_hours / total
        ])

    def train(self, feature_matrix: np.ndarray):
        """Train on baseline (benign) entity behavior."""
        scaled = self.scaler.fit_transform(feature_matrix)
        self.model.fit(scaled)
        self.is_trained = True
        logger.info(f"Trained anomaly model on {len(feature_matrix)} samples")

    def score(self, feature_vector: np.ndarray) -> float:
        """Return anomaly score. Negative = more anomalous."""
        if not self.is_trained:
            return 0.0
        scaled = self.scaler.transform(feature_vector.reshape(1, -1))
        return float(self.model.score_samples(scaled)[0])

    def save(self, path: Path):
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load(self, path: Path):
        data = joblib.load(path)
        self.model = data["model"]
        self.scaler = data["scaler"]
        self.is_trained = True
```

> **Critical honesty note:** The paper claims anomaly detection improves TPR by 8% for novel attacks. To validate this claim yourself, you must run your detection engine **with and without** the anomaly module on the same dataset and measure the difference. Report your actual number — whether it is 3%, 8%, or 15%.

---

## 7. Phase 4: Response Orchestration

### 7.1 Build Response with Safety First

The paper's response automation is the riskiest part. A bug here deletes production resources. Implement these safeguards before any automation:

```python
# response/orchestrator.py
from enum import Enum
from datetime import datetime, timezone
import logging

logger = logging.getLogger(__name__)

class ResponseMode(Enum):
    OBSERVE   = "observe"    # Log what would happen; do nothing
    ALERT     = "alert"      # Send notification only
    CONTAIN   = "contain"    # Execute containment (no deletion)
    REMEDIATE = "remediate"  # Full automated response

class ResponseOrchestrator:
    def __init__(self, mode: ResponseMode = ResponseMode.OBSERVE):
        # START IN OBSERVE MODE. Always.
        # Change to ALERT after a week of validation.
        # Change to CONTAIN only after a month of confirmed accuracy.
        self.mode = mode
        self.action_log = []

    def handle_detection(self, detection, event):
        action_record = {
            "detection_id": str(detection.detection_id),
            "event_provider": event.provider,
            "severity": detection.severity,
            "mode": self.mode.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action_taken": None,
            "dry_run": self.mode == ResponseMode.OBSERVE
        }

        if detection.severity not in ("high", "critical"):
            action_record["action_taken"] = "skipped_low_severity"
            self.action_log.append(action_record)
            return

        if self.mode == ResponseMode.OBSERVE:
            action_record["action_taken"] = "dry_run_logged"
            logger.info(f"[DRY RUN] Would respond to {detection.rule_id} "
                       f"on {event.provider} for {event.principal.id}")

        elif self.mode == ResponseMode.ALERT:
            self._send_alert(detection, event)
            action_record["action_taken"] = "alert_sent"

        elif self.mode == ResponseMode.CONTAIN:
            result = self._execute_containment(detection, event)
            action_record["action_taken"] = result

        self.action_log.append(action_record)

    def _execute_containment(self, detection, event) -> str:
        """Execute only non-destructive containment actions."""
        if event.provider == "aws":
            return self._aws_contain(detection, event)
        elif event.provider == "azure":
            return self._azure_contain(detection, event)
        return "no_action_for_provider"

    def _aws_contain(self, detection, event) -> str:
        from response.actions.aws_actions import AWSActions
        aws = AWSActions()

        if detection.rule_id == "iam_privilege_escalation":
            # Revoke session — reversible
            return aws.revoke_iam_sessions(event.principal.id)
        elif detection.rule_id == "security_group_open":
            # Remove the offending rule — reversible
            return aws.remove_sg_rule(event.target.id)

        return "no_matching_action"
```

### 7.2 Measure Response Latency (The Paper's 30-Second Claim)

```python
# response/latency_tracker.py
import time
from dataclasses import dataclass, field
from typing import List
import statistics

@dataclass
class LatencyRecord:
    detection_id: str
    event_timestamp: float      # when the cloud event occurred
    detection_timestamp: float  # when our engine flagged it
    response_timestamp: float   # when action was taken/logged
    provider: str

    @property
    def detection_latency_ms(self) -> int:
        return int((self.detection_timestamp - self.event_timestamp) * 1000)

    @property
    def response_latency_ms(self) -> int:
        return int((self.response_timestamp - self.event_timestamp) * 1000)

class LatencyTracker:
    def __init__(self):
        self.records: List[LatencyRecord] = []

    def record(self, record: LatencyRecord):
        self.records.append(record)

    def report(self) -> dict:
        """Generate the actual latency numbers you will put on your resume."""
        if not self.records:
            return {}

        response_latencies = [r.response_latency_ms for r in self.records]
        response_latencies.sort()
        n = len(response_latencies)

        def percentile(data, p):
            idx = int(len(data) * p / 100)
            return data[min(idx, len(data) - 1)]

        return {
            "sample_size": n,
            "p50_ms": percentile(response_latencies, 50),
            "p75_ms": percentile(response_latencies, 75),
            "p90_ms": percentile(response_latencies, 90),
            "p95_ms": percentile(response_latencies, 95),
            "p99_ms": percentile(response_latencies, 99),
            "mean_ms": int(statistics.mean(response_latencies)),
            "stdev_ms": int(statistics.stdev(response_latencies)) if n > 1 else 0,
            "by_provider": {
                provider: {
                    "count": len([r for r in self.records if r.provider == provider]),
                    "p95_ms": percentile(
                        sorted([r.response_latency_ms for r in self.records
                                if r.provider == provider]), 95
                    )
                }
                for provider in set(r.provider for r in self.records)
            }
        }
```

> **This is how you replace the paper's claimed "sub-30-second response."** Run your system, call `tracker.report()`, and record the actual numbers in `evaluation/results/latency_results.json`. Commit this file. Now your numbers are reproducible.

---

## 8. Phase 5: Evaluation Framework (The Honest Part)

This is what separates a credible implementation from a paper claim. Build this carefully.

### 8.1 Synthetic Attack Dataset Generator

The paper references "anonymized production logs from 3 organizations" — you likely do not have this. Here is how to build an honest, reproducible synthetic dataset instead.

```python
# evaluation/dataset_generator.py
"""
Generates labeled synthetic CloudTrail events for MC-CDR evaluation.

HONESTY NOTE: This dataset is entirely synthetic and generated by this script.
All metrics reported in our evaluation are measured against this dataset.
The dataset generator is open-source and reproducible — run with the same
seed to get identical results.
"""

import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)  # Reproducible results — document this in your paper

class AttackScenarioGenerator:

    BENIGN_EVENTS = [
        "GetObject", "PutObject", "DescribeInstances",
        "ListBuckets", "GetUser", "ListRoles", "ConsoleLogin"
    ]

    def generate_benign_event(self, user_id: str, timestamp: datetime) -> dict:
        return {
            "EventId": str(uuid.uuid4()),
            "EventName": random.choice(self.BENIGN_EVENTS),
            "EventTime": timestamp.isoformat(),
            "label": "benign",                 # ground truth label
            "scenario": "normal_operations",
            "userIdentity": {
                "type": "IAMUser",
                "arn": f"arn:aws:iam::123456789:user/{user_id}",
                "userName": user_id,
                "accountId": "123456789"
            },
            "sourceIPAddress": f"10.0.{random.randint(1,254)}.{random.randint(1,254)}",
            "awsRegion": random.choice(["us-east-1", "us-west-2"]),
            "resources": []
        }

    def generate_privilege_escalation_scenario(
        self, attacker_id: str, start_time: datetime
    ) -> list[dict]:
        """
        Models T1078.004 / T1098.001:
        1. AttachUserPolicy (attempt escalation)
        2. CreatePolicy (create permissive policy)
        3. AttachRolePolicy (attach to role)
        4. GetSecretValue (harvest credentials)
        """
        events = []
        t = start_time

        for event_name, region in [
            ("AttachUserPolicy", "us-east-1"),
            ("CreatePolicy", "us-east-1"),
            ("AttachRolePolicy", "us-east-1"),
            ("GetSecretValue", "us-west-2"),
        ]:
            t += timedelta(seconds=random.randint(30, 120))
            events.append({
                "EventId": str(uuid.uuid4()),
                "EventName": event_name,
                "EventTime": t.isoformat(),
                "label": "attack",                          # ground truth
                "scenario": "privilege_escalation",
                "technique": "T1078.004",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": f"arn:aws:iam::123456789:user/{attacker_id}",
                    "userName": attacker_id,
                    "accountId": "123456789"
                },
                "sourceIPAddress": "198.51.100.1",         # attacker IP
                "awsRegion": region,
                "resources": [{
                    "ARN": f"arn:aws:iam::123456789:policy/AdminPolicy",
                    "type": "AWS::IAM::Policy"
                }]
            })

        return events

    def generate_dataset(
        self,
        n_benign: int = 10000,
        n_attack_scenarios: int = 100,
        output_path: Path = Path("evaluation/data/dataset.jsonl")
    ) -> dict:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        all_events = []
        start = datetime(2026, 5, 1, tzinfo=timezone.utc)

        # Generate benign events
        users = [f"user_{i}" for i in range(20)]
        for i in range(n_benign):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.append(self.generate_benign_event(
                random.choice(users), ts
            ))

        # Generate attack scenarios
        for i in range(n_attack_scenarios):
            ts = start + timedelta(seconds=random.randint(0, 86400 * 30))
            all_events.extend(
                self.generate_privilege_escalation_scenario(f"attacker_{i}", ts)
            )
            # Add more scenario types here as you build them

        # Sort by time, shuffle slightly
        all_events.sort(key=lambda e: e["EventTime"])
        random.shuffle(all_events[:100])  # add some ordering noise

        with open(output_path, "w") as f:
            for event in all_events:
                f.write(json.dumps(event) + "\n")

        stats = {
            "total_events": len(all_events),
            "benign_count": sum(1 for e in all_events if e["label"] == "benign"),
            "attack_count": sum(1 for e in all_events if e["label"] == "attack"),
            "scenarios": list(set(e["scenario"] for e in all_events if e["label"] == "attack")),
            "random_seed": 42,
            "generated_at": datetime.now(timezone.utc).isoformat()
        }

        with open(output_path.parent / "dataset_stats.json", "w") as f:
            json.dump(stats, f, indent=2)

        return stats
```

### 8.2 Evaluation Runner (Produces Your Real Metrics)

```python
# evaluation/benchmarks.py
"""
Run this script to produce all metrics reported in the implementation.
Results are saved to evaluation/results/ and should be committed to the repo.
"""
import json
from pathlib import Path
from datetime import datetime, timezone
from csnl.normalizers.aws_normalizer import normalize_aws_event
from detection.engine import DetectionEngine

def run_evaluation(dataset_path: Path, rules_dir: Path) -> dict:
    engine = DetectionEngine(rules_dir)

    tp = fp = tn = fn = 0
    per_scenario = {}

    with open(dataset_path) as f:
        for line in f:
            raw_event = json.loads(line)
            ground_truth = raw_event["label"]          # "attack" or "benign"
            scenario = raw_event.get("scenario", "unknown")

            normalized = normalize_aws_event(
                raw_event,
                collected_at=datetime.now(timezone.utc)
            )
            if normalized is None:
                continue

            detections = engine.process(normalized)
            predicted_attack = len(detections) > 0

            if ground_truth == "attack" and predicted_attack:
                tp += 1
                per_scenario.setdefault(scenario, {"tp":0,"fp":0,"fn":0,"tn":0})["tp"] += 1
            elif ground_truth == "benign" and predicted_attack:
                fp += 1
                per_scenario.setdefault(scenario, {"tp":0,"fp":0,"fn":0,"tn":0})["fp"] += 1
            elif ground_truth == "attack" and not predicted_attack:
                fn += 1
                per_scenario.setdefault(scenario, {"tp":0,"fp":0,"fn":0,"tn":0})["fn"] += 1
            else:
                tn += 1

    tpr = tp / (tp + fn) if (tp + fn) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * tpr / (precision + tpr) if (precision + tpr) > 0 else 0

    results = {
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "dataset": str(dataset_path),
        "rules_dir": str(rules_dir),
        "overall": {
            "true_positives": tp,
            "false_positives": fp,
            "true_negatives": tn,
            "false_negatives": fn,
            "tpr": round(tpr, 4),
            "fpr": round(fpr, 4),
            "precision": round(precision, 4),
            "f1_score": round(f1, 4)
        },
        "per_scenario": per_scenario
    }

    output = Path("evaluation/results")
    output.mkdir(parents=True, exist_ok=True)
    with open(output / "detection_results.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"TPR: {tpr:.3f} | FPR: {fpr:.3f} | Precision: {precision:.3f} | F1: {f1:.3f}")
    return results

if __name__ == "__main__":
    run_evaluation(
        dataset_path=Path("evaluation/data/dataset.jsonl"),
        rules_dir=Path("detection/rules")
    )
```

---

## 9. Addressing the Paper's Loopholes

| Paper Claim | The Problem | How You Fix It |
|---|---|---|
| "94.3% detection accuracy" | No dataset described, no methodology shown | Run `benchmarks.py`, commit `detection_results.json` with your actual number |
| "Sub-30-second response" | No measurement methodology | Use `LatencyTracker`, commit `latency_results.json` |
| "47 detection rules" | No rules shown except one example | Build 15-20 rules, list all of them in README with technique mapping |
| "6M events from 3 organizations" | Unverifiable, likely unavailable to you | Use `dataset_generator.py` with seed 42 — fully reproducible |
| "60% cheaper than Splunk" | No cost model shown | Document your actual infra cost: EC2 instance type, DB size, hours run |
| "CSNL preserves forensic integrity" | No test shown | Write the `test_raw_event_preserved()` test and pass it |
| "23% improvement in cross-cloud correlation" | No baseline defined | Run with single-cloud only, then multi-cloud, compare F1 scores |
| Isolation Forest "reduces FPR" | No hyperparameter tuning shown | Grid-search contamination (0.01, 0.05, 0.1), report the curve |
| "Production-ready codebase" | No CI, no tests shown | Add GitHub Actions: `pytest` + `go test` on every commit |

---

## 10. Resume Framing by Build Stage

Use the framing that exactly matches what you have built. Never overstate.

**If you complete Phase 1–2 (Ingestion + CSNL):**
> Built a multi-cloud log ingestion and normalization pipeline for AWS CloudTrail and Azure Activity Logs, implementing a custom Cloud Security Normalization Layer (CSNL) with validated field mappings for 25+ event types, 90%+ unit test coverage, and measured ingestion latency tracking.

**If you complete Phase 1–3 (+ Detection):**
> Engineered a cloud-native detection system ingesting and normalizing AWS/Azure audit logs through a custom normalization layer, with 15 MITRE ATT&CK-mapped signature detection rules (T1078, T1562, T1530 families) achieving F1=0.XX on a reproducible synthetic evaluation dataset.

**If you complete Phase 1–4 (Full System):**
> Designed and implemented MC-CDR, a unified multi-cloud detection and response platform aggregating AWS and Azure security telemetry through a normalized event schema. The system implements 18 ATT&CK-mapped detection rules, Isolation Forest-based anomaly detection, and automated containment response. Benchmarked on a reproducible 12,000-event labeled dataset: TPR=X.XX, FPR=X.XX, p95 response latency=XX seconds.

> Note the placeholders — fill those with your actual measured numbers.

---

## 11. Interview Defense Cheatsheet

Questions you will be asked, and what to have ready:

**"Walk me through how you normalize an AWS CloudTrail event."**
Point to `aws_normalizer.py`, walk through the `AWS_ACTION_MAP` and `AWS_SEVERITY_RULES` tables, explain why you made specific mapping choices (e.g., "StopLogging maps to critical because it's the first thing attackers disable").

**"How did you validate detection accuracy?"**
"I built a synthetic labeled dataset using `dataset_generator.py` with a fixed random seed of 42, making it fully reproducible. I ran `benchmarks.py` against it and measured TPR, FPR, precision, and F1 per rule and overall. The results are committed to `evaluation/results/detection_results.json`."

**"Why did you pick Isolation Forest over DBSCAN or LOF?"**
"Isolation Forest is efficient on high-dimensional sparse data, which cloud audit logs are. It also doesn't require defining a neighborhood radius like DBSCAN, which is hard to set for event vectors. I evaluated contamination values of 0.01, 0.05, and 0.10 and found 0.05 gave the best F1 on my validation set."

**"What's the actual latency of your pipeline?"**
"My `LatencyTracker` measures end-to-end from cloud event timestamp to response action. At p95 it's X seconds on AWS, Y seconds on Azure. The AWS delay is dominated by CloudTrail's own delivery latency of roughly 2–4 minutes for the S3-based trail."

**"Why not just use OCSF instead of your own CSNL schema?"**
"OCSF is the right long-term answer for the industry. My CSNL intentionally mirrors OCSF's core fields but adds `ingestion_latency_ms` and keeps `raw_event` immutable for forensic use. In production I would migrate to OCSF as it gains broader SDK support."

**"What would break if AWS changed their CloudTrail format?"**
"The `AWS_ACTION_MAP` and the field extractions in `aws_normalizer.py` would need updating. I've isolated all provider-specific logic to the normalizer modules precisely so that a schema change only touches one file. I have tests that validate specific field mappings, so a breaking change would fail CI immediately."

---

*Build something real. Measure it honestly. Own the numbers.*
