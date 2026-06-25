# MC-CDR: Multi-Cloud Detection and Response Platform

A unified security detection and response platform that ingests AWS CloudTrail
and Azure Activity Logs, normalizes them through a provider-agnostic schema,
and applies MITRE ATT&CK-mapped detection rules with automated response
orchestration.

Built as a portfolio project demonstrating end-to-end security engineering
across ingestion, normalization, detection, and response.

---

## What This Is

Most cloud security tools are siloed — AWS GuardDuty only sees AWS, Azure
Sentinel only sees Azure. MC-CDR ingests logs from both providers, normalizes
them into a unified event schema (CSNL), and runs a single detection engine
across all of them. The same rule that catches CloudTrail deletion on AWS
can be mirrored for Azure diagnostic setting deletion — without duplicating
detection logic per provider.

---

## Measured Results

All numbers below are measured from a reproducible synthetic evaluation
dataset (`evaluation/data/dataset.jsonl`, `random.seed(42)`). No numbers
are borrowed from literature or estimated.

| Metric | Value |
|---|---|
| Detection TPR | 0.875 |
| Detection FPR | 0.000 |
| Precision | 1.000 |
| F1 Score | 0.933 |
| In-process p50 latency | 0.133 ms |
| In-process p95 latency | 0.298 ms |
| Test count | 53 |
| Code coverage | 92% |
| Detection rules | 15 |
| MITRE tactics covered | 6 |

Full results: `evaluation/results/detection_results.json`,
`evaluation/results/latency_results.json`

> Note: In-process latency measures rule engine execution only. Real-world
> end-to-end latency includes CloudTrail delivery delay of 2–5 minutes, which
> is a provider constraint, not a pipeline constraint.

---

## Architecture

```
AWS CloudTrail          Azure Activity Logs
      │                        │
      ▼                        ▼
 Go Collector            Python Collector
      │                        │
      └──────────┬─────────────┘
                 ▼
    Cloud Security Normalization Layer (CSNL)
    - AWS Normalizer  (aws_normalizer.py)
    - Azure Normalizer (azure_normalizer.py)
    - Enrichment: is_private_ip, is_off_hours, day_of_week
                 │
                 ▼
         Detection Engine
    - 15 Sigma-format YAML rules
    - Isolation Forest anomaly detection
    - MITRE ATT&CK technique mapping
                 │
                 ▼
      Response Orchestrator
    - OBSERVE / ALERT / CONTAIN modes
    - AWS actions: IAM revocation, SG rule removal, bucket ACL revert
    - Latency tracking (microsecond precision)
                 │
                 ▼
          TimescaleDB
    - normalized_events (hypertable, partitioned on timestamp)
    - detections
    - response_actions
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| AWS Ingestion | Go 1.22, aws-sdk-go-v2 |
| Azure Ingestion | Python 3.13, azure-monitor-query |
| Normalization | Python, Pydantic v2 |
| Detection | Python, PyYAML, scikit-learn |
| Response | Python, boto3, moto (tests) |
| Storage | TimescaleDB (PostgreSQL 15) |
| Infrastructure | Docker Compose |
| Testing | pytest, pytest-cov, moto |

---

## Detection Rules

All 15 rules are in `detection/rules/` as Sigma-format YAML. Each rule maps
to a MITRE ATT&CK technique and has a documented false positive list.

| Rule | Provider | MITRE Technique | Severity |
|---|---|---|---|
| cloudtrail_disabled | AWS | T1562.008 | Critical |
| root_account_login | AWS | T1078.004 | Critical |
| root_access_key_created | AWS | T1098.001 | Critical |
| azure_diagnostic_deleted | Azure | T1562.008 | Critical |
| iam_policy_escalation | AWS | T1078.004 | High |
| new_admin_user | AWS | T1136 | High |
| s3_bucket_made_public | AWS | T1530 | High |
| azure_role_assignment | Azure | T1098.003 | High |
| azure_guest_user_added | Azure | T1136.003 | High |
| security_group_open | AWS | T1190 | Medium |
| secrets_manager_access | AWS | T1555 | Medium |
| cross_account_role_assumption | AWS | T1199 | Medium |
| cloudtrail_tampering | AWS | T1562.008 | Medium |
| keyvault_secrets_read | Azure | T1555 | Medium |
| mass_access_key_list | AWS | T1087.004 | Low |

---

## CSNL: Cloud Security Normalization Layer

The CSNL is the core architectural component. It transforms provider-specific
log formats into a unified `NormalizedEvent` schema defined in `csnl/schema.py`.

Every normalized event contains:
- `event_id`, `timestamp`, `ingested_at`, `ingestion_latency_ms`
- `provider` (aws | azure | gcp)
- `event_type`, `severity`, `action` (normalized: create|read|update|delete|login|other)
- `principal` (id, type, name, account_id, is_root)
- `target` (id, type, name, region, arn)
- `source_ip`, `user_agent`
- `raw_event` — original provider log, immutable, preserved for forensics
- `enrichments` — computed: is_private_ip, is_off_hours, day_of_week
- `normalization_version` — schema version tracking

All provider-specific mapping logic is isolated in the normalizer modules.
A schema change only touches one file. CI catches breaking changes immediately.

---

## Known Limitations and Honest Gaps

**Detection gaps:** 10 of 15 rules had zero hits in the benchmark run because
the synthetic dataset does not include those scenarios. These rules are valid
and unit-tested — the gaps are in the dataset, not the rules. See
`evaluation/RESULTS.md` for the full list.

**False negatives in privilege_escalation:** 100 of 400 attack events in this
scenario were missed. The 4-event attack chain
(`AttachUserPolicy → CreatePolicy → AttachRolePolicy → GetSecretValue`)
has individual events that map to medium-severity rules — the engine detects
most of them but misses some chain combinations. Improving this requires
multi-event correlation, which is planned for Tier 2.

**Latency measurement scope:** The p95 latency of 0.298ms measures the rule
engine only. End-to-end latency in a real deployment includes CloudTrail's
2–5 minute log delivery delay, network transit, and database write time.

**Dataset is synthetic:** All evaluation metrics are measured against a
generated dataset with known labels. Real-world performance will differ,
particularly FPR, which may rise with messy production logs.

**Single-cloud correlation:** Currently each event is evaluated independently.
Multi-stage attacks that span both AWS and Azure in sequence are not yet
detected as a unified chain.

---

## Project Structure

```
mc-cdr/
├── ingestion/
│   ├── aws/                    # Go: CloudTrail collector + tests
│   └── azure/                  # Python: Activity Log collector
├── csnl/
│   ├── schema.py               # NormalizedEvent Pydantic model
│   ├── enrichment.py           # IP classification, off-hours, day-of-week
│   ├── normalizers/
│   │   ├── aws_normalizer.py   # CloudTrail → NormalizedEvent
│   │   └── azure_normalizer.py # Activity Log → NormalizedEvent
│   └── tests/                  # 22 unit tests, 94% CSNL coverage
├── detection/
│   ├── engine.py               # Rule loader and evaluator
│   ├── models.py               # Detection Pydantic model
│   ├── rules/                  # 15 Sigma-format YAML detection rules
│   ├── anomaly/
│   │   └── isolation_forest.py # EntityBehaviorModel, 6-feature vectors
│   └── tests/                  # 17 unit tests, 95%+ detection coverage
├── response/
│   ├── orchestrator.py         # OBSERVE/ALERT/CONTAIN mode engine
│   ├── latency_tracker.py      # Microsecond-precision latency recording
│   ├── actions/
│   │   └── aws_actions.py      # IAM revoke, SG rule remove, bucket ACL revert
│   └── tests/                  # 11 unit tests, moto-mocked AWS calls
├── storage/
│   └── migrations/
│       └── 001_init.sql        # TimescaleDB schema
├── evaluation/
│   ├── dataset_generator.py    # Synthetic labeled dataset (seed=42)
│   ├── benchmarks.py           # Detection TPR/FPR/F1 measurement
│   ├── latency_benchmark.py    # In-process latency measurement
│   ├── anomaly_tuning.py       # Contamination parameter sweep
│   ├── data/
│   │   ├── dataset.jsonl       # 10,800 labeled events
│   │   └── dataset_stats.json
│   ├── results/
│   │   ├── detection_results.json
│   │   ├── latency_results.json
│   │   └── anomaly_tuning.json
│   └── RESULTS.md              # All measured numbers in one place
├── docker-compose.yml
├── requirements.txt
├── go.mod
└── .github/workflows/ci.yml
```

---

## Quickstart

**Prerequisites:** Docker Desktop, Python 3.11+, Go 1.22+

```bash
# 1. Clone and enter project
git clone https://github.com/<your-username>/mc-cdr.git
cd mc-cdr

# 2. Start TimescaleDB
docker compose up -d

# 3. Apply schema (PowerShell)
Get-Content storage/migrations/001_init.sql | docker exec -i mc-cdr-timescaledb psql -U mc_cdr -d mc_cdr

# 4. Set up Python environment
python -m venv .venv
.venv/Scripts/activate       # Windows
pip install -r requirements.txt

# 5. Run all tests
pytest csnl/tests/ detection/tests/ response/tests/ -v --cov=csnl --cov=detection --cov=response

# 6. Run Go ingestion tests
go test ./...

# 7. Reproduce evaluation results
python evaluation/dataset_generator.py
python evaluation/benchmarks.py
python evaluation/latency_benchmark.py
```

---

## Reproducing Results

All evaluation results are deterministic. Running the scripts above with
`random.seed(42)` (hardcoded in `dataset_generator.py`) produces identical
output to the committed JSON files in `evaluation/results/`.

To verify:
```bash
python evaluation/benchmarks.py
# Compare output to evaluation/results/detection_results.json
```

---

## Roadmap (Tier 2)

- [ ] Apache Kafka buffering for stream durability
- [ ] GCP Pub/Sub ingestion (Cloud Audit Logs)
- [ ] Multi-event correlation for attack chain detection
- [ ] Cross-cloud entity tracking (same identity across AWS + Azure)
- [ ] FastAPI dashboard for live detections
- [ ] Grafana integration with TimescaleDB

---

## License

Apache 2.0