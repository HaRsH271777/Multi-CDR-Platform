# MC-CDR

MC-CDR (Multi-Cloud Detection and Response) is a security telemetry pipeline that
normalizes cloud audit logs into a common schema, enriches them, and prepares the
data for detection and response workflows. The project targets AWS, Azure, and GCP
with a consistent event model so detection rules can be written once and applied
across providers.

## What it does

- Ingests cloud audit events from AWS CloudTrail and Azure Activity Logs.
- Normalizes raw events into a shared CSNL schema with consistent fields.
- Adds enrichment metadata such as IP classification and time context.
- Provides a detection engine and response orchestration layer.
- Stores normalized events and detections in TimescaleDB for time-series analysis.

## Current status

- Phase 0: infrastructure setup complete (TimescaleDB and schema verified).
- Phase 1: ingestion scaffolding in place for AWS and Azure.
- Phase 2: Cloud Security Normalization Layer (CSNL) implemented with tests.
- Phase 3+: detection and response are planned next.

## Repository structure (high level)

- mc-cdr/ingestion: cloud log collectors
- mc-cdr/csnl: normalization schema, enrichments, and tests
- mc-cdr/detection: rule engine and anomaly detection
- mc-cdr/response: automated response actions and playbooks
- mc-cdr/storage: database models and migrations

## Principles

- Measured results only: metrics are reported after evaluation artifacts are committed.
- Explicit mappings: normalization and severity mappings are versioned and testable.
- Defensive automation: response workflows start in observe-only mode.
