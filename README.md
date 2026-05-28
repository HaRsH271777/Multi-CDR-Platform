# MC-CDR

MC-CDR (Multi-Cloud Detection and Response) is a unified security operations platform
for cloud environments. The project aims to eliminate visibility gaps across providers
by collecting audit telemetry, normalizing it into a common event schema, applying
provider-agnostic detections mapped to MITRE ATT&CK, and orchestrating response actions
through native cloud APIs. The architecture is modular so that ingestion, normalization,
detection, and response can evolve independently while remaining consistent across clouds.

At the core of MC-CDR is a Cloud Security Normalization Layer (CSNL). CSNL transforms
provider-specific audit logs into a normalized event model that preserves forensic
context while enabling consistent detection logic. This design makes it possible to
write rules once and run them across AWS, Azure, and GCP, reducing duplicated detection
engineering work and enabling cross-cloud correlation. The platform prioritizes
forensic integrity by retaining the original raw event alongside normalized fields
and enrichments such as IP classification and temporal context.

On top of normalized events, MC-CDR provides a rule-based detection engine and an
anomaly detection module to surface both known techniques and behavioral outliers.
Detections are mapped to MITRE ATT&CK techniques to keep analytic coverage explicit
and explainable. The response layer is designed to execute high-confidence actions
through provider APIs, supporting containment and remediation workflows without
locking the platform into any single cloud ecosystem.

The project also includes an evaluation framework for measuring detection accuracy
and response latency on reproducible datasets. Results are intended to be backed by
actual executions and saved as artifacts so that claims are defensible and auditable.
This commitment to measured outcomes drives design choices throughout the system,
from normalized event design to response telemetry and benchmarking.
