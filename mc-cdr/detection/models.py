from datetime import datetime, timezone
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


class Detection(BaseModel):
    detection_id: UUID = Field(default_factory=uuid4)
    event_id: UUID
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rule_id: str
    technique_id: str
    tactic: str
    severity: str
    confidence: float
    details: dict = Field(default_factory=dict)
    status: str = "open"
