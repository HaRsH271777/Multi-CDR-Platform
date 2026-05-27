from datetime import datetime
from typing import Optional, Literal, Any
from uuid import UUID, uuid4
import ipaddress

from pydantic import BaseModel, Field, field_validator

ProviderType = Literal["aws", "azure", "gcp"]
SeverityType = Literal["info", "low", "medium", "high", "critical"]
ActionType = Literal["create", "read", "update", "delete", "login", "other"]


class Principal(BaseModel):
    id: str
    type: str  # user | role | service_account | api_key
    name: Optional[str] = None
    account_id: Optional[str] = None
    is_root: bool = False


class Target(BaseModel):
    id: str
    type: str  # ec2_instance | iam_policy | storage_bucket ...
    name: Optional[str] = None
    region: Optional[str] = None
    arn: Optional[str] = None  # AWS only; stored here for forensics


class NormalizedEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime
    ingested_at: datetime
    ingestion_latency_ms: int  # always measure this
    normalization_version: str = "1.0"
    provider: ProviderType
    event_type: str
    severity: SeverityType
    principal: Principal
    target: Target
    action: ActionType
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    raw_event: dict  # original log, immutable
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
