"""Strict API and attribute contracts."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Department = Literal["data", "risk", "marketing", "finance"]
Level = Literal["public", "internal", "confidential", "restricted"]
Baseline = Literal["rbac", "static_abac", "context_abac"]
Strategy = Literal["deny-overrides", "permit-overrides", "priority-based"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Subject(StrictModel):
    id: str
    tenant_id: str = Field(default="demo", pattern=r"^[a-z][a-z0-9_-]{0,39}$")
    role: Literal["admin", "data_engineer", "risk_analyst", "marketing_analyst", "intern"]
    department: Department
    clearance: Level


class Resource(StrictModel):
    id: str
    type: Literal["report", "dataset", "database", "records"]
    department: Department
    sensitivity: Level


class Context(StrictModel):
    device_trusted: bool
    location: Literal["office", "vpn", "external"]
    time: str
    risk_score: int = Field(ge=0, le=100)

    @field_validator("time")
    @classmethod
    def aware_time(cls, value: str) -> str:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.utcoffset() is None:
            raise ValueError("time must include a timezone")
        return value


class AccessRequest(StrictModel):
    subject_id: str = Field(min_length=1, max_length=100)
    resource_id: str = Field(min_length=1, max_length=100)
    action: Literal["read", "write", "delete"]
    baseline: Baseline = "context_abac"
    strategy: Strategy = "deny-overrides"
    context: Context | None = None
    trace: bool = True
    failure_mode: Literal[
        "none",
        "opa_unavailable",
        "provider_unavailable",
        "stale_attribute",
        "invalid_opa_response",
        "opa_timeout",
        "undefined_result",
        "invalid_policy",
        "missing_attribute",
    ] = "none"
