from datetime import datetime
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class RunStep(BaseModel):
    technique_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    status: str = "pending"
    notes: Optional[str] = None


class Runbook(BaseModel):
    run_id: str
    goals: Optional[str] = None
    steps: List[RunStep] = Field(default_factory=list)


class EventArtifact(BaseModel):
    type: str
    uri: str


class Event(BaseModel):
    run_id: str
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    phase: Optional[Literal["queued", "running", "ok", "error"]] = None
    severity: Optional[Literal["low", "medium", "high"]] = None
    region: Optional[str] = None
    principal_arn: Optional[str] = None
    resource: Optional[str] = None
    artifacts: List[EventArtifact] = Field(default_factory=list)
