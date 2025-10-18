from datetime import datetime
from typing import Any, Dict, List, Optional

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


class Event(BaseModel):
    run_id: str
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
