from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TechniqueSpec(BaseModel):
    """Metadata describing an executable technique pulled from the catalog."""

    id: str
    requires: Dict[str, Any] = Field(default_factory=dict)
    params: Dict[str, Any] = Field(default_factory=dict)
    planner: Dict[str, Any] = Field(default_factory=dict)
    report: Dict[str, Any] = Field(default_factory=dict)
    safety: Any | None = None
    severity: Optional[str] = None
    impl: Dict[str, Any] = Field(default_factory=dict)
    mitre: List[str] = Field(default_factory=list)


class RunbookStep(BaseModel):
    technique_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None


class Runbook(BaseModel):
    steps: List[RunbookStep] = Field(default_factory=list)
    goals: Optional[str] = None

    def add_step(self, step: RunbookStep) -> None:
        self.steps.append(step)
