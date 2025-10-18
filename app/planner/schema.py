from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class TechniqueSpec(BaseModel):
    """Metadata describing an executable technique pulled from the catalog."""

    id: str
    requires: List[str] = Field(default_factory=list)
    params: Dict[str, Any] = Field(default_factory=dict)
    safety: Dict[str, Any] = Field(default_factory=dict)
    impl: Dict[str, Any] = Field(default_factory=dict)
    mitre: Dict[str, Any] = Field(default_factory=dict)


class RunbookStep(BaseModel):
    technique_id: str
    params: Dict[str, Any] = Field(default_factory=dict)
    notes: Optional[str] = None


class Runbook(BaseModel):
    steps: List[RunbookStep] = Field(default_factory=list)
    goals: Optional[str] = None

    def add_step(self, step: RunbookStep) -> None:
        self.steps.append(step)
