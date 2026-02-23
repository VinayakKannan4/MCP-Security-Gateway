from enum import Enum
from pydantic import BaseModel, Field


class RiskLabel(str, Enum):
    LOW_READONLY = "LOW_READONLY"
    MEDIUM_DATA_EXFIL = "MEDIUM_DATA_EXFIL"
    HIGH_WRITE_ACTION = "HIGH_WRITE_ACTION"
    HIGH_DESTRUCTIVE = "HIGH_DESTRUCTIVE"
    PROMPT_INJECTION_SUSPECT = "PROMPT_INJECTION_SUSPECT"
    PII_SENSITIVE = "PII_SENSITIVE"


class RiskAssessment(BaseModel):
    labels: list[RiskLabel] = Field(default_factory=list)
    score: float = Field(ge=0.0, le=1.0)
    explanation: str
    triggered_heuristics: list[str] = Field(default_factory=list)
    llm_consulted: bool = False
