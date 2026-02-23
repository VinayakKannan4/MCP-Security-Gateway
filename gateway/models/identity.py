from enum import IntEnum
from pydantic import BaseModel


class TrustLevel(IntEnum):
    UNTRUSTED = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    ADMIN = 4


class CallerIdentity(BaseModel):
    caller_id: str
    role: str
    trust_level: TrustLevel
    environment: str  # "dev" | "staging" | "prod"
    api_key_id: int  # FK to api_keys table
