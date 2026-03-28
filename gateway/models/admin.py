from datetime import datetime

from pydantic import BaseModel


class AdminLoginRequest(BaseModel):
    api_key: str


class AdminSessionData(BaseModel):
    caller_id: str
    role: str
    environment: str
    api_key_id: int
    org_id: str
    expires_at: datetime


class AdminSessionResponse(BaseModel):
    session_token: str
    caller_id: str
    role: str
    environment: str
    api_key_id: int
    org_id: str
    expires_at: datetime
