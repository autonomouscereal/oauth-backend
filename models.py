# models.py

from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class User(BaseModel):
    id: Optional[int]
    email: str
    hashed_password: str
    created_at: Optional[datetime]

class OAuth2Client(BaseModel):
    client_id: str
    client_secret: Optional[str]
    redirect_uris: list
    created_at: Optional[datetime]

class OAuth2AuthorizationCode(BaseModel):
    code: str
    client_id: str
    redirect_uri: str
    scope: Optional[str]
    user_id: int
    code_challenge: str
    code_challenge_method: str
    expires_at: datetime

class TokenRequest(BaseModel):
    grant_type: str
    code: Optional[str]
    redirect_uri: Optional[str]
    client_id: Optional[str]
    code_verifier: Optional[str]
