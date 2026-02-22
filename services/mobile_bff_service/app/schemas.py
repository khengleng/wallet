from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class MobileSelfOnboardRequest(BaseModel):
    legal_name: str = Field(default="", max_length=128)
    mobile_no: str = Field(default="", max_length=40)
    email: str = Field(default="", max_length=255)
    preferred_currency: str = Field(default="", max_length=12)
    wallet_currencies: list[str] = Field(default_factory=list)


class MobileOidcTokenExchangeRequest(BaseModel):
    code: str = Field(min_length=1)
    redirect_uri: str = Field(min_length=1, max_length=2048)
    code_verifier: str = Field(min_length=8, max_length=256)


class MobilePasswordResetRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    redirect_uri: str = Field(min_length=1, max_length=2048)


class MobileSessionRegisterRequest(BaseModel):
    session_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    expires_at: datetime | None = None


class MobileSessionRevokeRequest(BaseModel):
    session_id: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=128)


class MobileProfileUpdateRequest(BaseModel):
    first_name: str = Field(default="", max_length=150)
    last_name: str = Field(default="", max_length=150)
    legal_name: str = Field(default="", max_length=128)
    mobile_no: str = Field(default="", max_length=40)
    profile_picture_url: str = Field(default="", max_length=500)
    preferences: dict = Field(default_factory=dict)
