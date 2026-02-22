from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class IntrospectRequest(BaseModel):
    token: str = Field(min_length=1)


class OidcAuthUrlRequest(BaseModel):
    state: str = Field(min_length=8)
    nonce: str = Field(min_length=8)
    redirect_uri: str = Field(min_length=1)
    scope: str = Field(default="openid profile email")


class OidcCodeExchangeRequest(BaseModel):
    code: str = Field(min_length=1)
    redirect_uri: str = Field(min_length=1)
    code_verifier: str | None = Field(default=None, min_length=8, max_length=256)


class OidcUserInfoRequest(BaseModel):
    access_token: str = Field(min_length=1)


class OidcLogoutUrlRequest(BaseModel):
    id_token_hint: str = Field(min_length=1)
    post_logout_redirect_uri: str = Field(min_length=1)
    client_id: str = Field(min_length=1)


class SessionRegisterRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=128)
    username: str = Field(default="", max_length=150)
    session_id: str = Field(min_length=1, max_length=128)
    device_id: str = Field(min_length=1, max_length=128)
    ip_address: str = Field(default="", max_length=64)
    user_agent: str = Field(default="", max_length=2048)
    expires_at: datetime


class SessionRevokeRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(default=None, max_length=128)
    device_id: str | None = Field(default=None, max_length=128)
