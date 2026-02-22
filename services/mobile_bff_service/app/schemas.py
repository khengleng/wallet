from __future__ import annotations

from pydantic import BaseModel, Field


class MobileSelfOnboardRequest(BaseModel):
    legal_name: str = Field(default="", max_length=128)
    mobile_no: str = Field(default="", max_length=40)
    email: str = Field(default="", max_length=255)
    preferred_currency: str = Field(default="", max_length=12)
    wallet_currencies: list[str] = Field(default_factory=list)
