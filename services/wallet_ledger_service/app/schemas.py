from decimal import Decimal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AccountCreateRequest(BaseModel):
    external_owner_id: str = Field(min_length=1, max_length=128)
    currency: str = Field(default="USD", min_length=3, max_length=12)


class MoneyRequest(BaseModel):
    account_id: UUID
    amount: Decimal = Field(gt=0)
    reference_id: str = Field(min_length=1, max_length=128)
    metadata: dict = Field(default_factory=dict)


class TransferRequest(BaseModel):
    from_account_id: UUID
    to_account_id: UUID
    amount: Decimal = Field(gt=0)
    reference_id: str = Field(min_length=1, max_length=128)
    metadata: dict = Field(default_factory=dict)


class LedgerResult(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    account_id: UUID
    balance: Decimal
    reference_id: str
    idempotency_key: str


class TransferResult(BaseModel):
    from_account_id: UUID
    to_account_id: UUID
    from_balance: Decimal
    to_balance: Decimal
    reference_id: str
    idempotency_key: str
