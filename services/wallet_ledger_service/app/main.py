from typing import Annotated
from uuid import UUID

from fastapi import Depends, FastAPI, Header, HTTPException
from sqlalchemy import text
from sqlalchemy.orm import Session

from .config import settings
from .db import Base, SessionLocal, engine
from .schemas import (
    AccountCreateRequest,
    LedgerResult,
    MoneyRequest,
    TransferRequest,
    TransferResult,
)
from .service import (
    InsufficientFundsError,
    apply_deposit,
    apply_transfer,
    apply_withdrawal,
    create_account,
    get_account,
)

app = FastAPI(
    title="Wallet Ledger Service",
    version="1.0.0",
    description="Idempotent, transactional wallet ledger microservice.",
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/readyz")
def readyz(db: Annotated[Session, Depends(get_db)]):
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.post("/v1/accounts")
def create_account_endpoint(
    payload: AccountCreateRequest, db: Annotated[Session, Depends(get_db)]
):
    with db.begin():
        account = create_account(
            db, owner_id=payload.external_owner_id, currency=payload.currency
        )
    return {
        "account_id": str(account.id),
        "currency": account.currency,
        "balance": str(account.balance),
    }


@app.get("/v1/accounts/{account_id}")
def get_account_endpoint(account_id: UUID, db: Annotated[Session, Depends(get_db)]):
    account = get_account(db, account_id=account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")
    return {
        "account_id": str(account.id),
        "external_owner_id": account.external_owner_id,
        "currency": account.currency,
        "balance": str(account.balance),
    }


@app.post("/v1/transactions/deposit", response_model=LedgerResult)
def deposit_endpoint(
    payload: MoneyRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    db: Annotated[Session, Depends(get_db)],
):
    try:
        result = apply_deposit(
            db=db,
            account_id=payload.account_id,
            amount=payload.amount,
            reference_id=payload.reference_id,
            idempotency_key=idempotency_key,
            metadata=payload.metadata,
        )
        return {
            "account_id": result["account_id"],
            "balance": result["balance"],
            "reference_id": result["reference_id"],
            "idempotency_key": result["idempotency_key"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/v1/transactions/withdraw", response_model=LedgerResult)
def withdraw_endpoint(
    payload: MoneyRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    db: Annotated[Session, Depends(get_db)],
):
    try:
        result = apply_withdrawal(
            db=db,
            account_id=payload.account_id,
            amount=payload.amount,
            reference_id=payload.reference_id,
            idempotency_key=idempotency_key,
            metadata=payload.metadata,
        )
        return {
            "account_id": result["account_id"],
            "balance": result["balance"],
            "reference_id": result["reference_id"],
            "idempotency_key": result["idempotency_key"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InsufficientFundsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@app.post("/v1/transactions/transfer", response_model=TransferResult)
def transfer_endpoint(
    payload: TransferRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    db: Annotated[Session, Depends(get_db)],
):
    try:
        result = apply_transfer(
            db=db,
            from_account_id=payload.from_account_id,
            to_account_id=payload.to_account_id,
            amount=payload.amount,
            reference_id=payload.reference_id,
            idempotency_key=idempotency_key,
            metadata=payload.metadata,
        )
        return {
            "from_account_id": result["from_account_id"],
            "to_account_id": result["to_account_id"],
            "from_balance": result["from_balance"],
            "to_balance": result["to_balance"],
            "reference_id": result["reference_id"],
            "idempotency_key": result["idempotency_key"],
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InsufficientFundsError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
