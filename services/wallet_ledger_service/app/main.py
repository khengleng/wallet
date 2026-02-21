from typing import Annotated
from uuid import UUID
import time
from threading import Lock

from fastapi import Depends, FastAPI, Header, HTTPException, Response
from sqlalchemy import text
from sqlalchemy.orm import Session
import json
import logging

from .config import settings
from .db import SessionLocal
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

logger = logging.getLogger("wallet_ledger.audit")
metrics_lock = Lock()
metrics_counters = {
    "requests_total": 0,
    "accounts_created_total": 0,
    "deposits_success_total": 0,
    "withdrawals_success_total": 0,
    "transfers_success_total": 0,
    "insufficient_funds_total": 0,
    "not_found_total": 0,
}
APP_START_MONOTONIC = time.monotonic()


def _inc_counter(key: str, value: int = 1) -> None:
    with metrics_lock:
        metrics_counters[key] = int(metrics_counters.get(key, 0)) + value


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_service_api_key(
    x_service_api_key: Annotated[str | None, Header(alias="X-Service-Api-Key")] = None,
):
    if not settings.service_api_key:
        logger.error(
            json.dumps(
                {
                    "event": "service_auth_unconfigured",
                    "service": settings.service_name,
                }
            )
        )
        raise HTTPException(status_code=503, detail="Service API key is not configured")
    if x_service_api_key != settings.service_api_key:
        logger.warning(
            json.dumps(
                {"event": "service_auth_failed", "service": settings.service_name}
            )
        )
        raise HTTPException(status_code=401, detail="Unauthorized")


def require_metrics_token(
    x_metrics_token: Annotated[str | None, Header(alias="X-Metrics-Token")] = None,
):
    if settings.metrics_token and x_metrics_token != settings.metrics_token:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/healthz")
def healthz():
    return {"status": "ok", "service": settings.service_name}


@app.get("/metrics")
def metrics(_: Annotated[None, Depends(require_metrics_token)]):
    uptime_seconds = int(time.monotonic() - APP_START_MONOTONIC)
    with metrics_lock:
        snapshot = dict(metrics_counters)
    lines = [
        "# HELP wallet_ledger_uptime_seconds Process uptime in seconds.",
        "# TYPE wallet_ledger_uptime_seconds gauge",
        f"wallet_ledger_uptime_seconds {uptime_seconds}",
        "# HELP wallet_ledger_requests_total Total handled ledger requests.",
        "# TYPE wallet_ledger_requests_total counter",
        f"wallet_ledger_requests_total {snapshot['requests_total']}",
        "# HELP wallet_ledger_accounts_created_total Total created accounts.",
        "# TYPE wallet_ledger_accounts_created_total counter",
        f"wallet_ledger_accounts_created_total {snapshot['accounts_created_total']}",
        "# HELP wallet_ledger_deposits_success_total Successful deposits.",
        "# TYPE wallet_ledger_deposits_success_total counter",
        f"wallet_ledger_deposits_success_total {snapshot['deposits_success_total']}",
        "# HELP wallet_ledger_withdrawals_success_total Successful withdrawals.",
        "# TYPE wallet_ledger_withdrawals_success_total counter",
        f"wallet_ledger_withdrawals_success_total {snapshot['withdrawals_success_total']}",
        "# HELP wallet_ledger_transfers_success_total Successful transfers.",
        "# TYPE wallet_ledger_transfers_success_total counter",
        f"wallet_ledger_transfers_success_total {snapshot['transfers_success_total']}",
        "# HELP wallet_ledger_insufficient_funds_total Insufficient funds errors.",
        "# TYPE wallet_ledger_insufficient_funds_total counter",
        f"wallet_ledger_insufficient_funds_total {snapshot['insufficient_funds_total']}",
        "# HELP wallet_ledger_not_found_total Account not found errors.",
        "# TYPE wallet_ledger_not_found_total counter",
        f"wallet_ledger_not_found_total {snapshot['not_found_total']}",
    ]
    return Response(content="\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.get("/readyz")
def readyz(db: Annotated[Session, Depends(get_db)]):
    db.execute(text("SELECT 1"))
    return {"status": "ready"}


@app.post("/v1/accounts")
def create_account_endpoint(
    payload: AccountCreateRequest,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_service_api_key)],
):
    _inc_counter("requests_total")
    with db.begin():
        account = create_account(
            db, owner_id=payload.external_owner_id, currency=payload.currency
        )
    _inc_counter("accounts_created_total")
    logger.info(
        json.dumps(
            {
                "event": "account_created",
                "account_id": str(account.id),
                "external_owner_id": payload.external_owner_id,
                "currency": payload.currency,
            }
        )
    )
    return {
        "account_id": str(account.id),
        "currency": account.currency,
        "balance": str(account.balance),
    }


@app.get("/v1/accounts/{account_id}")
def get_account_endpoint(
    account_id: UUID,
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_service_api_key)],
):
    _inc_counter("requests_total")
    account = get_account(db, account_id=account_id)
    if account is None:
        _inc_counter("not_found_total")
        raise HTTPException(status_code=404, detail="Account not found")
    logger.info(
        json.dumps({"event": "account_read", "account_id": str(account.id)})
    )
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
    _: Annotated[None, Depends(require_service_api_key)],
):
    _inc_counter("requests_total")
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
        _inc_counter("not_found_total")
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    else:
        _inc_counter("deposits_success_total")
    finally:
        logger.info(
            json.dumps(
                {
                    "event": "transaction_deposit_attempt",
                    "account_id": str(payload.account_id),
                    "reference_id": payload.reference_id,
                    "idempotency_key": idempotency_key,
                }
            )
        )


@app.post("/v1/transactions/withdraw", response_model=LedgerResult)
def withdraw_endpoint(
    payload: MoneyRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_service_api_key)],
):
    _inc_counter("requests_total")
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
        _inc_counter("not_found_total")
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InsufficientFundsError as exc:
        _inc_counter("insufficient_funds_total")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    else:
        _inc_counter("withdrawals_success_total")
    finally:
        logger.info(
            json.dumps(
                {
                    "event": "transaction_withdraw_attempt",
                    "account_id": str(payload.account_id),
                    "reference_id": payload.reference_id,
                    "idempotency_key": idempotency_key,
                }
            )
        )


@app.post("/v1/transactions/transfer", response_model=TransferResult)
def transfer_endpoint(
    payload: TransferRequest,
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
    db: Annotated[Session, Depends(get_db)],
    _: Annotated[None, Depends(require_service_api_key)],
):
    _inc_counter("requests_total")
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
        _inc_counter("not_found_total")
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except InsufficientFundsError as exc:
        _inc_counter("insufficient_funds_total")
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    else:
        _inc_counter("transfers_success_total")
    finally:
        logger.info(
            json.dumps(
                {
                    "event": "transaction_transfer_attempt",
                    "from_account_id": str(payload.from_account_id),
                    "to_account_id": str(payload.to_account_id),
                    "reference_id": payload.reference_id,
                    "idempotency_key": idempotency_key,
                }
            )
        )
