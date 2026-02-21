from decimal import Decimal
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .models import Account, LedgerEntry, OutboxEvent, ProcessedRequest


class InsufficientFundsError(Exception):
    pass


def _record_processed_request(
    db: Session, idempotency_key: str, response_body: dict
) -> dict:
    record = ProcessedRequest(
        idempotency_key=idempotency_key,
        response_body=response_body,
    )
    db.add(record)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.scalar(
            select(ProcessedRequest).where(
                ProcessedRequest.idempotency_key == idempotency_key
            )
        )
        if existing is None:
            raise
        return existing.response_body
    return response_body


def create_account(db: Session, owner_id: str, currency: str) -> Account:
    account = Account(external_owner_id=owner_id, currency=currency)
    db.add(account)
    db.flush()
    return account


def get_account(db: Session, account_id: UUID, for_update: bool = False) -> Account | None:
    query = select(Account).where(Account.id == account_id)
    if for_update:
        query = query.with_for_update()
    return db.scalar(query)


def apply_deposit(
    db: Session,
    account_id: UUID,
    amount: Decimal,
    reference_id: str,
    idempotency_key: str,
    metadata: dict,
) -> dict:
    with db.begin():
        account = get_account(db, account_id, for_update=True)
        if account is None:
            raise ValueError("Account not found")

        account.balance += amount
        db.add(
            LedgerEntry(
                account_id=account.id,
                direction="credit",
                amount=amount,
                balance_after=account.balance,
                reference_id=reference_id,
                idempotency_key=idempotency_key,
                event_type="ledger.deposit",
                metadata_json=metadata,
            )
        )
        payload = {
            "account_id": str(account.id),
            "balance": str(account.balance),
            "reference_id": reference_id,
            "idempotency_key": idempotency_key,
        }
        db.add(OutboxEvent(event_type="ledger.deposit", payload=payload))
        return _record_processed_request(db, idempotency_key, payload)


def apply_withdrawal(
    db: Session,
    account_id: UUID,
    amount: Decimal,
    reference_id: str,
    idempotency_key: str,
    metadata: dict,
) -> dict:
    with db.begin():
        account = get_account(db, account_id, for_update=True)
        if account is None:
            raise ValueError("Account not found")
        if account.balance < amount:
            raise InsufficientFundsError("Insufficient funds")

        account.balance -= amount
        db.add(
            LedgerEntry(
                account_id=account.id,
                direction="debit",
                amount=amount,
                balance_after=account.balance,
                reference_id=reference_id,
                idempotency_key=idempotency_key,
                event_type="ledger.withdraw",
                metadata_json=metadata,
            )
        )
        payload = {
            "account_id": str(account.id),
            "balance": str(account.balance),
            "reference_id": reference_id,
            "idempotency_key": idempotency_key,
        }
        db.add(OutboxEvent(event_type="ledger.withdraw", payload=payload))
        return _record_processed_request(db, idempotency_key, payload)


def apply_transfer(
    db: Session,
    from_account_id: UUID,
    to_account_id: UUID,
    amount: Decimal,
    reference_id: str,
    idempotency_key: str,
    metadata: dict,
) -> dict:
    with db.begin():
        lock_order = sorted([from_account_id, to_account_id], key=lambda x: str(x))
        accounts = {
            account.id: account
            for account in db.scalars(
                select(Account).where(Account.id.in_(lock_order)).with_for_update()
            ).all()
        }
        sender = accounts.get(from_account_id)
        receiver = accounts.get(to_account_id)
        if sender is None or receiver is None:
            raise ValueError("One or both accounts not found")
        if sender.balance < amount:
            raise InsufficientFundsError("Insufficient funds")

        sender.balance -= amount
        receiver.balance += amount

        db.add_all(
            [
                LedgerEntry(
                    account_id=sender.id,
                    direction="debit",
                    amount=amount,
                    balance_after=sender.balance,
                    reference_id=reference_id,
                    idempotency_key=idempotency_key,
                    event_type="ledger.transfer.out",
                    metadata_json=metadata,
                ),
                LedgerEntry(
                    account_id=receiver.id,
                    direction="credit",
                    amount=amount,
                    balance_after=receiver.balance,
                    reference_id=reference_id,
                    idempotency_key=idempotency_key,
                    event_type="ledger.transfer.in",
                    metadata_json=metadata,
                ),
            ]
        )

        payload = {
            "from_account_id": str(sender.id),
            "to_account_id": str(receiver.id),
            "from_balance": str(sender.balance),
            "to_balance": str(receiver.balance),
            "reference_id": reference_id,
            "idempotency_key": idempotency_key,
        }
        db.add(OutboxEvent(event_type="ledger.transfer", payload=payload))
        return _record_processed_request(db, idempotency_key, payload)
