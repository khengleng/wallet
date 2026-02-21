# Wallet Ledger Events

All events are emitted through the outbox table and published asynchronously.

## Event Types
- `ledger.deposit`
- `ledger.withdraw`
- `ledger.transfer`

## Common Fields
- `idempotency_key` (string): dedupe key for exactly-once semantics at consumers.
- `reference_id` (string): business reference.

## ledger.deposit payload
```json
{
  "account_id": "uuid",
  "balance": "decimal-string",
  "reference_id": "ext-ref-123",
  "idempotency_key": "idem-123"
}
```

## ledger.withdraw payload
```json
{
  "account_id": "uuid",
  "balance": "decimal-string",
  "reference_id": "ext-ref-123",
  "idempotency_key": "idem-123"
}
```

## ledger.transfer payload
```json
{
  "from_account_id": "uuid",
  "to_account_id": "uuid",
  "from_balance": "decimal-string",
  "to_balance": "decimal-string",
  "reference_id": "ext-ref-123",
  "idempotency_key": "idem-123"
}
```
