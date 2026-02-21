# Wallet Ledger Events

All events are emitted through the outbox table and published asynchronously.

## Broker Contract
- Exchange: `wallet.events` (topic, configurable)
- Routing key format: `ledger.<event_type_with_dots_replaced_by_underscores>`
  - Example: `ledger.ledger_transfer`
- Message headers:
  - `event_id`
  - `event_type`
  - `idempotency_key`
  - `reference_id`

## Delivery Semantics
- Publisher uses transactional outbox records.
- Worker retries failed publish attempts with exponential backoff.
- Events that exceed retry limit move to outbox status `dead_letter`.

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
