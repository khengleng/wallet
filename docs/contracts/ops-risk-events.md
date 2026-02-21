# Ops/Risk Event Consumption Contract

Consumer: `ops-risk-service`

## Source
- Exchange: `wallet.events` (topic)
- Routing key binding: `ledger.#`

## Headers Required
- `event_id` (globally unique)
- `event_type`
- `idempotency_key`
- `reference_id`

## Idempotency Rule
- `event_id` is unique in `processed_events`.
- Duplicate `event_id` is acknowledged and ignored.

## Dead-Letter Policy
- Processing failures are persisted to `dead_letter_events` with:
  - raw payload
  - headers
  - routing key
  - error reason
- Replay tool republishes pending dead letters to the original exchange/routing key.
