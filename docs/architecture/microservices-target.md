# Microservices Target Architecture

## Service Boundaries
- `identity-service`: authentication, MFA, device/session management, account recovery.
- `mobile-bff-service`: mobile channel backend-for-frontend (bootstrap/onboarding/balance/statement APIs).
- `wallet-ledger-service`: immutable ledger, balances, transfers, refunds, idempotency.
- `risk-service`: real-time risk scoring, velocity checks, anomaly flags, step-up requirements.
- `notification-service`: email/SMS/push outbox delivery.
- `api-gateway`: authn/authz, WAF, rate limits, request signing, routing.

## Data Ownership
- Database-per-service.
- No cross-service direct table access.
- `wallet-ledger-service` is the source of truth for balance and transaction state.
- Runtime contract:
  - Backoffice web: `BACKOFFICE_DATABASE_URL`
  - Ledger + outbox worker: `LEDGER_DATABASE_URL`
  - Ops/risk API + consumer: `OPS_RISK_DATABASE_URL`
  - Audit exporter: `AUDIT_EXPORT_DATABASE_URL` (or explicit shared `BACKOFFICE_DATABASE_URL`)
  - Production enforcement: set `DATABASE_ISOLATION_MODE=strict`.
  - Validation helper: `python scripts/ops/check_db_isolation.py` (non-zero exit on violations).

## Communication
- Synchronous: REST/gRPC for request/response operations.
- Asynchronous: event bus (Kafka/RabbitMQ) for domain events.
- Required patterns:
  - Outbox for event publishing.
  - Idempotent consumers.
  - Dead-letter queue and replay flow.

## High Availability and Scale
- Run services in Kubernetes with:
  - multiple replicas,
  - pod disruption budgets,
  - horizontal pod autoscaling,
  - rolling deployments.
- PostgreSQL with connection pooling (PgBouncer) and read replicas.
- Redis for rate limits/session/risk cache.

## Security Baseline
- Mandatory MFA for high-risk actions.
- Per-user and per-IP rate limiting at gateway.
- Strict RBAC for admin operations.
- Secure defaults: HTTPS only, secure cookies, HSTS, CSRF protection.
- Signed internal service-to-service auth (mTLS or short-lived JWT).
- Interim zero-trust baseline in this repo:
  - `INTERNAL_AUTH_MODE=hmac` between gateway and ledger,
  - signed request headers with timestamp + nonce + body digest,
  - replay protection and clock-skew validation on ledger ingress.

## Current Repo State (Phase 1)
- Production-hardening settings added.
- PostgreSQL-first runtime (no SQLite fallback in production).
- Release migration command separated from web startup.
- Health/readiness endpoints added.
- Deployment scaffolding for K8s and local infra added.
- Extracted services:
  - `services/identity_service` (OIDC boundary + token/session/device APIs)
  - `services/wallet_ledger_service` (ledger + outbox + service API key)
  - `services/api_gateway_service` (JWT auth + rate limiting + audit logging)
- Ledger DB migrations are now managed with Alembic (`python -m app.migrate`).

## Phase 2 Progress
- Outbox relay worker now supports:
  - `FOR UPDATE SKIP LOCKED` event claiming,
  - retry with exponential backoff,
  - dead-lettering after max attempts,
  - RabbitMQ topic exchange publish.

## Phase 3 Progress
- Added `ops-risk-service`:
  - idempotent event consumer (`processed_events` unique by `event_id`),
  - dead-letter persistence (`dead_letter_events`),
  - replay tooling (`python -m app.replay_dead_letters`),
  - risk alert generation for high-value transactions.
- API gateway now includes:
  - bounded retry with exponential backoff,
  - circuit-breaker behavior for ledger upstream failures.

## Phase 4 Progress
- Added `audit-export-worker`:
  - incremental export of immutable backoffice audit logs to SIEM webhook,
  - HMAC-signed export payload headers,
  - retry with exponential backoff and dead-letter persistence,
  - replay tooling (`python -m app.replay_dead_letters --limit 200`),
  - Prometheus metrics for lag/failures/replay outcomes.
- Added monitoring assets:
  - alert rules: `infra/monitoring/alerts/audit-export-alerts.yml`,
  - dashboard template: `infra/monitoring/dashboards/audit-export-dashboard.json`.
