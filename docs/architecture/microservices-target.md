# Microservices Target Architecture

## Service Boundaries
- `identity-service`: authentication, MFA, device/session management, account recovery.
- `wallet-ledger-service`: immutable ledger, balances, transfers, refunds, idempotency.
- `risk-service`: real-time risk scoring, velocity checks, anomaly flags, step-up requirements.
- `notification-service`: email/SMS/push outbox delivery.
- `api-gateway`: authn/authz, WAF, rate limits, request signing, routing.

## Data Ownership
- Database-per-service.
- No cross-service direct table access.
- `wallet-ledger-service` is the source of truth for balance and transaction state.

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

## Current Repo State (Phase 1)
- Production-hardening settings added.
- PostgreSQL-first runtime (no SQLite fallback in production).
- Release migration command separated from web startup.
- Health/readiness endpoints added.
- Deployment scaffolding for K8s and local infra added.
- Extracted services:
  - `services/wallet_ledger_service` (ledger + outbox + service API key)
  - `services/api_gateway_service` (JWT auth + rate limiting + audit logging)
- Ledger DB migrations are now managed with Alembic (`python -m app.migrate`).

## Phase 2 Progress
- Outbox relay worker now supports:
  - `FOR UPDATE SKIP LOCKED` event claiming,
  - retry with exponential backoff,
  - dead-lettering after max attempts,
  - RabbitMQ topic exchange publish.
