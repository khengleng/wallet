# Platform SDK Baseline

Shared capabilities consumed by all modules:
- identity/session client (`identity-service`),
- API gateway client (`api-gateway-service`),
- idempotency/signing helpers for write operations,
- encrypted keychain/keystore wrapper,
- telemetry adapter (`channel=mobile`).

The SDK is the only allowed integration layer for cross-cutting concerns.
