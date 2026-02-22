# Mobile Baseline (Microfrontend-Ready)

This directory is the implementation baseline for the mobile modular architecture.
It follows the blueprint in `docs/architecture/mobile-microfrontend-blueprint.md`.

## Structure
- `app-shell/`: bootstrap, auth guard, navigation root, feature manifest loader.
- `platform-sdk/`: shared identity, gateway client, secure storage, telemetry adapter.
- `modules/`: domain modules with independent ownership boundaries.
- `shared/`: cross-module contracts, design system, and test utilities.

## Rules
- Modules must not mutate each other's state directly.
- Financial write APIs must include idempotency keys.
- Auth/session flows must use OIDC + PKCE and secure storage.
- Backend authorization remains source of truth.

## Current Status
- Scaffold only (no runtime mobile implementation yet).
