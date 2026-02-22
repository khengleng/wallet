# Mobile Microfrontend Blueprint (Preparation)

## Objective
Prepare a mobile architecture that supports:
- independent domain delivery,
- secure financial transactions,
- high scale and high availability,
- future iOS/Android feature velocity without monolithic app coupling.

This document defines target architecture and delivery standards only. No mobile implementation is included here.

## Scope
- Mobile app shell and domain module boundaries.
- Contract between mobile frontends and backend services.
- Security, observability, release, and governance model.
- Phased execution plan for development teams.

## Non-Goals
- Building screens/components in this phase.
- Migrating backend APIs in this document.
- Store submission details.

## Recommended Mobile Microfrontend Model
For mobile, use a **modular app shell** pattern (microfrontend equivalent), not browser-style runtime composition.

- Single `App Shell` controls boot, auth session, navigation root, feature flags, and remote config.
- Domain features are isolated modules/packages owned by different teams.
- Module activation is controlled by role, risk state, region, and feature flag.
- Shared platform SDK handles auth tokens, encrypted storage, API client, telemetry, and policy enforcement.

## Target Runtime Architecture
- `App Shell`
  - startup orchestration
  - secure session bootstrap
  - feature manifest loading
  - global navigation and deep-link routing
- `Platform SDK` (shared)
  - identity/session client
  - API gateway client
  - signed request/idempotency helpers
  - encrypted keychain/keystore wrapper
  - analytics and logging adapter
- `Domain Modules`
  - loaded as internal packages, release-gated by flags
  - no direct module-to-module data mutation
  - communication through typed contracts/events

## Proposed Domain Modules
- `auth-module`
  - login, MFA, device binding, session recovery
- `customer-module`
  - CIF profile, KYC/KYB status, linked wallets
- `wallet-module`
  - balances, statements, top-up, withdrawal
- `transfer-module`
  - B2B, B2C, C2B, P2G, G2P flows
- `fx-module`
  - quote, conversion, rate lock, source transparency
- `merchant-module`
  - merchant wallet, settlement status, loyalty features
- `treasury-finance-module`
  - treasury actions and finance views (role restricted)
- `ops-support-module`
  - case creation, complaint/dispute status tracking
- `settings-security-module`
  - devices, sessions, PIN/password controls, alerts
- `assistant-module`
  - ChatGPT-like conversational assistant for wallet guidance and contextual actions

## Backend Integration Contract
Mobile app should not call internal microservices directly.

- Primary path: `api-gateway-service` for transactional APIs.
- Mobile experience path: `mobile-bff-service` for channel-specific profile/personalization/assistant APIs.
- Identity path: `identity-service` for token/session/device/recovery flows.
- Notifications path: OneSignal/CleverTap SDKs via controlled adapter only.
- Role enforcement:
  - backend remains source of truth for authorization,
  - mobile only hides/disables UI capabilities based on issued claims and feature flags.

## Navigation and State Boundaries
- App shell owns global navigation stack and authentication guard.
- Each domain module owns only local state and local routes.
- Shared global state is limited to:
  - authenticated user context,
  - role/permission claims,
  - selected wallet/currency context,
  - feature flags and policy constraints.
- Use event contracts for cross-module updates (example: `wallet_balance_updated`).

## Security Baseline for Mobile
- OIDC Authorization Code + PKCE.
- Short-lived access token; refresh-token rotation.
- Device registration with `identity-service`.
- Store tokens only in secure OS storage (Keychain/Keystore).
- Root/jailbreak detection policy + risk step-up.
- Certificate pinning for production APIs.
- Idempotency key required for financial write actions.
- Server-side anti-replay and HMAC verification remain authoritative.

## Feature Flag and Remote Config Strategy
- App shell fetches signed feature manifest on boot.
- Manifest includes:
  - module enablement,
  - min app version,
  - role requirements,
  - kill switch.
- Fail-safe behavior:
  - if manifest unavailable, fallback to last known signed config.
  - high-risk modules default to disabled on signature/expiry failure.

## Observability and Product Analytics
- Use a shared telemetry adapter in platform SDK.
- Operational telemetry:
  - API latency/failure,
  - auth/session failure rates,
  - transaction error taxonomy.
- Product analytics:
  - continue existing event naming from `docs/operations/clevertap-readiness.md`.
  - append `channel=mobile` and `module=<domain-module>`.

## CI/CD and Release Model
- Monorepo with package-level ownership and CODEOWNERS rules.
- Build matrix:
  - module unit tests,
  - integration tests for module contracts,
  - end-to-end happy paths for critical money movement.
- Release tracks:
  - store releases for shell/runtime changes,
  - OTA/content updates only for approved non-native-safe changes.
- Mandatory gates for production:
  - security scan pass,
  - dependency vulnerability threshold,
  - critical flow e2e pass.

## Performance and Reliability Budgets
- App cold start target: `< 2.5s` on reference device tier.
- Screen transition target: `< 300ms` interaction latency.
- Crash-free sessions target: `>= 99.8%`.
- API client timeout/retry policy must align with gateway circuit-breaker behavior.

## Team Ownership Model
- One team per major module with clear API and UX ownership.
- Platform team owns:
  - app shell,
  - platform SDK,
  - design system,
  - security policy enforcement.
- Domain teams own:
  - module features,
  - module tests,
  - module analytics completeness.

## Suggested Repository Layout (Future)
```text
mobile/
  app-shell/
  platform-sdk/
  modules/
    auth/
    customer/
    wallet/
    transfer/
    fx/
    merchant/
    treasury-finance/
    ops-support/
    settings-security/
  shared/
    design-system/
    contracts/
    test-utils/
```

## Phased Execution Plan
1. Foundation
- establish app shell, platform SDK, auth bootstrap, feature manifest verification.
2. Core Wallet Flows
- deliver `customer`, `wallet`, `transfer`, `fx` modules with strict idempotency and telemetry.
3. Business Operations
- deliver `merchant`, `treasury-finance`, `ops-support` modules with RBAC gating.
4. Hardening
- performance tuning, chaos/failure drills, security penetration test, observability SLO rollout.

## Readiness Checklist Before Implementation
- Identity endpoints finalized (`identity-service`) for mobile session/device lifecycle.
- Gateway contract versioning agreed for mobile clients.
- Feature-flag governance and rollout approval process defined.
- Mobile threat model and secure coding baseline signed off.
- QA test data strategy for multi-currency and maker-checker flows approved.
