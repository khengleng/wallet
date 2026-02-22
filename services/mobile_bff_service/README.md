# Mobile BFF Service

Dedicated backend-for-frontend service for the mobile app channel.

## Purpose
- Separate mobile channel from web portal channel.
- Keep mobile contracts stable even if web/backoffice evolves.
- Apply channel-specific auth/rate controls and response shaping.

## Endpoints
- `POST /v1/auth/oidc/token` -> PKCE code exchange via identity-service
- `POST /v1/auth/recovery/password-reset-url` -> password reset kickoff URL
- `GET /v1/bootstrap` -> mobile bootstrap data (user, CIF, wallets)
- `GET /v1/profile` -> current mobile profile (user + CIF + preferences)
- `POST /v1/profile` -> update mobile profile (non-sensitive fields, avatar URL, preferences)
- `GET /v1/personalization` -> personalized native MFE layout payload
- `POST /v1/personalization/signals` -> collect user data points for personalization
- `GET /v1/personalization/ai` -> OpenAI-augmented personalization suggestions
- `POST /v1/assistant/chat` -> ChatGPT-like assistant response for native app
- `POST /v1/onboarding/self` -> self onboarding (CIF-first)
- `GET /v1/wallets/balance` -> wallet balances summary
- `GET /v1/wallets/statement` -> wallet transaction statement
- `POST /v1/sessions/register` -> register current device session
- `GET /v1/sessions/active` -> list active sessions for current user
- `POST /v1/sessions/revoke` -> revoke session(s) for current user

## Upstream Dependencies
- `identity-service` for access token introspection.
- `web` service mobile endpoints:
  - `/api/mobile/bootstrap/`
  - `/api/mobile/profile/`
  - `/api/mobile/personalization/`
  - `/api/mobile/personalization/signals/`
  - `/api/mobile/onboarding/self/`
  - `/api/mobile/statement/`

## Required Env Vars
- `ENVIRONMENT=production`
- `SERVICE_NAME=mobile-bff-service`
- `SERVICE_API_KEY` (optional trusted service-call bypass)
- `METRICS_TOKEN`
- `IDENTITY_SERVICE_BASE_URL` (example: `https://identity-service-...`)
- `IDENTITY_SERVICE_API_KEY`
- `IDENTITY_SERVICE_TIMEOUT_SECONDS` (default `3.0`)
- `WEB_SERVICE_BASE_URL` (example: `https://web-production-...`)
- `WEB_SERVICE_TIMEOUT_SECONDS` (default `8.0`)
- `MOBILE_RATE_LIMIT_PER_TOKEN` (default `240/minute`)
- `MOBILE_RATE_LIMIT_PER_IP` (default `180/minute`)
- `OPENAI_API_KEY` (optional; enables `/v1/personalization/ai`)
- `OPENAI_MODEL` (default `gpt-5-mini`)
- `OPENAI_BASE_URL` (default `https://api.openai.com/v1`)
- `OPENAI_TIMEOUT_SECONDS` (default `10.0`)

## Railway Deployment
1. Create a Railway service named `mobile-bff-service`.
2. Set root directory to `services/mobile_bff_service`.
3. Use Nixpacks builder (it reads local `nixpacks.toml`).
4. Set all required environment variables above.
5. Deploy and verify:
   - `GET /healthz`
   - `GET /readyz`
   - `GET /metrics` with `X-Metrics-Token`
