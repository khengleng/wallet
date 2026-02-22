# Mobile BFF API

Mobile app channel should call `mobile-bff-service` instead of calling web portal endpoints directly.

## Authentication
- Header: `Authorization: Bearer <access_token>`
- Token is introspected through `identity-service`.

## Endpoints

### `POST /v1/auth/oidc/token`
Exchanges authorization code for tokens using PKCE.

Body:
```json
{
  "code": "auth_code",
  "redirect_uri": "com.wallet.app://oidc/callback",
  "code_verifier": "pkce_code_verifier"
}
```

### `POST /v1/auth/recovery/password-reset-url`
Creates a password reset entrypoint URL through identity service.

Body:
```json
{
  "email": "john@example.com",
  "redirect_uri": "com.wallet.app://recovery-complete"
}
```

### `GET /v1/bootstrap`
Returns authenticated user bootstrap payload (CIF + wallets + onboarding status).

### `POST /v1/onboarding/self`
Body:
```json
{
  "legal_name": "John Doe",
  "mobile_no": "+85512345678",
  "email": "john@example.com",
  "preferred_currency": "USD",
  "wallet_currencies": ["USD", "KHR"]
}
```
Creates or updates CIF and provisions wallets.

### `GET /v1/wallets/balance`
Returns normalized wallet balances for the user.

### `GET /v1/wallets/statement?limit=50&wallet_slug=default&currency=USD`
Returns transaction statement for user wallets.

### `POST /v1/sessions/register`
Registers current mobile device session for account security and session management.

Body:
```json
{
  "session_id": "session-uuid",
  "device_id": "device-fingerprint",
  "expires_at": "2026-02-23T12:00:00Z"
}
```

### `GET /v1/sessions/active`
Returns active sessions for the authenticated user.

### `POST /v1/sessions/revoke`
Revokes one or more active sessions for the authenticated user.

Body:
```json
{
  "session_id": "session-uuid",
  "device_id": "device-fingerprint"
}
```

## Notes
- CIF starts in `pending_kyc` during self onboarding.
- Wallets are frozen until activation via approved maker-checker class upgrade.
