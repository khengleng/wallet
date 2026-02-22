# Mobile BFF API

Mobile app channel should call `mobile-bff-service` instead of calling web portal endpoints directly.

## Authentication
- Header: `Authorization: Bearer <access_token>`
- Token is introspected through `identity-service`.

## Endpoints

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

## Notes
- CIF starts in `pending_kyc` during self onboarding.
- Wallets are frozen until activation via approved maker-checker class upgrade.
