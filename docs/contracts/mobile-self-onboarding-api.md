# Mobile Self-Onboarding API

This document defines the mobile-app-facing onboarding endpoints currently available in the wallet web service.

## Prerequisite

- Identity: Keycloak OIDC login must be completed first.
- Session: the user must be authenticated before calling these endpoints.
- Target flow: self-registered end-customer onboarding (CIF-first).

## 1) Bootstrap

- Method: `GET`
- Path: `/api/mobile/bootstrap/`
- Purpose: fetch current authenticated user onboarding and wallet state.

### Success response

```json
{
  "ok": true,
  "data": {
    "user": {
      "username": "mobile_user",
      "email": "mobile_user@example.com",
      "first_name": "",
      "last_name": "",
      "wallet_type": "C"
    },
    "onboarding": {
      "is_completed": true,
      "status": "active"
    },
    "cif": {
      "cif_no": "CIF-20260222093000112233-ABCD",
      "legal_name": "Mobile User",
      "mobile_no": "+85512345678",
      "email": "mobile_user@example.com",
      "service_class": "Z"
    },
    "wallets": [
      {
        "wallet_pk": 15,
        "wallet_id": "WAL-0000000015",
        "slug": "default",
        "currency": "USD",
        "balance": "0.00",
        "is_frozen": false
      }
    ]
  }
}
```

### Unauthorized response

```json
{
  "ok": false,
  "error": {
    "code": "unauthorized",
    "message": "Authentication required."
  }
}
```

## 2) Self Onboarding

- Method: `POST`
- Path: `/api/mobile/onboarding/self/`
- Purpose: create/update CIF for current user, assign default customer service class, and provision wallets.

### Request body

```json
{
  "legal_name": "Mobile User",
  "mobile_no": "+85512345678",
  "email": "mobile_user@example.com",
  "preferred_currency": "EUR",
  "wallet_currencies": ["USD", "EUR", "KHR"]
}
```

### Behavior

- Creates CIF if missing (one CIF per user).
- Assigns default service class (config `MOBILE_SELF_ONBOARD_DEFAULT_SERVICE_CLASS`, fallback `Z`, then highest code active policy).
- Sets `wallet_type` to customer (`C`).
- Provisions base wallet currency plus any supported currencies requested.
- Writes audit event `mobile.self_onboard`.

### Success response

- `201` when CIF is created.
- `200` when CIF already exists and is updated.

```json
{
  "ok": true,
  "data": {
    "created": true,
    "cif": {
      "cif_no": "CIF-20260222093000112233-ABCD",
      "status": "active",
      "service_class": "Z"
    },
    "wallets": [
      {
        "wallet_pk": 15,
        "wallet_id": "WAL-0000000015",
        "slug": "default",
        "currency": "USD",
        "balance": "0.00",
        "is_frozen": false
      }
    ]
  }
}
```

## Security Notes

- If CIF status is blocked/closed, self-onboard is rejected with `403`.
- Role and policy controls continue to apply on wallet transactions after onboarding.
- MFA and adaptive controls should be enforced in Keycloak for high-risk actions.
