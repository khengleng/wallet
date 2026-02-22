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
- Starts CIF in `pending_kyc`.
- Provisions base wallet currency plus any supported currencies requested.
- Freezes wallets while CIF is not active.
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

## 3) Profile

- Method: `GET`
- Path: `/api/mobile/profile/`
- Purpose: return current user profile and CIF profile for mobile self-service.

### Update Profile

- Method: `POST`
- Path: `/api/mobile/profile/`
- Purpose: update non-sensitive profile attributes for current user.

### Request body

```json
{
  "first_name": "John",
  "last_name": "Doe",
  "legal_name": "John Doe",
  "mobile_no": "+85512345678",
  "profile_picture_url": "https://cdn.example.com/profiles/john.png",
  "preferences": {
    "language": "en",
    "timezone": "Asia/Phnom_Penh",
    "theme": "system",
    "preferred_currency": "USD",
    "notifications": {
      "push": true,
      "email": true,
      "sms": false
    }
  }
}
```

### Notes

- Requires existing CIF (onboarding must be completed first).
- Does not allow changing username/email through this endpoint.
- `profile_picture_url` supports HTTP/HTTPS URL.
- Preferences are stored per user and returned in bootstrap/profile payloads.

## 4) Personalization Data Points

- Method: `GET`
- Path: `/api/mobile/personalization/`
- Purpose: returns native personalization payload (segments, widgets, feature flags, preferences).

- Method: `POST`
- Path: `/api/mobile/personalization/signals/`
- Purpose: stores data points collected from mobile usage for personalization.

### Request body

```json
{
  "data_points": {
    "last_screen": "wallet_home",
    "preferred_entry_point": "scan_pay",
    "avg_session_seconds": 420
  }
}
```

## Security Notes

- If CIF status is blocked/closed, self-onboard is rejected with `403`.
- Role and policy controls continue to apply on wallet transactions after onboarding.
- MFA and adaptive controls should be enforced in Keycloak for high-risk actions.
