# Merchant Webhook Signing Contract

## Inputs

- `nonce`: unique string per credential
- `payload`: raw body content
- `secret_hash`: value associated with merchant API credential

## Signature

1. Compute `payload_hash = sha256(payload)`.
2. Compute signature:
   - `hmac_sha256(secret_hash, "{nonce}:{payload_hash}")`

## Validation Rules

1. Signature must match.
2. Nonce must not be reused per credential.
3. Replay is detected when nonce already exists.

## Recorded Fields

- `signature_valid`
- `replay_detected`
- `response_code`

Records are stored in `MerchantWebhookEvent`.
