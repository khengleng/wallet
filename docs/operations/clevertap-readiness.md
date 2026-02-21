# CleverTap Readiness (Web + Future Mobile)

This platform now has a unified analytics event store (`wallets_demo.AnalyticsEvent`) and optional CleverTap forwarding.

## Environment Variables
- `CLEVERTAP_ENABLED` (`true` / `false`)
- `CLEVERTAP_ACCOUNT_ID`
- `CLEVERTAP_PASSCODE`
- `CLEVERTAP_REGION` (default `us1`)
- `CLEVERTAP_EVENT_ENDPOINT` (optional override)
- `CLEVERTAP_TIMEOUT_SECONDS` (default `5`)

## Current Tracked Events
- `auth_login_success`
- `auth_login_failed`
- `user_registered`
- `wallet_deposit_requested`
- `wallet_deposit_success`
- `wallet_withdraw_requested`
- `wallet_withdraw_success`
- `wallet_transfer_requested`
- `wallet_transfer_success`
- `merchant_created`
- `merchant_updated`
- `wallet_type_updated`
- `merchant_cashflow_executed`
- `loyalty_event_created`
- `ops_case_created`
- `ops_case_updated`

## Mobile App Plan
Use the same event names and property keys for mobile SDK instrumentation to keep funnel and attribution reports consistent across channels.
