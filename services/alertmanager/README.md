# Alertmanager Service

Alert routing service for Prometheus alert delivery.

## Railway Root Directory
Set the Railway service root to:

`services/alertmanager`

## Optional Env Vars
- `ALERTMANAGER_WEBHOOK_URL` (generic webhook target)
- `ALERTMANAGER_SLACK_WEBHOOK_URL` (Slack incoming webhook URL)
- `ALERTMANAGER_SLACK_CHANNEL` (default `#wallet-alerts`)
- `ALERTMANAGER_RESOLVE_TIMEOUT` (default `5m`)
- `ALERTMANAGER_GROUP_WAIT` (default `30s`)
- `ALERTMANAGER_GROUP_INTERVAL` (default `5m`)
- `ALERTMANAGER_REPEAT_INTERVAL` (default `4h`)

If no webhook/slack URL is configured, alerts are retained in Alertmanager UI only.
