#!/bin/sh
set -eu

RESOLVE_TIMEOUT="${ALERTMANAGER_RESOLVE_TIMEOUT:-5m}"
GROUP_WAIT="${ALERTMANAGER_GROUP_WAIT:-30s}"
GROUP_INTERVAL="${ALERTMANAGER_GROUP_INTERVAL:-5m}"
REPEAT_INTERVAL="${ALERTMANAGER_REPEAT_INTERVAL:-4h}"
WEBHOOK_URL="${ALERTMANAGER_WEBHOOK_URL:-}"
SLACK_WEBHOOK_URL="${ALERTMANAGER_SLACK_WEBHOOK_URL:-}"
SLACK_CHANNEL="${ALERTMANAGER_SLACK_CHANNEL:-#wallet-alerts}"
WEB_LISTEN_PORT="${PORT:-9093}"

RECEIVERS="  - name: default-log"
ROUTES=""

if [ -n "${WEBHOOK_URL}" ]; then
  RECEIVERS="${RECEIVERS}
  - name: webhook-notifications
    webhook_configs:
      - url: '${WEBHOOK_URL}'
        send_resolved: true"
  ROUTES="${ROUTES}
    - receiver: webhook-notifications"
fi

if [ -n "${SLACK_WEBHOOK_URL}" ]; then
  RECEIVERS="${RECEIVERS}
  - name: slack-notifications
    slack_configs:
      - api_url: '${SLACK_WEBHOOK_URL}'
        channel: '${SLACK_CHANNEL}'
        send_resolved: true
        title: '[{{ .Status | toUpper }}] {{ .CommonLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.summary }} - {{ .Annotations.description }}\\n{{ end }}'"
  ROUTES="${ROUTES}
    - receiver: slack-notifications"
fi

cat > /etc/alertmanager/alertmanager.yml <<CONFIG
global:
  resolve_timeout: ${RESOLVE_TIMEOUT}

route:
  receiver: default-log
  group_by: ['alertname', 'service', 'severity']
  group_wait: ${GROUP_WAIT}
  group_interval: ${GROUP_INTERVAL}
  repeat_interval: ${REPEAT_INTERVAL}
${ROUTES:+  routes:${ROUTES}}

receivers:
${RECEIVERS}
CONFIG

exec /bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/alertmanager \
  --web.listen-address=":${WEB_LISTEN_PORT}"
