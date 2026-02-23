#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE_NAME:-${RAILWAY_SERVICE_NAME:-web}}"

if [[ "$SERVICE" == "mobile-bff-service" || "$SERVICE" == "mobile-bff" ]]; then
  cd services/mobile_bff_service
  exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}" --workers "${UVICORN_WORKERS:-2}"
else
  cd demo_project
  python manage.py migrate --noinput
  exec gunicorn demo_project_app.wsgi:application -c ../gunicorn.conf.py
fi

