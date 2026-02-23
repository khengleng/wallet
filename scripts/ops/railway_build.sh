#!/usr/bin/env bash
set -euo pipefail

SERVICE="${SERVICE_NAME:-${RAILWAY_SERVICE_NAME:-web}}"

if [[ "$SERVICE" == "mobile-bff-service" || "$SERVICE" == "mobile-bff" ]]; then
  python -m pip install --upgrade pip
  python -m pip install -r services/mobile_bff_service/requirements.txt
else
  cd demo_project
  python manage.py collectstatic --noinput
fi

