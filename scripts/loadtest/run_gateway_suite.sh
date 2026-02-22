#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESULTS_DIR="${ROOT_DIR}/scripts/loadtest/results"
TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SUITE_DIR="${RESULTS_DIR}/${TIMESTAMP}"

if ! command -v k6 >/dev/null 2>&1; then
  echo "ERROR: k6 is not installed." >&2
  exit 1
fi

required_vars=("BASE_URL" "BEARER_TOKEN" "ACCOUNT_ID")
for var in "${required_vars[@]}"; do
  if [[ -z "${!var:-}" ]]; then
    echo "ERROR: ${var} is required." >&2
    exit 1
  fi
done

mkdir -p "${SUITE_DIR}"

echo "Running baseline load test..."
k6 run \
  -e BASE_URL="${BASE_URL}" \
  -e BEARER_TOKEN="${BEARER_TOKEN}" \
  -e ACCOUNT_ID="${ACCOUNT_ID}" \
  -e IDEMPOTENCY_PREFIX="${IDEMPOTENCY_PREFIX:-k6}" \
  --summary-export "${SUITE_DIR}/baseline-summary.json" \
  "${ROOT_DIR}/scripts/loadtest/k6_gateway_baseline.js"

echo "Running spike load test..."
k6 run \
  -e BASE_URL="${BASE_URL}" \
  -e BEARER_TOKEN="${BEARER_TOKEN}" \
  -e ACCOUNT_ID="${ACCOUNT_ID}" \
  --summary-export "${SUITE_DIR}/spike-summary.json" \
  "${ROOT_DIR}/scripts/loadtest/k6_gateway_spike.js"

echo "Load test suite finished."
echo "Results directory: ${SUITE_DIR}"
