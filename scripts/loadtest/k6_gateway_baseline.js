import http from 'k6/http';
import { check, sleep } from 'k6';

export const options = {
  stages: [
    { duration: '2m', target: 200 },
    { duration: '5m', target: 200 },
    { duration: '2m', target: 1000 },
    { duration: '5m', target: 1000 },
    { duration: '2m', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<400', 'p(99)<900'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:8082';
const bearer = __ENV.BEARER_TOKEN || '';
const idempotencyPrefix = __ENV.IDEMPOTENCY_PREFIX || 'k6';

function authHeaders(extra = {}) {
  return {
    headers: {
      Authorization: `Bearer ${bearer}`,
      'Content-Type': 'application/json',
      ...extra,
    },
  };
}

export default function () {
  const accountId = __ENV.ACCOUNT_ID;
  if (!bearer || !accountId) {
    throw new Error('Set BEARER_TOKEN and ACCOUNT_ID env vars before running this script.');
  }

  const readResp = http.get(`${baseUrl}/v1/accounts/${accountId}`, authHeaders());
  check(readResp, {
    'account read status is 200': (r) => r.status === 200,
  });

  const depositBody = JSON.stringify({
    account_id: accountId,
    amount: '1.00',
    reference_id: `${idempotencyPrefix}-dep-${__VU}-${__ITER}`,
    meta: { source: 'k6-baseline' },
  });
  const depResp = http.post(
    `${baseUrl}/v1/transactions/deposit`,
    depositBody,
    authHeaders({ 'Idempotency-Key': `${idempotencyPrefix}-dep-${__VU}-${__ITER}` })
  );
  check(depResp, {
    'deposit status is 200': (r) => r.status === 200,
  });

  sleep(0.25);
}
