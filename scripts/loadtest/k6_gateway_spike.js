import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    traffic_spike: {
      executor: 'ramping-arrival-rate',
      startRate: 200,
      timeUnit: '1s',
      preAllocatedVUs: 500,
      maxVUs: 5000,
      stages: [
        { target: 1000, duration: '2m' },
        { target: 5000, duration: '5m' },
        { target: 10000, duration: '5m' },
        { target: 0, duration: '2m' },
      ],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.02'],
    http_req_duration: ['p(95)<500', 'p(99)<1200'],
  },
};

const baseUrl = __ENV.BASE_URL || 'http://localhost:8082';
const bearer = __ENV.BEARER_TOKEN || '';
const accountId = __ENV.ACCOUNT_ID || '';

export default function () {
  if (!bearer || !accountId) {
    throw new Error('Set BEARER_TOKEN and ACCOUNT_ID env vars before running this script.');
  }

  const res = http.get(`${baseUrl}/v1/accounts/${accountId}`, {
    headers: { Authorization: `Bearer ${bearer}` },
  });
  check(res, {
    'status is 200': (r) => r.status === 200,
  });
}
