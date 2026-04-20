/**
 * k6 Script — Software Cryptography Provider: Sign Operation
 *
 * Invokes the sign endpoint directly on the connector (no ILM Core, no authentication).
 *
 * Endpoint:
 *   POST /v1/cryptographyProvider/tokens/{TOKEN_UUID}/keys/{KEY_UUID}/sign
 *
 * Usage:
 *   # Functional smoke (defaults: 1 VU, 30 s)
 *   k6 run connector-sign.js
 *
 *   # Custom UUIDs
 *   k6 run --env TOKEN_UUID=<uuid> --env KEY_UUID=<uuid> connector-sign.js
 *
 *   # Load test with a custom payload
 *   k6 run --env VUS=20 --env DURATION=2m --env DATA_B64=$(base64 -i myfile.bin) connector-sign.js
 *
 *   # Different algorithm
 *   k6 run --env SIG_SCHEME=PKCS1-v1_5 --env DIGEST=SHA-256 connector-sign.js
 *
 * Environment variables:
 *   BASE_URL     Connector base URL                             (default: http://localhost:8230)
 *   TOKEN_UUID   Token instance UUID on the connector           (default: 83f85f72-cee1-469f-9b67-3025c99d93b2)
 *   KEY_UUID     Key item UUID on the connector                 (default: 3fdc00de-0afe-4a70-be52-8f5a7d2aa10e)
 *   SIG_SCHEME   RSA signature scheme: PSS | PKCS1-v1_5         (default: PSS)
 *   DIGEST       Digest algorithm: SHA-256 | SHA-384 | SHA-512  (default: SHA-384)
 *   DATA_B64     Base64-encoded data to sign                    (default: small test string)
 *   VUS          Number of virtual users                        (default: 1)
 *   DURATION     Test duration                                  (default: 30s)
 */

import http from 'k6/http';
import { check } from 'k6';
import { Counter } from 'k6/metrics';

// ─── Configuration ────────────────────────────────────────────────────────────

const BASE_URL   = __ENV.BASE_URL    || 'http://localhost:8230';
const TOKEN_UUID = __ENV.TOKEN_UUID  || '83f85f72-cee1-469f-9b67-3025c99d93b2';
const KEY_UUID   = __ENV.KEY_UUID    || '3fdc00de-0afe-4a70-be52-8f5a7d2aa10e';
const SIG_SCHEME = __ENV.SIG_SCHEME  || 'PSS';
const DIGEST     = __ENV.DIGEST      || 'SHA-384';
// Default: base64("connector-sign-k6-test")
const DATA_B64   = __ENV.DATA_B64    || 'Y29ubmVjdG9yLXNpZ24tazYtdGVzdA==';

// ─── k6 Options ───────────────────────────────────────────────────────────────

export const options = {
    vus:      parseInt(__ENV.VUS      || '1',   10),
    duration: __ENV.DURATION          || '30s',

    summaryTrendStats: ['avg', 'min', 'med', 'max', 'p(90)', 'p(95)', 'p(99)', 'p(99.9)'],

    thresholds: {
        http_req_duration: ['p(95)<500', 'p(99)<2000'],
        http_req_failed:   ['rate<0.01'],
        checks:            ['rate>0.99'],
    },
};

// ─── Metrics ──────────────────────────────────────────────────────────────────

const requestCount = new Counter('sign_requests_total');

// ─── Setup (runs once, result passed to every VU) ─────────────────────────────

export function setup() {
    const url = `${BASE_URL}/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/${KEY_UUID}/sign`;

    // Connector matches signatureAttributes by name, not UUID.
    const payload = JSON.stringify({
        signatureAttributes: [
            {
                name:        'data_rsaSigScheme',
                contentType: 'string',
                version:     'v2',
                content:     [{ data: SIG_SCHEME }],
            },
            {
                name:        'data_sigDigest',
                contentType: 'string',
                version:     'v2',
                content:     [{ data: DIGEST }],
            },
        ],
        data: [{ data: DATA_B64 }],
    });

    return { url, payload };
}

// ─── Default VU function ──────────────────────────────────────────────────────

export default function (data) {
    const res = http.post(data.url, data.payload, {
        headers: {
            'Content-Type': 'application/json',
            'Accept':       'application/json',
        },
    });

    requestCount.add(1);

    check(res, {
        'status is 200':                    (r) => r.status === 200,
        'response has signatures array':    (r) => {
            try {
                const body = r.json();
                return Array.isArray(body.signatures) && body.signatures.length > 0;
            } catch (_) {
                return false;
            }
        },
        'signatures[0].data is non-empty': (r) => {
            try {
                const sig = r.json().signatures[0].data;
                return typeof sig === 'string' && sig.length > 0;
            } catch (_) {
                return false;
            }
        },
    });
}

// ─── Teardown (runs once after all VUs finish) ────────────────────────────────

export function teardown(data) {
    const durationSec = parseInt(__ENV.DURATION || '30', 10);
    const total = requestCount.name; // informational label only
    // k6 exposes __ENV but not accumulated counter values in teardown;
    // throughput is printed as part of the summary via handleSummary below.
    void data; void total; void durationSec;
}

// ─── Custom summary ───────────────────────────────────────────────────────────

export function handleSummary(data) {
    const duration  = data.state.testRunDurationMs / 1000;
    const total     = data.metrics['http_reqs']?.values?.count   ?? 0;
    const throughput = (total / duration).toFixed(2);

    const p95 = (data.metrics['http_req_duration']?.values?.['p(95)'] ?? 0).toFixed(2);
    const p99 = (data.metrics['http_req_duration']?.values?.['p(99)'] ?? 0).toFixed(2);

    const lines = [
        '',
        '┌────────────────────────────────────────┐',
        '│           SIGN OPERATION SUMMARY       │',
        '├────────────────────────────────────────┤',
        `│  Total requests : ${String(total).padEnd(20)} │`,
        `│  Duration       : ${(duration.toFixed(1) + ' s').padEnd(20)} │`,
        `│  Throughput     : ${(throughput + ' req/s').padEnd(20)} │`,
        `│  p(95) latency  : ${(p95 + ' ms').padEnd(20)} │`,
        `│  p(99) latency  : ${(p99 + ' ms').padEnd(20)} │`,
        '└────────────────────────────────────────┘',
        '',
    ].join('\n');

    return {
        stdout: lines,
    };
}

/*
* Equivalent curl command:
curl -X POST "http://localhost:8230/v1/cryptographyProvider/tokens/83f85f72-cee1-469f-9b67-3025c99d93b2/keys/3fdc00de-0afe-4a70-be52-8f5a7d2aa10e/sign"   \
  -H "Content-Type: application/json"  -H "Accept: application/json" -d '{
    "signatureAttributes": [
      {
        "name": "data_rsaSigScheme",
        "contentType": "string",
        "version": "v2",
        "content": [{ "data": "PSS" }]
      },
      {
        "name": "data_sigDigest",
        "contentType": "string",
        "version": "v2",
        "content": [{ "data": "SHA-384" }]
      }
    ],
    "data": [{ "data": "Y29ubmVjdG9yLXNpZ24tazYtdGVzdA==" }]
  }'
*/