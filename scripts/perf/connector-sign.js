/**
 * k6 Script — Software Cryptography Provider: Sign Operation on an RSA private key
 *
 * Invokes the sign endpoint directly on the connector (no ILM Core, no authentication).
 * A dedicated token instance and RSA key pair are created in setup() and destroyed in teardown().
 *
 * Endpoints used:
 *   POST   /v1/cryptographyProvider/tokens                                  (setup: create token)
 *   POST   /v1/cryptographyProvider/tokens/{tokenUuid}/keys/pair            (setup: create key pair)
 *   POST   /v1/cryptographyProvider/tokens/{tokenUuid}/keys/{keyUuid}/sign  (benchmarking loop)
 *   DELETE /v1/cryptographyProvider/tokens/{tokenUuid}/keys/{keyUuid}       (teardown: destroy keys)
 *   DELETE /v1/cryptographyProvider/tokens/{tokenUuid}                      (teardown: remove token if created)
 *
 * Usage:
 *   # Functional smoke (defaults: 1 VU, 30 s)
 *   k6 run connector-sign.js
 *
 *   # Load test with a custom payload
 *   k6 run --env VUS=20 --env DURATION=2m --env DATA_B64=$(base64 -i myfile.bin) connector-sign.js
 *
 *   # Different algorithm
 *   k6 run --env SIG_SCHEME=PKCS1-v1_5 --env DIGEST=SHA-256 connector-sign.js
 *
 *   # Custom token/key identity
 *   k6 run --env TOKEN_NAME=myPerfToken --env KEY_ALIAS=myKey --env KEY_SIZE=4096 connector-sign.js
 *
 * Environment variables:
 *   BASE_URL     Connector base URL                             (default: http://localhost:8230)
 *   TOKEN_NAME   Name for the ephemeral token instance          (default: k6PerfToken)
 *   KEY_ALIAS    Alias for the ephemeral key pair               (default: k6RsaKey)
 *   KEY_SIZE     RSA key size in bits: 1024 | 2048 | 4096       (default: 2048)
 *   SIG_SCHEME   RSA signature scheme: PSS | PKCS1-v1_5         (default: PSS)
 *   DIGEST       Digest algorithm: SHA-256 | SHA-384 | SHA-512  (default: SHA-384)
 *   DATA_B64     Base64-encoded data to sign                    (default: small test string)
 *   VUS          Number of virtual users                        (default: 1)
 *   DURATION     Test duration                                  (default: 30s)
 */

import http from 'k6/http';
import { check, fail } from 'k6';
import { Counter } from 'k6/metrics';

// ─── Configuration ────────────────────────────────────────────────────────────

const BASE_URL    = __ENV.BASE_URL    || 'http://localhost:8230';
const TOKEN_NAME  = __ENV.TOKEN_NAME  || 'k6PerfToken';
const KEY_ALIAS   = __ENV.KEY_ALIAS   || 'k6RsaKey';
const KEY_SIZE    = parseInt(__ENV.KEY_SIZE || '2048', 10);
const SIG_SCHEME  = __ENV.SIG_SCHEME  || 'PSS';
const DIGEST      = __ENV.DIGEST      || 'SHA-384';
// Default: base64("connector-sign-k6-test")
const DATA_B64    = __ENV.DATA_B64    || 'Y29ubmVjdG9yLXNpZ24tazYtdGVzdA==';

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
    const jsonHeaders = { 'Content-Type': 'application/json', 'Accept': 'application/json' };

    // 1. Discover token creation attributes.
    // GET /v1/cryptographyProvider/SOFT/attributes returns different attribute sets
    // depending on whether tokens already exist:
    //   - No existing tokens → attributes for new-token creation are returned directly.
    //   - Existing tokens    → a data_options selector + a group_loadToken group (with
    //                          a callback) are returned; a separate callback call
    //                          resolves the new-token sub-attributes.
    const tokenTopAttrsRes = http.get(`${BASE_URL}/v1/cryptographyProvider/SOFT/attributes`, { headers: jsonHeaders });
    if (tokenTopAttrsRes.status !== 200) {
        fail(`Token attribute discovery failed (${tokenTopAttrsRes.status}): ${tokenTopAttrsRes.body}`);
    }
    const tokenTopAttrs = tokenTopAttrsRes.json();

    const attrUuid = (attrs, name, contentType) => {
        const attr = attrs.find(a => a.name === name && (contentType ? a.contentType === contentType : true));
        if (!attr || !attr.uuid) {
            fail(`Attribute name='${name}' contentType='${contentType || '(any)'}' not found in: ${JSON.stringify(attrs)}`);
        }
        return attr.uuid;
    };

    let optionsUuid = null;
    let tokenNewAttrs = null;
    if (tokenTopAttrs.some(a => a.name === 'data_options')) {
        optionsUuid = attrUuid(tokenTopAttrs, 'data_options', 'string');
        const tokenNewAttrsRes = http.get(`${BASE_URL}/v1/cryptographyProvider/callbacks/token/new/attributes`, { headers: jsonHeaders });
        if (tokenNewAttrsRes.status !== 200) {
            fail(`Token new-attribute callback failed (${tokenNewAttrsRes.status}): ${tokenNewAttrsRes.body}`);
        }
        tokenNewAttrs = tokenNewAttrsRes.json();
    } else {
        tokenNewAttrs = tokenTopAttrs;
    }

    const actionUuid = attrUuid(tokenNewAttrs, 'data_createTokenAction', 'string');
    const nameUuid   = attrUuid(tokenNewAttrs, 'data_newTokenName',      'string');
    const codeUuid   = attrUuid(tokenNewAttrs, 'data_tokenCode',         'secret');

    // 2. Create ephemeral token instance or reuse existing.
    const tokenPassword = 'k6-test-token-secret';

    let tokenPreexisted = false;
    const existingTokensRes = http.get(`${BASE_URL}/v1/cryptographyProvider/tokens`, { headers: jsonHeaders });
    let tokenUuid = null;
    if (existingTokensRes.status === 200) {
        const existingTokens = existingTokensRes.json();
        if (Array.isArray(existingTokens)) {
            const found = existingTokens.find(t => t.name === TOKEN_NAME);
            if (found) {
                tokenUuid = found.uuid;
                tokenPreexisted = true;
            }
        }
    }

    if (tokenUuid) {
        console.log(`Token already exists — reusing UUID: ${tokenUuid}`);
    } else {
        const attributes = [
            {
                uuid:        actionUuid,
                name:        'data_createTokenAction',
                contentType: 'string',
                version:     'v2',
                content:     [{ reference: 'new', data: 'new' }],
            },
            {
                uuid:        nameUuid,
                name:        'data_newTokenName',
                contentType: 'string',
                version:     'v2',
                content:     [{ data: TOKEN_NAME }],
            },
            {
                uuid:        codeUuid,
                name:        'data_tokenCode',
                contentType: 'secret',
                version:     'v2',
                content:     [{ reference: TOKEN_NAME, data: { secret: tokenPassword } }],
            },
        ];

        if (optionsUuid) {
            attributes.push({
                uuid:        optionsUuid,
                name:        'data_options',
                contentType: 'string',
                version:     'v2',
                content:     [{ reference: 'new', data: 'Create new Token' }],
            });
        }

        const createTokenRes = http.post(
            `${BASE_URL}/v1/cryptographyProvider/tokens`,
            JSON.stringify({
                name: TOKEN_NAME,
                kind: 'SOFT',
                attributes: attributes,
            }),
            { headers: jsonHeaders },
        );

        if (createTokenRes.status !== 200) {
            fail(`Token creation failed (${createTokenRes.status}): ${createTokenRes.body}`);
        }

        tokenUuid = createTokenRes.json().uuid;
    }

    // 3. Discover key-pair creation attributes.
    // GET /v1/cryptographyProvider/tokens/{tokenUuid}/keys/pair/attributes returns:
    //   data_keyAlias (string), data_keyAlgorithm (string), group_keySpec (group).
    const keyPairAttrDefsRes = http.get(`${BASE_URL}/v1/cryptographyProvider/tokens/${tokenUuid}/keys/pair/attributes`, { headers: jsonHeaders });
    if (keyPairAttrDefsRes.status !== 200) {
        fail(`Key-pair attribute discovery failed (${keyPairAttrDefsRes.status}): ${keyPairAttrDefsRes.body}`);
    }
    const keyPairAttrDefs = keyPairAttrDefsRes.json();

    const aliasUuid = attrUuid(keyPairAttrDefs, 'data_keyAlias',     'string');
    const algUuid   = attrUuid(keyPairAttrDefs, 'data_keyAlgorithm', 'string');

    // For RSA: GET /v1/cryptographyProvider/callbacks/keyspec/RSA/attributes
    //   returns data_rsaKeySize (integer).
    const rsaSpecAttrsRes = http.get(`${BASE_URL}/v1/cryptographyProvider/callbacks/keyspec/RSA/attributes`, { headers: jsonHeaders });
    if (rsaSpecAttrsRes.status !== 200) {
        fail(`RSA keyspec attribute callback failed (${rsaSpecAttrsRes.status}): ${rsaSpecAttrsRes.body}`);
    }
    const rsaSpecAttrs = rsaSpecAttrsRes.json();
    const sizeUuid = attrUuid(rsaSpecAttrs, 'data_rsaKeySize', 'integer');

    // 4. Create RSA key pair inside the token.
    const createKeyRes = http.post(
        `${BASE_URL}/v1/cryptographyProvider/tokens/${tokenUuid}/keys/pair`,
        JSON.stringify({
            tokenProfileAttributes: [],
            createKeyAttributes: [
                {
                    uuid:        aliasUuid,
                    name:        'data_keyAlias',
                    contentType: 'string',
                    version:     'v2',
                    content:     [{ data: KEY_ALIAS }],
                },
                {
                    uuid:        algUuid,
                    name:        'data_keyAlgorithm',
                    contentType: 'string',
                    version:     'v2',
                    content:     [{ reference: 'RSA', data: 'RSA' }],
                },
                {
                    uuid:        sizeUuid,
                    name:        'data_rsaKeySize',
                    contentType: 'integer',
                    version:     'v2',
                    content:     [{ reference: `RSA_${KEY_SIZE}`, data: KEY_SIZE }],
                },
            ],
        }),
        { headers: jsonHeaders },
    );

    if (createKeyRes.status !== 200) {
        // Best-effort cleanup before aborting.
        if (!tokenPreexisted) {
            http.del(`${BASE_URL}/v1/cryptographyProvider/tokens/${tokenUuid}`);
        }
        fail(`Key pair creation failed (${createKeyRes.status}): ${createKeyRes.body}`);
    }

    const keyPair        = createKeyRes.json();
    const privateKeyUuid = keyPair.privateKeyData.uuid;
    const publicKeyUuid  = keyPair.publicKeyData.uuid;

    // 5. Build the sign URL and payload used by every VU.
    const url = `${BASE_URL}/v1/cryptographyProvider/tokens/${tokenUuid}/keys/${privateKeyUuid}/sign`;

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

    return { url, payload, tokenUuid, privateKeyUuid, publicKeyUuid, tokenPreexisted };
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
    if (!data || !data.tokenUuid) return;

    // Destroy the private and public keys, then remove the token instance.
    if (data.privateKeyUuid) {
        http.del(`${BASE_URL}/v1/cryptographyProvider/tokens/${data.tokenUuid}/keys/${data.privateKeyUuid}`);
    }
    if (data.publicKeyUuid) {
        http.del(`${BASE_URL}/v1/cryptographyProvider/tokens/${data.tokenUuid}/keys/${data.publicKeyUuid}`);
    }
    if (!data.tokenPreexisted) {
        http.del(`${BASE_URL}/v1/cryptographyProvider/tokens/${data.tokenUuid}`);
    }
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
