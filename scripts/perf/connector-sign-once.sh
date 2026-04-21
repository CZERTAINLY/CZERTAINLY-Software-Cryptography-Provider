#!/usr/bin/env bash
# connector-sign-once.sh
#
# Test script which:
#   1. Discover token creation attribute definitions from the connector
#   2. Create a token
#   3. Discover key-pair creation attribute definitions from the connector
#   4. Create an RSA key pair inside that token
#   5. Perform one sign operation
#   6. Destroy the key pair (private + public keys)
#   7. Destroy the token
#
# Attribute UUIDs are fetched live from the connector before each operation so
# the script does not need to hard-code UUIDs that may change between releases.
# (Sign operation attributes have no connector-side attribute endpoint — they
#  are controlled by Core — and are therefore sent by name as documented in the
#  connector source.)
#
# Requires: curl, jq
#
# Usage:
#   ./connector-sign-once.sh
#
# Environment variables (all optional):
#   BASE_URL      Connector base URL                             (default: http://localhost:8230)
#   TOKEN_NAME    Name for the ephemeral token instance          (default: k6PerfToken)
#   TOKEN_PASS    Token password / code                          (default: k6-test-token-secret)
#   KEY_ALIAS     Alias for the ephemeral key pair               (default: k6RsaKey)
#   KEY_SIZE      RSA key size in bits: 1024 | 2048 | 4096       (default: 2048)
#   SIG_SCHEME    RSA signature scheme: PSS | PKCS1-v1_5         (default: PSS)
#   DIGEST        Digest algorithm: SHA-256 | SHA-384 | SHA-512  (default: SHA-384)
#   DATA_B64      Base64-encoded data to sign                    (default: "connector-sign-k6-test")

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8230}"
TOKEN_NAME="${TOKEN_NAME:-k6PerfToken}"
TOKEN_PASS="${TOKEN_PASS:-k6-test-token-secret}"
KEY_ALIAS="${KEY_ALIAS:-k6RsaKey}"
KEY_SIZE="${KEY_SIZE:-2048}"
SIG_SCHEME="${SIG_SCHEME:-PSS}"
DIGEST="${DIGEST:-SHA-384}"
# base64("connector-sign-k6-test")
DATA_B64="${DATA_B64:-Y29ubmVjdG9yLXNpZ24tazYtdGVzdA==}"

# ─── Helpers ──────────────────────────────────────────────────────────────────

die() { echo "ERROR: $*" >&2; exit 1; }

# connector_curl METHOD RELATIVE_PATH [BODY_JSON]
# Makes a call to the connector; dies on non-2xx status.
connector_curl() {
    local method="$1" path="$2" body="${3:-}"
    local tmp http_code response
    tmp=$(mktemp)
    if [[ -n "$body" ]]; then
        http_code=$(curl -s -o "$tmp" -w "%{http_code}" \
            -X "$method" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            -d "$body" \
            "${BASE_URL}${path}")
    else
        http_code=$(curl -s -o "$tmp" -w "%{http_code}" \
            -X "$method" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            "${BASE_URL}${path}")
    fi
    response=$(<"$tmp"); rm -f "$tmp"
    if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
        die "HTTP ${http_code} on ${method} ${path}: ${response}"
    fi
    echo "$response"
}

# attr_uuid ATTRS_JSON NAME CONTENT_TYPE
# Looks up the uuid of a data attribute by name + contentType.
# Exits with a diagnostic if not found.
attr_uuid() {
    local attrs="$1" name="$2" content_type="$3"
    local uuid
    uuid=$(echo "$attrs" | jq -r \
        --arg n "$name" --arg ct "$content_type" \
        'first(.[] | select(.name==$n and .contentType==$ct) | .uuid) // empty')
    if [[ -z "$uuid" ]]; then
        echo "ERROR: Attribute  name='${name}'  contentType='${content_type}'  not found." >&2
        echo "       Received attributes:" >&2
        echo "$attrs" | jq -r \
            '.[] | "         name=\(.name)  contentType=\(.contentType // "(none)")  type=\(.type)"' >&2
        exit 1
    fi
    echo "$uuid"
}

# group_uuid ATTRS_JSON NAME
# Looks up the uuid of a group attribute by name.
group_uuid() {
    local attrs="$1" name="$2"
    local uuid
    uuid=$(echo "$attrs" | jq -r \
        --arg n "$name" \
        'first(.[] | select(.name==$n and .type=="group") | .uuid) // empty')
    if [[ -z "$uuid" ]]; then
        echo "ERROR: Group attribute  name='${name}'  not found." >&2
        echo "       Received attributes:" >&2
        echo "$attrs" | jq -r \
            '.[] | "         name=\(.name)  contentType=\(.contentType // "(none)")  type=\(.type)"' >&2
        exit 1
    fi
    echo "$uuid"
}

# ─── Cleanup (runs on EXIT) ───────────────────────────────────────────────────

TOKEN_UUID=''
TOKEN_PREEXISTED=false
PRIVATE_KEY_UUID=''
PUBLIC_KEY_UUID=''

# connector_curl_soft METHOD RELATIVE_PATH [BODY_JSON]
# Like connector_curl but warns on non-2xx instead of exiting.
# Used inside cleanup() so that a failed step does not abort subsequent ones
# (connector_curl calls die() -> exit 1, which would terminate the shell even
# from within a trap handler, making || echo "WARNING" ineffective).
connector_curl_soft() {
    local method="$1" path="$2" body="${3:-}"
    local tmp http_code response
    tmp=$(mktemp)
    if [[ -n "$body" ]]; then
        http_code=$(curl -s -o "$tmp" -w "%{http_code}" \
            -X "$method" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            -d "$body" \
            "${BASE_URL}${path}") || true
    else
        http_code=$(curl -s -o "$tmp" -w "%{http_code}" \
            -X "$method" \
            -H 'Content-Type: application/json' -H 'Accept: application/json' \
            "${BASE_URL}${path}") || true
    fi
    response=$(<"$tmp"); rm -f "$tmp"
    if [[ "$http_code" -lt 200 || "$http_code" -ge 300 ]]; then
        echo "  WARNING: HTTP ${http_code} on ${method} ${path}: ${response}" >&2
        return 1
    fi
    echo "$response"
}

cleanup() {
    echo ""
    echo "=== Cleanup ==="
    if [[ -n "$PRIVATE_KEY_UUID" ]]; then
        echo "  Deleting private key $PRIVATE_KEY_UUID ..."
        if connector_curl_soft DELETE \
                "/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/${PRIVATE_KEY_UUID}"; then
            echo "    Private key deleted."
        else
            echo "    WARNING: failed to delete private key."
        fi
    fi
    if [[ -n "$PUBLIC_KEY_UUID" ]]; then
        echo "  Deleting public key $PUBLIC_KEY_UUID ..."
        if connector_curl_soft DELETE \
                "/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/${PUBLIC_KEY_UUID}"; then
            echo "    Public key deleted."
        else
            echo "    WARNING: failed to delete public key."
        fi
    fi
    if [[ -n "$TOKEN_UUID" ]]; then
        echo "  Deleting token $TOKEN_UUID ..."
        if connector_curl_soft DELETE \
                "/v1/cryptographyProvider/tokens/${TOKEN_UUID}"; then
            echo "    Token deleted."
        else
            echo "    WARNING: failed to delete token."
        fi
    fi
}

trap cleanup EXIT

# ─── Step 1: Discover token creation attributes ────────────────────────────────
#
# GET /v1/cryptographyProvider/SOFT/attributes returns different attribute sets
# depending on whether tokens already exist:
#   - No existing tokens → attributes for new-token creation are returned directly.
#   - Existing tokens    → a data_options selector + a group_loadToken group (with
#                          a callback) are returned; a separate callback call
#                          resolves the new-token sub-attributes.

echo "=== Step 1: Discover token creation attributes ==="
TOKEN_TOP_ATTRS=$(connector_curl GET "/v1/cryptographyProvider/SOFT/attributes")

OPTIONS_UUID=''
if echo "$TOKEN_TOP_ATTRS" | jq -e '[.[].name] | any(. == "data_options")' > /dev/null 2>&1; then
    echo "  Existing tokens found — fetching 'Create new Token' sub-attributes via callback."
    OPTIONS_UUID=$(attr_uuid "$TOKEN_TOP_ATTRS" "data_options" "string")
    TOKEN_NEW_ATTRS=$(connector_curl GET "/v1/cryptographyProvider/callbacks/token/new/attributes")
else
    echo "  No existing tokens — new-token attributes returned directly."
    TOKEN_NEW_ATTRS="$TOKEN_TOP_ATTRS"
fi

ACTION_UUID=$(attr_uuid "$TOKEN_NEW_ATTRS" "data_createTokenAction" "string")
NAME_UUID=$(attr_uuid   "$TOKEN_NEW_ATTRS" "data_newTokenName"      "string")
CODE_UUID=$(attr_uuid   "$TOKEN_NEW_ATTRS" "data_tokenCode"         "secret")
echo "  data_createTokenAction uuid : $ACTION_UUID"
echo "  data_newTokenName      uuid : $NAME_UUID"
echo "  data_tokenCode         uuid : $CODE_UUID"
[[ -n "$OPTIONS_UUID" ]] && echo "  data_options           uuid : $OPTIONS_UUID"

# ─── Step 2: Create token or reuse existing ───────────────────────────────────

echo ""
echo "=== Step 2: Create token '$TOKEN_NAME' ==="

# Check whether a token with this name already exists; reuse it if so.
EXISTING_TOKENS=$(connector_curl_soft GET "/v1/cryptographyProvider/tokens") || true
TOKEN_UUID=$(echo "$EXISTING_TOKENS" | jq -r \
    --arg name "$TOKEN_NAME" \
    'if type == "array" then (first(.[] | select(.name == $name) | .uuid) // empty) else empty end' \
    2>/dev/null || true)

if [[ -n "$TOKEN_UUID" ]]; then
    TOKEN_PREEXISTED=true
    echo "  Token already exists — reusing UUID: $TOKEN_UUID"
else
    # Build the options attribute entry conditionally (only present when the server
    # returned data_options, i.e. when tokens already exist).
    OPTIONS_ATTR_JSON='[]'
    if [[ -n "$OPTIONS_UUID" ]]; then
        OPTIONS_ATTR_JSON=$(jq -n \
            --arg uuid "$OPTIONS_UUID" \
            '[{uuid: $uuid, name: "data_options", contentType: "string", version: "v2",
               content: [{reference: "new", data: "Create new Token"}]}]')
    fi

    CREATE_TOKEN_BODY=$(jq -n \
        --arg  name       "$TOKEN_NAME" \
        --arg  actionUuid "$ACTION_UUID" \
        --arg  nameUuid   "$NAME_UUID" \
        --arg  codeUuid   "$CODE_UUID" \
        --arg  tokenPass  "$TOKEN_PASS" \
        --argjson optAttrs "$OPTIONS_ATTR_JSON" \
        '$optAttrs + [
            {uuid: $actionUuid, name: "data_createTokenAction", contentType: "string",
             version: "v2", content: [{reference: "new", data: "new"}]},
            {uuid: $nameUuid, name: "data_newTokenName", contentType: "string",
             version: "v2", content: [{data: $name}]},
            {uuid: $codeUuid, name: "data_tokenCode", contentType: "secret",
             version: "v2", content: [{reference: $name, data: {secret: $tokenPass}}]}
        ] | {name: $name, kind: "SOFT", attributes: .}')

    CREATE_TOKEN_RESP=$(connector_curl POST "/v1/cryptographyProvider/tokens" "$CREATE_TOKEN_BODY") \
        || die "Token creation failed."

    TOKEN_UUID=$(echo "$CREATE_TOKEN_RESP" | jq -r '.uuid // empty')
    [[ -n "$TOKEN_UUID" ]] \
        || die "Token UUID missing from response: $CREATE_TOKEN_RESP"
    echo "  Token UUID: $TOKEN_UUID"
fi

# ─── Step 3: Discover key-pair creation attributes ────────────────────────────
#
# GET /v1/cryptographyProvider/tokens/{tokenUuid}/keys/pair/attributes returns:
#   data_keyAlias (string), data_keyAlgorithm (string), group_keySpec (group).
# The group_keySpec carries a callback to resolve algorithm-specific attributes.
# For RSA: GET /v1/cryptographyProvider/callbacks/keyspec/RSA/attributes
#   returns data_rsaKeySize (integer).

echo ""
echo "=== Step 3: Discover key-pair creation attributes ==="
KEYPAIR_ATTR_DEFS=$(connector_curl GET \
    "/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/pair/attributes")

ALIAS_UUID=$(attr_uuid   "$KEYPAIR_ATTR_DEFS" "data_keyAlias"     "string")
ALG_UUID=$(attr_uuid     "$KEYPAIR_ATTR_DEFS" "data_keyAlgorithm" "string")
echo "  data_keyAlias     uuid : $ALIAS_UUID"
echo "  data_keyAlgorithm uuid : $ALG_UUID"

RSA_SPEC_ATTRS=$(connector_curl GET \
    "/v1/cryptographyProvider/callbacks/keyspec/RSA/attributes")
RSA_SIZE_UUID=$(attr_uuid "$RSA_SPEC_ATTRS" "data_rsaKeySize" "integer")
echo "  data_rsaKeySize   uuid : $RSA_SIZE_UUID"

# ─── Step 4: Create RSA key pair ──────────────────────────────────────────────

echo ""
echo "=== Step 4: Create RSA-${KEY_SIZE} key pair (alias: ${KEY_ALIAS}) ==="

CREATE_KEY_BODY=$(jq -n \
    --arg  aliasUuid   "$ALIAS_UUID" \
    --arg  algUuid     "$ALG_UUID" \
    --arg  sizeUuid    "$RSA_SIZE_UUID" \
    --arg  keyAlias    "$KEY_ALIAS" \
    --argjson keySize  "$KEY_SIZE" \
    '{
        tokenProfileAttributes: [],
        createKeyAttributes: [
            {uuid: $aliasUuid, name: "data_keyAlias",     contentType: "string",
             version: "v2", content: [{data: $keyAlias}]},
            {uuid: $algUuid,   name: "data_keyAlgorithm", contentType: "string",
             version: "v2", content: [{reference: "RSA", data: "RSA"}]},
            {uuid: $sizeUuid,  name: "data_rsaKeySize",   contentType: "integer",
             version: "v2", content: [{reference: ("RSA_" + ($keySize|tostring)), data: $keySize}]}
        ]
    }')

CREATE_KEY_RESP=$(connector_curl POST \
    "/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/pair" "$CREATE_KEY_BODY") \
    || die "Key pair creation failed."

PRIVATE_KEY_UUID=$(echo "$CREATE_KEY_RESP" | jq -r '.privateKeyData.uuid // empty')
PUBLIC_KEY_UUID=$(echo  "$CREATE_KEY_RESP" | jq -r '.publicKeyData.uuid  // empty')
[[ -n "$PRIVATE_KEY_UUID" ]] || die "Private key UUID missing. Response: $CREATE_KEY_RESP"
[[ -n "$PUBLIC_KEY_UUID"  ]] || die "Public key UUID missing.  Response: $CREATE_KEY_RESP"
echo "  Private key UUID : $PRIVATE_KEY_UUID"
echo "  Public  key UUID : $PUBLIC_KEY_UUID"

# ─── Step 5: Sign ─────────────────────────────────────────────────────────────
#
# The connector's CryptographicOperationsController has no attribute-definition
# endpoint for sign/cipher operations — per the interface source comment:
# "Attributes for Cipher and Signature is controlled by core."
# The connector matches signatureAttributes by name (not UUID), so no UUID
# discovery is needed here.

echo ""
echo "=== Step 5: Sign (scheme: ${SIG_SCHEME}, digest: ${DIGEST}) ==="

SIGN_BODY=$(jq -n \
    --arg scheme "$SIG_SCHEME" \
    --arg digest "$DIGEST" \
    --arg data   "$DATA_B64" \
    '{
        signatureAttributes: [
            {name: "data_rsaSigScheme", contentType: "string", version: "v2",
             content: [{data: $scheme}]},
            {name: "data_sigDigest",    contentType: "string", version: "v2",
             content: [{data: $digest}]}
        ],
        data: [{data: $data}]
    }')

SIGN_RESP=$(connector_curl POST \
    "/v1/cryptographyProvider/tokens/${TOKEN_UUID}/keys/${PRIVATE_KEY_UUID}/sign" \
    "$SIGN_BODY") || die "Sign request failed."

SIGNATURE=$(echo "$SIGN_RESP" | jq -r '.signatures[0].data // empty')
[[ -n "$SIGNATURE" ]] || die "Signature missing from response: $SIGN_RESP"
echo "  Signature (base64): ${SIGNATURE}"

echo ""
echo "=== Sign operation successful ==="
# Cleanup runs automatically via trap EXIT.
