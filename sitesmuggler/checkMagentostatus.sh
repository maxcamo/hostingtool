#!/usr/bin/env bash

set -u

VERSION="1.0.0"
DOMAIN="${1:-}"
TMPDIR=""
ORIGIN_PORT=""

cleanup() {
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

print_line() {
    printf '%-48s %s\n' "$1" "$2"
}

status_route() {
    local LABEL="$1"
    local CODE="$2"

    case "$CODE" in
        200|201|202|204|301|302|303|307|308|400)
            print_line "[ACTIVE] $LABEL" "HTTP $CODE"
            ;;
        401|403)
            print_line "[BLOCK]  $LABEL" "HTTP $CODE"
            ;;
        404)
            print_line "[OFF]    $LABEL" "HTTP 404"
            ;;
        405)
            print_line "[BLOCK]  $LABEL" "HTTP 405"
            ;;
        000)
            print_line "[WARN]   $LABEL" "HTTP 000"
            ;;
        *)
            print_line "[REACH]  $LABEL" "HTTP $CODE"
            ;;
    esac
}

normalize_domain() {
    DOMAIN="${DOMAIN#https://}"
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%%:*}"
    DOMAIN="${DOMAIN%.}"
    DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
}

request_origin_get() {
    local URI="$1"
    local OUT="$2"
    local CODE

    CODE="$(curl -sS --max-time 15 \
        -H "Host: $DOMAIN" \
        -o "$OUT" \
        -w '%{http_code}' \
        "http://127.0.0.1:${ORIGIN_PORT}${URI}" 2>/dev/null)" || CODE="000"

    [ -n "$CODE" ] || CODE="000"
    printf '%s' "$CODE"
}

request_origin_post_json() {
    local URI="$1"
    local JSON="$2"
    local OUT="$3"
    local EXTRA_HEADER="${4:-}"
    local CODE

    if [ -n "$EXTRA_HEADER" ]; then
        CODE="$(curl -sS --max-time 15 \
            -X POST \
            -H "Host: $DOMAIN" \
            -H 'Content-Type: application/json' \
            -H "$EXTRA_HEADER" \
            --data "$JSON" \
            -o "$OUT" \
            -w '%{http_code}' \
            "http://127.0.0.1:${ORIGIN_PORT}${URI}" 2>/dev/null)" || CODE="000"
    else
        CODE="$(curl -sS --max-time 15 \
            -X POST \
            -H "Host: $DOMAIN" \
            -H 'Content-Type: application/json' \
            --data "$JSON" \
            -o "$OUT" \
            -w '%{http_code}' \
            "http://127.0.0.1:${ORIGIN_PORT}${URI}" 2>/dev/null)" || CODE="000"
    fi

    [ -n "$CODE" ] || CODE="000"
    printf '%s' "$CODE"
}

request_origin_post_form() {
    local URI="$1"
    local OUT="$2"
    local CODE

    CODE="$(curl -sS --max-time 15 \
        -X POST \
        -H "Host: $DOMAIN" \
        -H 'Content-Type: application/x-www-form-urlencoded' \
        --data 'sitesmuggler_probe=1' \
        -o "$OUT" \
        -w '%{http_code}' \
        "http://127.0.0.1:${ORIGIN_PORT}${URI}" 2>/dev/null)" || CODE="000"

    [ -n "$CODE" ] || CODE="000"
    printf '%s' "$CODE"
}

request_public_get() {
    local URI="$1"
    local OUT="$2"
    local CODE

    CODE="$(curl -ksS --max-time 20 \
        -o "$OUT" \
        -w '%{http_code}' \
        "https://${DOMAIN}${URI}" 2>/dev/null)" || CODE="000"

    [ -n "$CODE" ] || CODE="000"
    printf '%s' "$CODE"
}

request_public_post_json() {
    local URI="$1"
    local JSON="$2"
    local OUT="$3"
    local CODE

    CODE="$(curl -ksS --max-time 20 \
        -X POST \
        -H 'Content-Type: application/json' \
        --data "$JSON" \
        -o "$OUT" \
        -w '%{http_code}' \
        "https://${DOMAIN}${URI}" 2>/dev/null)" || CODE="000"

    [ -n "$CODE" ] || CODE="000"
    printf '%s' "$CODE"
}

find_origin_port() {
    local PORT CODE OUT
    local CANDIDATES="80 8080 8081 8000 8888"

    for PORT in $CANDIDATES; do
        if command -v ss >/dev/null 2>&1; then
            ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$PORT$" || continue
        fi

        OUT="$TMPDIR/origin-$PORT"
        CODE="$(curl -sS --max-time 5 \
            -H "Host: $DOMAIN" \
            -o "$OUT" \
            -w '%{http_code}' \
            "http://127.0.0.1:${PORT}/" 2>/dev/null)" || CODE="000"

        case "$CODE" in
            000) ;;
            *)
                ORIGIN_PORT="$PORT"
                return 0
                ;;
        esac
    done

    return 1
}

if [ -z "$DOMAIN" ]; then
    clear
    echo "============================================================"
    echo " CHECK MAGENTO STATUS"
    echo " Magento / StyleSmuggler surface checker"
    echo " Version $VERSION"
    echo "============================================================"
    echo
    read -r -p "Dominio Magento: " DOMAIN
fi

normalize_domain

if [ -z "$DOMAIN" ] || [[ "$DOMAIN" != *.* ]]; then
    echo "[ERROR] Dominio non valido: $DOMAIN"
    exit 1
fi

TMPDIR="$(mktemp -d /tmp/checkMagentoStatus.XXXXXX)"

echo "============================================================"
echo " CHECK MAGENTO STATUS"
echo "============================================================"
echo
printf 'Version : %s\n' "$VERSION"
printf 'Domain  : %s\n' "$DOMAIN"
printf 'Date    : %s\n' "$(date)"
echo

echo "============================================================"
echo " 1. ORIGIN DISCOVERY"
echo "============================================================"

if find_origin_port; then
    print_line "[PASS] Origin HTTP locale" "127.0.0.1:$ORIGIN_PORT"
else
    print_line "[WARN] Origin HTTP locale" "non rilevato"
fi

echo

echo "============================================================"
echo " 2. PUBLIC STATUS"
echo "============================================================"

BODY="$TMPDIR/public-home"
CODE="$(request_public_get '/' "$BODY")"
status_route "PUBLIC /" "$CODE"

BODY="$TMPDIR/public-graphql"
CODE="$(request_public_post_json '/graphql' '{"query":"{__typename}"}' "$BODY")"
status_route "PUBLIC POST /graphql {__typename}" "$CODE"

BODY="$TMPDIR/public-styles"
CODE="$(request_public_post_json '/graphql?styles%5Bsitesmuggler_probe%5D=1' '{"query":"{__typename}"}' "$BODY")"
status_route "PUBLIC /graphql?styles[...]" "$CODE"

if [ -z "$ORIGIN_PORT" ]; then
    echo
    echo "[WARN] Origin locale non rilevato: salto i test diretti all'applicazione."
    exit 0
fi

echo

echo "============================================================"
echo " 3. ORIGIN MAGENTO STATUS"
echo "============================================================"

BODY="$TMPDIR/origin-home"
CODE="$(request_origin_get '/' "$BODY")"
status_route "ORIGIN /" "$CODE"

BODY="$TMPDIR/origin-customer"
CODE="$(request_origin_get '/customer/account/' "$BODY")"
status_route "ORIGIN /customer/account/" "$CODE"

BODY="$TMPDIR/origin-rest"
CODE="$(request_origin_get '/rest/V1/store/storeConfigs' "$BODY")"
status_route "ORIGIN Magento REST" "$CODE"

echo

echo "============================================================"
echo " 4. GRAPHQL / STYLESMUGGLER SURFACE"
echo "============================================================"
echo "Probe innocui: nessun payload PHP/RCE viene inviato."
echo

BODY="$TMPDIR/graphql-typename"
CODE="$(request_origin_post_json '/graphql' '{"query":"{__typename}"}' "$BODY")"
status_route "POST /graphql {__typename}" "$CODE"

BODY="$TMPDIR/graphql-storeconfig"
CODE="$(request_origin_post_json '/graphql' '{"query":"{storeConfig{store_code}}"}' "$BODY")"
status_route "POST /graphql storeConfig" "$CODE"

STORE_CODE=""
if [ "$CODE" = "200" ]; then
    STORE_CODE="$(python3 - "$BODY" 2>/dev/null <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
    print(data.get('data', {}).get('storeConfig', {}).get('store_code', '') or '')
except Exception:
    pass
PY
)"
fi

if [ -n "$STORE_CODE" ]; then
    BODY="$TMPDIR/graphql-store-header"
    CODE="$(request_origin_post_json '/graphql' '{"query":"{__typename}"}' "$BODY" "Store: $STORE_CODE")"
    status_route "GraphQL + Store: $STORE_CODE" "$CODE"
else
    print_line "[INFO] GraphQL Store header" "store_code non rilevato"
fi

BODY="$TMPDIR/graphql-styles"
CODE="$(request_origin_post_json '/graphql?styles%5Bsitesmuggler_probe%5D=1' '{"query":"{__typename}"}' "$BODY")"
status_route "POST /graphql?styles[...]" "$CODE"

BODY="$TMPDIR/customer-section"
CODE="$(request_origin_get '/customer/section/load/?sections=customer&force_new_section_timestamp=true' "$BODY")"
status_route "GET /customer/section/load/" "$CODE"

BODY="$TMPDIR/paypal-transparent"
CODE="$(request_origin_post_form '/paypal/transparent/response/?sitesmuggler_probe=1' "$BODY")"
status_route "POST /paypal/transparent/response/" "$CODE"

echo

echo "============================================================"
echo " 5. SUMMARY"
echo "============================================================"
echo

echo "ACTIVE/REACH = route raggiungibile; NON significa vulnerabile."
echo "BLOCK/OFF    = route bloccata o non disponibile."
echo "La verifica della vulnerabilita' richiede comunque il controllo"
echo "della patch/hotfix Magento installata sulla specifica versione."
echo