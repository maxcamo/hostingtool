#!/usr/bin/env bash

set -u

VERSION="1.1.0"
TARGET="${1:-}"
TMPDIR=""
BASE_URL=""
DOMAIN=""
FINAL_URL=""
REMOTE_IP=""
WAF=""
WAF_MAIN=""
MAGENTO_DETECTED=0
MAGENTO_VERSION=""
MAGENTO_VERSION_SOURCE=""

cleanup() {
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

print_line() {
    printf '%-54s %s\n' "$1" "$2"
}

status_route() {
    local LABEL="$1" CODE="$2"
    case "$CODE" in
        200|201|202|204|301|302|303|307|308|400) print_line "[ACTIVE] $LABEL" "HTTP $CODE" ;;
        401|403) print_line "[BLOCK]  $LABEL" "HTTP $CODE" ;;
        404) print_line "[OFF]    $LABEL" "HTTP 404" ;;
        405) print_line "[BLOCK]  $LABEL" "HTTP 405" ;;
        000) print_line "[WARN]   $LABEL" "HTTP 000" ;;
        *) print_line "[REACH]  $LABEL" "HTTP $CODE" ;;
    esac
}

normalize_target() {
    TARGET="${TARGET%/}"
    if [[ "$TARGET" =~ ^https?:// ]]; then
        BASE_URL="$TARGET"
    else
        BASE_URL="https://$TARGET"
    fi
    DOMAIN="${BASE_URL#https://}"
    DOMAIN="${DOMAIN#http://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%%:*}"
    DOMAIN="${DOMAIN%.}"
    DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
}

public_get() {
    local URL="$1" BODY="$2" HEADERS="$3" META RC
    set +e
    META="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 25 \
        -A 'SiteSmuggler-MagentoStatus/1.1' \
        -D "$HEADERS" -o "$BODY" \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$URL" 2>/dev/null)"
    RC=$?
    set -e
    if [ "$RC" -ne 0 ]; then
        printf '000||'
    else
        printf '%s' "$META"
    fi
}

public_post_json() {
    local URL="$1" JSON="$2" BODY="$3" HEADERS="$4" META RC
    set +e
    META="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 25 \
        -A 'SiteSmuggler-MagentoStatus/1.1' \
        -X POST -H 'Content-Type: application/json' \
        --data "$JSON" \
        -D "$HEADERS" -o "$BODY" \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$URL" 2>/dev/null)"
    RC=$?
    set -e
    if [ "$RC" -ne 0 ]; then
        printf '000||'
    else
        printf '%s' "$META"
    fi
}

public_post_form() {
    local URL="$1" BODY="$2" HEADERS="$3" META RC
    set +e
    META="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 25 \
        -A 'SiteSmuggler-MagentoStatus/1.1' \
        -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
        --data 'sitesmuggler_probe=1' \
        -D "$HEADERS" -o "$BODY" \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$URL" 2>/dev/null)"
    RC=$?
    set -e
    if [ "$RC" -ne 0 ]; then
        printf '000||'
    else
        printf '%s' "$META"
    fi
}

meta_code() { printf '%s' "$1" | cut -d'|' -f1; }
meta_url()  { printf '%s' "$1" | cut -d'|' -f2; }
meta_ip()   { printf '%s' "$1" | cut -d'|' -f3; }

extract_any_version() {
    local FILE="$1"
    [ -s "$FILE" ] || return 1
    grep -Eio '2\.[0-9]+\.[0-9]+(-p[0-9]+)?' "$FILE" 2>/dev/null | head -1
}

extract_magento_version() {
    local FILE="$1"
    [ -s "$FILE" ] || return 1
    grep -Eio 'Magento[^[:cntrl:]]{0,120}2\.[0-9]+\.[0-9]+(-p[0-9]+)?|2\.[0-9]+\.[0-9]+(-p[0-9]+)?[^[:cntrl:]]{0,120}Magento' "$FILE" 2>/dev/null \
        | grep -Eo '2\.[0-9]+\.[0-9]+(-p[0-9]+)?' \
        | head -1
}

set_version_if_empty() {
    local VALUE="$1" SOURCE="$2"
    if [ -z "$MAGENTO_VERSION" ] && [ -n "$VALUE" ]; then
        MAGENTO_VERSION="$VALUE"
        MAGENTO_VERSION_SOURCE="$SOURCE"
    fi
}

detect_waf() {
    local H="$1" B="$2" TEXT
    TEXT="$(cat "$H" "$B" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    WAF=""

    if grep -Eq '(^|[[:space:]])cf-ray:|server:[[:space:]]*cloudflare|cf-mitigated:|__cf_bm|cf_clearance' <<< "$TEXT"; then
        WAF="Cloudflare"
    elif grep -Eq 'x-sucuri-id:|x-sucuri-cache:|server:[[:space:]]*sucuri|sucuri/cloudproxy' <<< "$TEXT"; then
        WAF="Sucuri"
    elif grep -Eq 'x-iinfo:|incap_ses_|visid_incap_|server:[[:space:]]*imperva|incapsula' <<< "$TEXT"; then
        WAF="Imperva/Incapsula"
    elif grep -Eq 'akamai|x-akamai-|akamai-grn|akamai-ghost' <<< "$TEXT"; then
        WAF="Akamai"
    elif grep -Eq 'x-cdn:[[:space:]]*stackpath|x-stackpath|stackpath' <<< "$TEXT"; then
        WAF="StackPath"
    elif grep -Eq 'server:[[:space:]]*fastly|x-served-by:.*cache-|fastly' <<< "$TEXT"; then
        WAF="Fastly/CDN"
    elif grep -Eq 'x-amz-cf-id:|x-amz-cf-pop:|server:[[:space:]]*cloudfront' <<< "$TEXT"; then
        WAF="AWS CloudFront/CDN"
    elif grep -Eq 'x-varnish:|via:.*varnish' <<< "$TEXT"; then
        WAF="Varnish/Reverse proxy"
    fi
}

detect_magento_markers() {
    local FILE="$1"
    [ -s "$FILE" ] || return 1
    if grep -Eqi 'Magento_[A-Za-z]+|/static/(version[^/]+/)?frontend/|mage/requirejs|requirejs/require\.js|x-magento-init|Magento_Ui' "$FILE"; then
        MAGENTO_DETECTED=1
        return 0
    fi
    return 1
}

scan_home_js_for_version() {
    local HOME="$1" HOME_URL="$2" OUT="$3" COUNT=0 SRC JSURL JSFILE VER
    : > "$OUT"
    [ -s "$HOME" ] || return 1

    while IFS= read -r SRC; do
        [ -n "$SRC" ] || continue
        case "$SRC" in
            //*) JSURL="https:$SRC" ;;
            http://*|https://*) JSURL="$SRC" ;;
            /*) JSURL="${HOME_URL%%://*}://$DOMAIN$SRC" ;;
            *) JSURL="${HOME_URL%/*}/$SRC" ;;
        esac

        case "$JSURL" in
            *"$DOMAIN"*) ;;
            *) continue ;;
        esac

        JSFILE="$TMPDIR/js-$COUNT"
        curl -ksSL --connect-timeout 5 --max-time 10 -A 'SiteSmuggler-MagentoStatus/1.1' \
            -o "$JSFILE" "$JSURL" 2>/dev/null || true

        if [ -s "$JSFILE" ]; then
            grep -Eio 'Magento[^[:cntrl:]]{0,100}2\.[0-9]+\.[0-9]+(-p[0-9]+)?|2\.[0-9]+\.[0-9]+(-p[0-9]+)?[^[:cntrl:]]{0,100}Magento' "$JSFILE" 2>/dev/null \
                | head -3 >> "$OUT" || true
        fi

        COUNT=$((COUNT + 1))
        [ "$COUNT" -ge 12 ] && break
    done < <(
        grep -Eio "<script[^>]+src=[\"'][^\"']+[\"']" "$HOME" 2>/dev/null \
            | sed -E "s/.*src=[\"']([^\"']+)[\"'].*/\1/" \
            | awk '!seen[$0]++'
    )

    VER="$(extract_magento_version "$OUT" || true)"
    [ -n "$VER" ] && printf '%s' "$VER"
}

if [ -z "$TARGET" ]; then
    clear
    echo "============================================================"
    echo " CHECK MAGENTO STATUS"
    echo " Remote Magento / StyleSmuggler surface checker"
    echo " Version $VERSION"
    echo "============================================================"
    echo
    read -r -p "URL o dominio Magento: " TARGET
fi

normalize_target

if [ -z "$DOMAIN" ] || [[ "$DOMAIN" != *.* ]]; then
    echo "[ERROR] Dominio non valido: $DOMAIN"
    exit 1
fi

TMPDIR="$(mktemp -d /tmp/checkMagentoStatus.XXXXXX)"

echo "============================================================"
echo " CHECK MAGENTO STATUS - REMOTE"
echo "============================================================"
echo
printf 'Version : %s\n' "$VERSION"
printf 'Target  : %s\n' "$BASE_URL"
printf 'Domain  : %s\n' "$DOMAIN"
printf 'Date    : %s\n' "$(date)"
echo

echo "============================================================"
echo " 1. PUBLIC STATUS / WAF"
echo "============================================================"

HOME_BODY="$TMPDIR/home.body"
HOME_HEADERS="$TMPDIR/home.headers"
META="$(public_get "$BASE_URL/" "$HOME_BODY" "$HOME_HEADERS")"
CODE="$(meta_code "$META")"
FINAL_URL="$(meta_url "$META")"
REMOTE_IP="$(meta_ip "$META")"
status_route "Homepage" "$CODE"
[ -n "$FINAL_URL" ] && print_line "[INFO] Final URL" "$FINAL_URL"
[ -n "$REMOTE_IP" ] && print_line "[INFO] Remote IP" "$REMOTE_IP"

detect_waf "$HOME_HEADERS" "$HOME_BODY"
WAF_MAIN="$WAF"
if [ -n "$WAF_MAIN" ]; then
    print_line "[WAF]  Protezione/CDN rilevata" "$WAF_MAIN"
else
    print_line "[INFO] WAF/CDN" "non identificato dagli header pubblici"
fi

if detect_magento_markers "$HOME_BODY"; then
    print_line "[PASS] Magento frontend fingerprint" "Magento 2 rilevato"
else
    print_line "[INFO] Magento frontend fingerprint" "non conclusivo"
fi

echo
echo "============================================================"
echo " 2. MAGENTO VERSION FINGERPRINT"
echo "============================================================"

MV_BODY="$TMPDIR/magento_version.body"
MV_HEADERS="$TMPDIR/magento_version.headers"
META="$(public_get "${BASE_URL}/magento_version" "$MV_BODY" "$MV_HEADERS")"
CODE="$(meta_code "$META")"
VER="$(extract_any_version "$MV_BODY" || true)"
if [ -n "$VER" ]; then
    print_line "[FOUND] /magento_version" "$VER (HTTP $CODE)"
    set_version_if_empty "$VER" "/magento_version"
else
    status_route "/magento_version" "$CODE"
fi

SETUP_BODY="$TMPDIR/setup.body"
SETUP_HEADERS="$TMPDIR/setup.headers"
META="$(public_get "${BASE_URL}/setup/" "$SETUP_BODY" "$SETUP_HEADERS")"
CODE="$(meta_code "$META")"
VER="$(extract_magento_version "$SETUP_BODY" || true)"
if [ -n "$VER" ]; then
    print_line "[LEAK]  /setup/ Magento version" "$VER (HTTP $CODE)"
    set_version_if_empty "$VER" "/setup/"
else
    status_route "/setup/" "$CODE"
fi

HTML_VER="$(extract_magento_version "$HOME_BODY" || true)"
if [ -n "$HTML_VER" ]; then
    print_line "[FOUND] Homepage version string" "$HTML_VER"
    set_version_if_empty "$HTML_VER" "homepage HTML"
else
    print_line "[INFO] Homepage version string" "non trovata"
fi

JS_SCAN="$TMPDIR/js-version.txt"
JS_VER="$(scan_home_js_for_version "$HOME_BODY" "${FINAL_URL:-$BASE_URL/}" "$JS_SCAN" || true)"
if [ -n "$JS_VER" ]; then
    print_line "[FOUND] JS Magento version string" "$JS_VER"
    set_version_if_empty "$JS_VER" "JavaScript pubblico"
else
    print_line "[INFO] JS exact-version fingerprint" "nessuna versione affidabile trovata"
fi

if grep -Eqi '/static/version[^/]+/' "$HOME_BODY" 2>/dev/null; then
    print_line "[INFO] Static content signing" "rilevato /static/version... (NON e' la release Magento)"
fi

if [ -n "$MAGENTO_VERSION" ]; then
    print_line "[RESULT] Magento version" "$MAGENTO_VERSION"
    print_line "[INFO] Version source" "$MAGENTO_VERSION_SOURCE"
else
    if [ "$MAGENTO_DETECTED" -eq 1 ]; then
        print_line "[RESULT] Magento version" "Magento 2.x; release 2.4.x non determinabile con affidabilita'"
    else
        print_line "[RESULT] Magento version" "non determinata"
    fi
fi

echo
echo "============================================================"
echo " 3. GRAPHQL / STYLESMUGGLER SURFACE"
echo "============================================================"
echo "Probe innocui: nessun payload PHP/RCE viene inviato."
echo

BODY="$TMPDIR/graphql-typename.body"; HEAD="$TMPDIR/graphql-typename.headers"
META="$(public_post_json "${BASE_URL}/graphql" '{"query":"{__typename}"}' "$BODY" "$HEAD")"
CODE="$(meta_code "$META")"
status_route "POST /graphql {__typename}" "$CODE"

BODY="$TMPDIR/graphql-store.body"; HEAD="$TMPDIR/graphql-store.headers"
META="$(public_post_json "${BASE_URL}/graphql" '{"query":"{storeConfig{store_code}}"}' "$BODY" "$HEAD")"
CODE="$(meta_code "$META")"
status_route "POST /graphql storeConfig" "$CODE"
if [ "$CODE" = "200" ] && grep -q 'store_code' "$BODY" 2>/dev/null; then
    STORE_CODE="$(sed -n 's/.*"store_code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$BODY" | head -1)"
    [ -n "$STORE_CODE" ] && print_line "[INFO] GraphQL store_code" "$STORE_CODE"
fi

BODY="$TMPDIR/graphql-styles.body"; HEAD="$TMPDIR/graphql-styles.headers"
META="$(public_post_json "${BASE_URL}/graphql?styles%5Bsitesmuggler_probe%5D=1" '{"query":"{__typename}"}' "$BODY" "$HEAD")"
CODE="$(meta_code "$META")"
status_route "POST /graphql?styles[...]" "$CODE"

detect_waf "$HEAD" "$BODY"
PROBE_WAF="$WAF"
if [ -n "$PROBE_WAF" ] && [ "$CODE" = "403" ]; then
    print_line "[INFO] styles probe protection" "$PROBE_WAF ha intercettato la richiesta"
fi

BODY="$TMPDIR/customer-section.body"; HEAD="$TMPDIR/customer-section.headers"
META="$(public_get "${BASE_URL}/customer/section/load/?sections=customer&force_new_section_timestamp=true" "$BODY" "$HEAD")"
CODE="$(meta_code "$META")"
status_route "GET /customer/section/load/" "$CODE"

BODY="$TMPDIR/paypal.body"; HEAD="$TMPDIR/paypal.headers"
META="$(public_post_form "${BASE_URL}/paypal/transparent/response/?sitesmuggler_probe=1" "$BODY" "$HEAD")"
CODE="$(meta_code "$META")"
status_route "POST /paypal/transparent/response/" "$CODE"

echo
echo "============================================================"
echo " 4. SUMMARY"
echo "============================================================"
echo
[ -n "$WAF_MAIN" ] && echo "WAF/CDN          : $WAF_MAIN" || echo "WAF/CDN          : non identificato"
[ -n "$MAGENTO_VERSION" ] && echo "Magento version  : $MAGENTO_VERSION ($MAGENTO_VERSION_SOURCE)" || echo "Magento version  : non determinata con affidabilita'"
echo "Remote IP        : ${REMOTE_IP:-n/d}"
echo
echo "ACTIVE/REACH = route pubblicamente raggiungibile; NON significa vulnerabile."
echo "BLOCK/OFF    = route bloccata o non disponibile."
echo "La stringa /static/versionXXXX e' una firma di deployment/cache, non la versione Magento."
echo "Il checker e' completamente remoto e non richiede SSH sul server target."
echo