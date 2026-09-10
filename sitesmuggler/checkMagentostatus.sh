#!/usr/bin/env bash

set -u

VERSION="1.3.0"
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
TTFB_MEDIAN=""
TTFB_AVERAGE=""
TTFB_MIN=""
TTFB_MAX=""
TTFB_VALID=0
TTFB_RUNS=10
JS_CDN_RESULT="non determinata"
IMG_CDN_RESULT="non determinata"
JS_ASSET_HOSTS=""
IMG_ASSET_HOSTS=""

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
        -A 'SiteSmuggler-MagentoStatus/1.3' \
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
        -A 'SiteSmuggler-MagentoStatus/1.3' \
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
        -A 'SiteSmuggler-MagentoStatus/1.3' \
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
    local HOME="$1" HOME_URL="$2" OUT="$3"
    local COUNT=0 SRC JSURL JSFILE VER SCHEME

    : > "$OUT"
    [ -s "$HOME" ] || return 1

    SCHEME="${HOME_URL%%:*}"
    case "$SCHEME" in
        http|https) ;;
        *) SCHEME="https" ;;
    esac

    while IFS= read -r SRC; do
        [ -n "$SRC" ] || continue

        case "$SRC" in
            //*) JSURL="${SCHEME}:$SRC" ;;
            http://*|https://*) JSURL="$SRC" ;;
            /*) JSURL="${SCHEME}://${DOMAIN}${SRC}" ;;
            *) JSURL="${HOME_URL%/*}/$SRC" ;;
        esac

        case "$JSURL" in
            *"$DOMAIN"*) ;;
            *) continue ;;
        esac

        JSFILE="$TMPDIR/js-$COUNT"
        curl -ksSL --connect-timeout 5 --max-time 10 \
            -A 'SiteSmuggler-MagentoStatus/1.3' \
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

ms_from_seconds() {
    awk -v s="$1" 'BEGIN { printf "%.0f", s * 1000 }'
}

run_ttfb_benchmark() {
    local URL="$1" RUNS="${2:-10}"
    local DATA="$TMPDIR/ttfb.tsv"
    local VALUES="$TMPDIR/ttfb-values.txt"
    local I SEP TEST_URL RESULT RC CODE DNS CONNECT TLS TTFB TOTAL
    local TTFB_MS TOTAL_MS DNS_MS CONNECT_MS TLS_MS
    local AVG_DNS AVG_CONNECT AVG_TLS AVG_TOTAL

    : > "$DATA"
    : > "$VALUES"

    echo "Target benchmark: $URL"
    echo "Metodo          : $RUNS richieste HTTPS, redirect seguiti, cache-buster + no-cache"
    echo

    for ((I=1; I<=RUNS; I++)); do
        SEP='?'
        [[ "$URL" == *\?* ]] && SEP='&'
        TEST_URL="${URL}${SEP}sitesmuggler_ttfb=$(date +%s%N)-${I}"

        set +e
        RESULT="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 30 \
            -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36' \
            -H 'Cache-Control: no-cache' \
            -H 'Pragma: no-cache' \
            -o /dev/null \
            -w '%{http_code}|%{time_namelookup}|%{time_connect}|%{time_appconnect}|%{time_starttransfer}|%{time_total}' \
            "$TEST_URL" 2>/dev/null)"
        RC=$?
        set -e

        if [ "$RC" -ne 0 ] || [ -z "$RESULT" ]; then
            printf 'TEST %02d | HTTP=000 | errore connessione\n' "$I"
            continue
        fi

        IFS='|' read -r CODE DNS CONNECT TLS TTFB TOTAL <<< "$RESULT"
        TTFB_MS="$(ms_from_seconds "${TTFB:-0}")"
        TOTAL_MS="$(ms_from_seconds "${TOTAL:-0}")"
        DNS_MS="$(ms_from_seconds "${DNS:-0}")"
        CONNECT_MS="$(ms_from_seconds "${CONNECT:-0}")"
        TLS_MS="$(ms_from_seconds "${TLS:-0}")"

        printf 'TEST %02d | HTTP=%s | TTFB=%4s ms | TOTAL=%4s ms\n' "$I" "$CODE" "$TTFB_MS" "$TOTAL_MS"
        printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$CODE" "$DNS_MS" "$CONNECT_MS" "$TLS_MS" "$TTFB_MS" "$TOTAL_MS" >> "$DATA"

        case "$CODE" in
            2??|3??)
                [ "$TTFB_MS" -gt 0 ] 2>/dev/null && printf '%s\n' "$TTFB_MS" >> "$VALUES"
                ;;
        esac
    done

    TTFB_VALID="$(wc -l < "$VALUES" | tr -d ' ')"

    echo
    if [ "$TTFB_VALID" -eq 0 ]; then
        print_line "[WARN] TTFB benchmark" "nessuna richiesta HTTP 2xx/3xx valida"
        return 0
    fi

    TTFB_AVERAGE="$(awk '{s+=$1} END {if (NR) printf "%.0f", s/NR}' "$VALUES")"
    TTFB_MIN="$(sort -n "$VALUES" | head -1)"
    TTFB_MAX="$(sort -n "$VALUES" | tail -1)"
    TTFB_MEDIAN="$(sort -n "$VALUES" | awk '{a[NR]=$1} END {if (NR%2) printf "%.0f", a[(NR+1)/2]; else printf "%.0f", (a[NR/2]+a[NR/2+1])/2}')"

    AVG_DNS="$(awk -F '\t' '$1 ~ /^[23][0-9][0-9]$/ {s+=$2;n++} END {if(n) printf "%.0f", s/n}' "$DATA")"
    AVG_CONNECT="$(awk -F '\t' '$1 ~ /^[23][0-9][0-9]$/ {s+=$3;n++} END {if(n) printf "%.0f", s/n}' "$DATA")"
    AVG_TLS="$(awk -F '\t' '$1 ~ /^[23][0-9][0-9]$/ {s+=$4;n++} END {if(n) printf "%.0f", s/n}' "$DATA")"
    AVG_TOTAL="$(awk -F '\t' '$1 ~ /^[23][0-9][0-9]$/ {s+=$6;n++} END {if(n) printf "%.0f", s/n}' "$DATA")"

    print_line "[RESULT] TTFB median" "${TTFB_MEDIAN} ms"
    print_line "[RESULT] TTFB average" "${TTFB_AVERAGE} ms"
    print_line "[INFO] TTFB min / max" "${TTFB_MIN} ms / ${TTFB_MAX} ms"
    print_line "[INFO] Valid runs" "${TTFB_VALID}/${RUNS}"
    print_line "[INFO] Avg DNS / CONNECT / TLS" "${AVG_DNS:-n/d} / ${AVG_CONNECT:-n/d} / ${AVG_TLS:-n/d} ms"
    print_line "[INFO] Avg total response" "${AVG_TOTAL:-n/d} ms"
}

asset_host() {
    local URL="$1" H
    H="${URL#*://}"
    H="${H%%/*}"
    H="${H%%:*}"
    printf '%s' "$H" | tr '[:upper:]' '[:lower:]'
}

resolve_asset_url() {
    local SRC="$1" PAGE_URL="$2" SCHEME BASE
    SCHEME="${PAGE_URL%%:*}"
    case "$SCHEME" in http|https) ;; *) SCHEME="https" ;; esac

    case "$SRC" in
        data:*|blob:*|javascript:*|'') return 1 ;;
        //*) printf '%s:%s' "$SCHEME" "$SRC" ;;
        http://*|https://*) printf '%s' "$SRC" ;;
        /*) printf '%s://%s%s' "$SCHEME" "$DOMAIN" "$SRC" ;;
        *)
            BASE="${PAGE_URL%%\?*}"
            BASE="${BASE%/*}"
            printf '%s/%s' "$BASE" "$SRC"
            ;;
    esac
}

cdn_provider_from_host_headers() {
    local HOST="$1" HEADERS="$2" TEXT
    TEXT="$(cat "$HEADERS" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    HOST="$(printf '%s' "$HOST" | tr '[:upper:]' '[:lower:]')"

    if [[ "$HOST" == *cloudfront.net ]] || grep -Eq 'x-amz-cf-id:|x-amz-cf-pop:|server:[[:space:]]*cloudfront' <<< "$TEXT"; then
        printf 'AWS CloudFront'
    elif [[ "$HOST" == *cloudflare.net ]] || grep -Eq 'cf-ray:|server:[[:space:]]*cloudflare|cf-cache-status:' <<< "$TEXT"; then
        printf 'Cloudflare'
    elif grep -Eq 'x-sucuri-id:|x-sucuri-cache:|server:[[:space:]]*sucuri' <<< "$TEXT"; then
        printf 'Sucuri'
    elif [[ "$HOST" == *fastly.net ]] || grep -Eq 'server:[[:space:]]*fastly|x-served-by:.*cache-|x-cache-hits:|fastly' <<< "$TEXT"; then
        printf 'Fastly'
    elif [[ "$HOST" == *akamaized.net || "$HOST" == *akamai.net || "$HOST" == *edgekey.net || "$HOST" == *edgesuite.net ]] || grep -Eq 'x-akamai-|akamai-grn|akamai-ghost' <<< "$TEXT"; then
        printf 'Akamai'
    elif [[ "$HOST" == *b-cdn.net || "$HOST" == *bunnycdn.com ]] || grep -Eq 'server:[[:space:]]*bunnycdn|cdn-pullzone|bunnycdn' <<< "$TEXT"; then
        printf 'Bunny CDN'
    elif [[ "$HOST" == *cloudinary.com ]] || grep -Eq 'x-cld-|server:[[:space:]]*cloudinary' <<< "$TEXT"; then
        printf 'Cloudinary'
    elif [[ "$HOST" == *imgix.net ]] || grep -Eq 'x-imgix-id:|server:[[:space:]]*imgix' <<< "$TEXT"; then
        printf 'Imgix'
    elif [[ "$HOST" == *keycdn.com || "$HOST" == *kxcdn.com ]] || grep -Eq 'server:[[:space:]]*keycdn|x-edge-location:' <<< "$TEXT"; then
        printf 'KeyCDN'
    elif [[ "$HOST" == *cdn77.org || "$HOST" == *cdn77.com ]] || grep -Eq 'server:[[:space:]]*cdn77|x-77-' <<< "$TEXT"; then
        printf 'CDN77'
    elif [[ "$HOST" == *jsdelivr.net ]]; then
        printf 'jsDelivr'
    elif [[ "$HOST" == unpkg.com ]]; then
        printf 'UNPKG'
    elif grep -Eq '^x-cache:|^age:|^via:.*varnish|^x-varnish:' <<< "$TEXT"; then
        printf 'CDN/cache proxy (provider non identificato)'
    fi
}

asset_cache_status() {
    local HEADERS="$1" VALUE
    VALUE="$(grep -Ei '^(cf-cache-status|x-cache|x-sucuri-cache|x-cache-hits|age):' "$HEADERS" 2>/dev/null | tail -3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
    [ -n "$VALUE" ] && printf '%s' "$VALUE"
}

extract_asset_urls() {
    local TYPE="$1" HTML="$2" PAGE_URL="$3" OUT="$4" RAW SRC URL
    : > "$OUT"

    if [ "$TYPE" = "js" ]; then
        while IFS= read -r RAW; do
            SRC="$(printf '%s' "$RAW" | sed -E "s/.*src=[\"']([^\"']+)[\"'].*/\1/")"
            URL="$(resolve_asset_url "$SRC" "$PAGE_URL" || true)"
            [ -n "$URL" ] && printf '%s\n' "$URL" >> "$OUT"
        done < <(grep -Eio "<script[^>]+src=[\"'][^\"']+[\"']" "$HTML" 2>/dev/null || true)
    else
        while IFS= read -r RAW; do
            SRC="$(printf '%s' "$RAW" | sed -E "s/.*(src|data-src)=[\"']([^\"']+)[\"'].*/\2/")"
            URL="$(resolve_asset_url "$SRC" "$PAGE_URL" || true)"
            [ -n "$URL" ] && printf '%s\n' "$URL" >> "$OUT"
        done < <(grep -Eio "<img[^>]+(src|data-src)=[\"'][^\"']+[\"']" "$HTML" 2>/dev/null || true)
    fi

    sort -u "$OUT" -o "$OUT"
}

probe_asset_cdn_type() {
    local TYPE="$1" LIST="$2" MAX="${3:-6}"
    local URL HOST HEADERS PROVIDER CACHE COUNT=0 TOTAL=0 FOUND=0 RC
    local PROVIDERS="$TMPDIR/${TYPE}-cdn-providers.txt"
    local HOSTS="$TMPDIR/${TYPE}-asset-hosts.txt"
    local HOST_LIST PROVIDER_LIST

    : > "$PROVIDERS"
    : > "$HOSTS"
    TOTAL="$(wc -l < "$LIST" | tr -d ' ')"

    if [ "$TOTAL" -eq 0 ]; then
        print_line "[INFO] ${TYPE^^} assets" "nessun asset rilevato nella homepage"
        [ "$TYPE" = "js" ] && JS_CDN_RESULT="nessun asset rilevato"
        [ "$TYPE" = "img" ] && IMG_CDN_RESULT="nessun asset rilevato"
        return 0
    fi

    while IFS= read -r URL; do
        [ -n "$URL" ] || continue
        HOST="$(asset_host "$URL")"
        [ -n "$HOST" ] || continue
        printf '%s\n' "$HOST" >> "$HOSTS"

        HEADERS="$TMPDIR/${TYPE}-asset-${COUNT}.headers"
        set +e
        curl -ksSIL --max-redirs 5 --connect-timeout 5 --max-time 12 \
            -A 'SiteSmuggler-MagentoStatus/1.3' \
            -D "$HEADERS" -o /dev/null "$URL" 2>/dev/null
        RC=$?
        set -e
        if [ "$RC" -ne 0 ] || [ ! -s "$HEADERS" ]; then
            : > "$HEADERS"
            curl -ksSL --range 0-0 --max-redirs 5 --connect-timeout 5 --max-time 12 \
                -A 'SiteSmuggler-MagentoStatus/1.3' \
                -D "$HEADERS" -o /dev/null "$URL" 2>/dev/null || true
        fi

        PROVIDER="$(cdn_provider_from_host_headers "$HOST" "$HEADERS" || true)"
        CACHE="$(asset_cache_status "$HEADERS" || true)"

        if [ -n "$PROVIDER" ]; then
            FOUND=$((FOUND + 1))
            printf '%s\n' "$PROVIDER" >> "$PROVIDERS"
            if [ -n "$CACHE" ]; then
                print_line "[CDN]  ${TYPE^^} asset" "$PROVIDER | $HOST | $CACHE"
            else
                print_line "[CDN]  ${TYPE^^} asset" "$PROVIDER | $HOST"
            fi
        else
            print_line "[INFO] ${TYPE^^} asset" "host=$HOST | CDN non identificata"
        fi

        COUNT=$((COUNT + 1))
        [ "$COUNT" -ge "$MAX" ] && break
    done < "$LIST"

    sort -u "$HOSTS" -o "$HOSTS"
    sort -u "$PROVIDERS" -o "$PROVIDERS"

    HOST_LIST="$(paste -sd ',' "$HOSTS" 2>/dev/null | sed 's/,/, /g')"
    PROVIDER_LIST="$(paste -sd ',' "$PROVIDERS" 2>/dev/null | sed 's/,/, /g')"

    print_line "[INFO] ${TYPE^^} asset URLs" "$TOTAL rilevati; $COUNT verificati"
    print_line "[INFO] ${TYPE^^} asset hosts" "${HOST_LIST:-n/d}"

    if [ "$FOUND" -gt 0 ]; then
        print_line "[RESULT] ${TYPE^^} CDN" "$PROVIDER_LIST"
        if [ "$TYPE" = "js" ]; then
            JS_CDN_RESULT="$PROVIDER_LIST"
            JS_ASSET_HOSTS="$HOST_LIST"
        else
            IMG_CDN_RESULT="$PROVIDER_LIST"
            IMG_ASSET_HOSTS="$HOST_LIST"
        fi
    else
        print_line "[RESULT] ${TYPE^^} CDN" "non rilevata nei campioni"
        if [ "$TYPE" = "js" ]; then
            JS_CDN_RESULT="non rilevata nei campioni"
            JS_ASSET_HOSTS="$HOST_LIST"
        else
            IMG_CDN_RESULT="non rilevata nei campioni"
            IMG_ASSET_HOSTS="$HOST_LIST"
        fi
    fi
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

command -v curl >/dev/null 2>&1 || {
    echo "[ERROR] curl non trovato"
    exit 1
}

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
echo " 3. ASSET CDN CHECK - JS / IMAGES"
echo "============================================================"

ASSET_PAGE_URL="${FINAL_URL:-$BASE_URL/}"
JS_ASSETS="$TMPDIR/assets-js.txt"
IMG_ASSETS="$TMPDIR/assets-img.txt"
extract_asset_urls "js" "$HOME_BODY" "$ASSET_PAGE_URL" "$JS_ASSETS"
extract_asset_urls "img" "$HOME_BODY" "$ASSET_PAGE_URL" "$IMG_ASSETS"

echo "-- JavaScript --"
probe_asset_cdn_type "js" "$JS_ASSETS" 6

echo
echo "-- Immagini --"
probe_asset_cdn_type "img" "$IMG_ASSETS" 6

echo
echo "============================================================"
echo " 4. TTFB BENCHMARK"
echo "============================================================"

TTFB_URL="${FINAL_URL:-$BASE_URL/}"
run_ttfb_benchmark "$TTFB_URL" "$TTFB_RUNS"

echo
echo "============================================================"
echo " 5. GRAPHQL / STYLESMUGGLER SURFACE"
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
echo " 6. SUMMARY"
echo "============================================================"
echo
[ -n "$WAF_MAIN" ] && echo "WAF/CDN          : $WAF_MAIN" || echo "WAF/CDN          : non identificato"
[ -n "$MAGENTO_VERSION" ] && echo "Magento version  : $MAGENTO_VERSION ($MAGENTO_VERSION_SOURCE)" || echo "Magento version  : non determinata con affidabilita'"
echo "Remote IP        : ${REMOTE_IP:-n/d}"
echo "JS CDN           : $JS_CDN_RESULT"
echo "Image CDN        : $IMG_CDN_RESULT"
[ -n "$JS_ASSET_HOSTS" ] && echo "JS hosts         : $JS_ASSET_HOSTS"
[ -n "$IMG_ASSET_HOSTS" ] && echo "Image hosts      : $IMG_ASSET_HOSTS"
if [ -n "$TTFB_MEDIAN" ]; then
    echo "TTFB median      : ${TTFB_MEDIAN} ms"
    echo "TTFB average     : ${TTFB_AVERAGE} ms"
    echo "TTFB min / max   : ${TTFB_MIN} / ${TTFB_MAX} ms"
    echo "TTFB valid runs  : ${TTFB_VALID}/${TTFB_RUNS}"
else
    echo "TTFB             : non determinato"
fi

echo
echo "ACTIVE/REACH = route pubblicamente raggiungibile; NON significa vulnerabile."
echo "BLOCK/OFF    = route bloccata o non disponibile."
echo "La stringa /static/versionXXXX e' una firma di deployment/cache, non la versione Magento."
echo "Asset CDN: il checker verifica host e header CDN/cache su campioni JS e immagini della homepage."
echo "Il TTFB e' misurato remotamente con cache-buster/no-cache; CDN/WAF e rete incidono sul risultato."
echo "Il checker e' completamente remoto e non richiede SSH sul server target."
echo