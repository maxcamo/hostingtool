#!/usr/bin/env bash

set -u

VERSION="1.0.0"
TARGET="${1:-}"
TMPDIR=""
BASE_URL=""
DOMAIN=""
FINAL_URL=""
REMOTE_IP=""
WAF=""
WORDPRESS_DETECTED=0
WORDPRESS_VERSION=""
WORDPRESS_VERSION_SOURCE=""
GENERATOR_EXPOSED=0
REST_API_STATUS=""
XMLRPC_STATUS=""
WP_CRON_STATUS=""
WP_LOGIN_STATUS=""
WP_INSTALL_STATUS=""
WP_SIGNUP_STATUS=""
USERS_ENDPOINT_STATUS=""
USERS_EXPOSED=0
TTFB_RUNS=10
TTFB_MEDIAN=""
TTFB_AVERAGE=""
TTFB_MIN=""
TTFB_MAX=""
TTFB_VALID=0
CACHE_HINT=""
CACHE_TECH=""
CACHE_CONTROL=""
SECURITY_HEADERS_SCORE=0
PLUGIN_COUNT=0
THEME_COUNT=0
PLUGIN_LIST=""
THEME_LIST=""
PHP_HINT=""
SERVER_HINT=""

UA_STATUS="SiteSmuggler-WordPressStatus/1.0"
UA_BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

cleanup() {
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

print_line() {
    printf '%-56s %s\n' "$1" "$2"
}

section() {
    printf '\n============================================================\n'
    printf ' %s\n' "$1"
    printf '============================================================\n'
}

status_route() {
    local LABEL="$1" CODE="$2"
    case "$CODE" in
        200|201|202|204|301|302|303|307|308|400) print_line "[ACTIVE] $LABEL" "HTTP $CODE" ;;
        401|403) print_line "[BLOCK]  $LABEL" "HTTP $CODE" ;;
        404|410) print_line "[OFF]    $LABEL" "HTTP $CODE" ;;
        405) print_line "[BLOCK]  $LABEL" "HTTP 405" ;;
        000|"") print_line "[WARN]   $LABEL" "HTTP 000" ;;
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
    META="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 25 \
        -A "$UA_STATUS" \
        -D "$HEADERS" -o "$BODY" \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$URL" 2>/dev/null)"
    RC=$?

    if [ "$RC" -ne 0 ]; then
        printf '000||'
    else
        printf '%s' "$META"
    fi
}

public_head() {
    local URL="$1" HEADERS="$2" META RC
    META="$(curl -ksSIL --max-redirs 8 --connect-timeout 8 --max-time 20 \
        -A "$UA_STATUS" \
        -D "$HEADERS" -o /dev/null \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$URL" 2>/dev/null)"
    RC=$?

    if [ "$RC" -ne 0 ]; then
        printf '000||'
    else
        printf '%s' "$META"
    fi
}

meta_code() { printf '%s' "$1" | cut -d'|' -f1; }
meta_url()  { printf '%s' "$1" | cut -d'|' -f2; }
meta_ip()   { printf '%s' "$1" | cut -d'|' -f3; }

header_value() {
    local NAME="$1" FILE="$2"
    awk -v name="$NAME" 'BEGIN{IGNORECASE=1} $0 ~ "^" name ":" {sub(/^[^:]+:[[:space:]]*/, ""); gsub(/\r/, ""); value=$0} END{print value}' "$FILE" 2>/dev/null
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

detect_wordpress() {
    local FILE="$1"
    [ -s "$FILE" ] || return 1

    if grep -Eqi '/wp-content/|/wp-includes/|wp-emoji-release|min\.js\?ver=|wordpress' "$FILE"; then
        WORDPRESS_DETECTED=1
        return 0
    fi

    return 1
}

extract_wp_version() {
    local FILE="$1" VALUE=""
    [ -s "$FILE" ] || return 1

    VALUE="$(grep -Eio '<meta[^>]+name=["'"']generator["'"'][^>]+content=["'"']WordPress[[:space:]]+[0-9]+(\.[0-9]+){1,3}[^>]*>' "$FILE" 2>/dev/null \
        | grep -Eo '[0-9]+(\.[0-9]+){1,3}' | head -1 || true)"
    if [ -n "$VALUE" ]; then
        WORDPRESS_VERSION="$VALUE"
        WORDPRESS_VERSION_SOURCE="meta generator"
        GENERATOR_EXPOSED=1
        return 0
    fi

    VALUE="$(grep -Eo "/wp-includes/[^\"' <]+[?&]ver=[0-9]+(\\.[0-9]+){1,3}" "$FILE" 2>/dev/null \
        | sed -E 's/.*[?&]ver=([0-9]+(\.[0-9]+){1,3}).*/\1/' \
        | sort -V | uniq -c | sort -nr | awk 'NR==1{print $2}' || true)"
    if [ -n "$VALUE" ]; then
        WORDPRESS_VERSION="$VALUE"
        WORDPRESS_VERSION_SOURCE="asset query string (indicativo)"
        return 0
    fi

    return 1
}

probe_route() {
    local ROUTE="$1" PREFIX="$2" META CODE
    META="$(public_get "${BASE_URL}${ROUTE}" "$TMPDIR/${PREFIX}.body" "$TMPDIR/${PREFIX}.headers")"
    CODE="$(meta_code "$META")"
    printf '%s' "$CODE"
}

collect_components() {
    local HOME="$1"
    local PLUGINS THEMES

    PLUGINS="$(grep -Eo '/wp-content/plugins/[A-Za-z0-9._-]+' "$HOME" 2>/dev/null \
        | sed -E 's#^/wp-content/plugins/##' | sort -u || true)"
    THEMES="$(grep -Eo '/wp-content/themes/[A-Za-z0-9._-]+' "$HOME" 2>/dev/null \
        | sed -E 's#^/wp-content/themes/##' | sort -u || true)"

    PLUGIN_LIST="$PLUGINS"
    THEME_LIST="$THEMES"
    if [ -n "$PLUGINS" ]; then PLUGIN_COUNT="$(printf '%s\n' "$PLUGINS" | sed '/^$/d' | wc -l | tr -d ' ')"; fi
    if [ -n "$THEMES" ]; then THEME_COUNT="$(printf '%s\n' "$THEMES" | sed '/^$/d' | wc -l | tr -d ' ')"; fi
}

measure_ttfb() {
    local URL="$1" OUT="$TMPDIR/ttfb.txt" I VALUE SEP
    : > "$OUT"

    SEP='?'
    [[ "$URL" == *"?"* ]] && SEP='&'

    for I in $(seq 1 "$TTFB_RUNS"); do
        VALUE="$(curl -ksS -o /dev/null \
            --connect-timeout 8 --max-time 25 \
            -A "$UA_BROWSER" \
            -H 'Cache-Control: no-cache' \
            -w '%{time_starttransfer}' \
            "${URL}${SEP}sitesmuggler_ttfb=${I}" 2>/dev/null || true)"

        if [[ "$VALUE" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
            awk -v v="$VALUE" 'BEGIN{printf "%.0f\n", v*1000}' >> "$OUT"
        fi
    done

    if [ -s "$OUT" ]; then
        sort -n "$OUT" -o "$OUT"
        TTFB_VALID="$(wc -l < "$OUT" | tr -d ' ')"
        TTFB_MIN="$(head -1 "$OUT")"
        TTFB_MAX="$(tail -1 "$OUT")"
        TTFB_AVERAGE="$(awk '{s+=$1} END{if(NR) printf "%.0f", s/NR}' "$OUT")"
        TTFB_MEDIAN="$(awk '{a[NR]=$1} END{if(NR%2) print a[(NR+1)/2]; else printf "%.0f", (a[NR/2]+a[NR/2+1])/2}' "$OUT")"
    fi
}

analyze_headers() {
    local FILE="$1" V
    SERVER_HINT="$(header_value 'server' "$FILE")"
    PHP_HINT="$(header_value 'x-powered-by' "$FILE")"
    CACHE_CONTROL="$(header_value 'cache-control' "$FILE")"

    if grep -Eqi '^strict-transport-security:' "$FILE"; then SECURITY_HEADERS_SCORE=$((SECURITY_HEADERS_SCORE + 1)); fi
    if grep -Eqi '^content-security-policy:' "$FILE"; then SECURITY_HEADERS_SCORE=$((SECURITY_HEADERS_SCORE + 1)); fi
    if grep -Eqi '^x-content-type-options:' "$FILE"; then SECURITY_HEADERS_SCORE=$((SECURITY_HEADERS_SCORE + 1)); fi
    if grep -Eqi '^referrer-policy:' "$FILE"; then SECURITY_HEADERS_SCORE=$((SECURITY_HEADERS_SCORE + 1)); fi
    if grep -Eqi '^permissions-policy:' "$FILE"; then SECURITY_HEADERS_SCORE=$((SECURITY_HEADERS_SCORE + 1)); fi

    V="$(cat "$FILE" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    if grep -Eqi '^x-litespeed-cache:' "$FILE"; then CACHE_TECH="LiteSpeed Cache";
    elif grep -Eqi '^x-kinsta-cache:' "$FILE"; then CACHE_TECH="Kinsta Cache";
    elif grep -Eqi '^x-wp-cf-super-cache:' "$FILE"; then CACHE_TECH="WP Cloudflare Super Page Cache";
    elif grep -Eqi '^x-fastcgi-cache:' "$FILE"; then CACHE_TECH="FastCGI cache";
    elif grep -Eqi '^x-proxy-cache:' "$FILE"; then CACHE_TECH="Proxy cache"; fi

    if grep -Eq '^cf-cache-status:[[:space:]]*(hit|miss|dynamic|bypass)' <<< "$V"; then
        CACHE_HINT="Cloudflare: $(header_value 'cf-cache-status' "$FILE")"
    elif grep -Eq '^x-sucuri-cache:' <<< "$V"; then
        CACHE_HINT="Sucuri: $(header_value 'x-sucuri-cache' "$FILE")"
    elif grep -Eq '^x-cache:' <<< "$V"; then
        CACHE_HINT="$(header_value 'x-cache' "$FILE")"
    elif grep -Eq '^x-cache-status:' <<< "$V"; then
        CACHE_HINT="$(header_value 'x-cache-status' "$FILE")"
    elif grep -Eq '^x-fastcgi-cache:' <<< "$V"; then
        CACHE_HINT="FastCGI: $(header_value 'x-fastcgi-cache' "$FILE")"
    fi
}

print_security_header() {
    local LABEL="$1" HEADER="$2" FILE="$3" VALUE
    VALUE="$(header_value "$HEADER" "$FILE")"
    if [ -n "$VALUE" ]; then
        print_line "[OK]   $LABEL" "$VALUE"
    else
        print_line "[WARN] $LABEL" "assente"
    fi
}

print_component_list() {
    local TITLE="$1" LIST="$2" LIMIT="${3:-20}" I=0 ITEM
    if [ -z "$LIST" ]; then
        print_line "$TITLE" "nessuno rilevato nell'HTML"
        return 0
    fi

    while IFS= read -r ITEM; do
        [ -n "$ITEM" ] || continue
        if [ "$I" -eq 0 ]; then
            print_line "$TITLE" "$ITEM"
        else
            print_line "" "$ITEM"
        fi
        I=$((I + 1))
        [ "$I" -ge "$LIMIT" ] && break
    done <<< "$LIST"
}

if [ -z "$TARGET" ]; then
    printf 'Dominio WordPress (es. example.com): '
    read -r TARGET
fi

if [ -z "$TARGET" ]; then
    echo "Errore: dominio non specificato."
    exit 1
fi

for CMD in curl grep sed awk sort cut tr head tail wc mktemp seq date; do
    if ! command -v "$CMD" >/dev/null 2>&1; then
        echo "Errore: comando richiesto non trovato: $CMD"
        exit 1
    fi
done

normalize_target
TMPDIR="$(mktemp -d)"

HOME_BODY="$TMPDIR/home.body"
HOME_HEADERS="$TMPDIR/home.headers"
HOME_META="$(public_get "$BASE_URL/" "$HOME_BODY" "$HOME_HEADERS")"
HOME_CODE="$(meta_code "$HOME_META")"
FINAL_URL="$(meta_url "$HOME_META")"
REMOTE_IP="$(meta_ip "$HOME_META")"

if [ "$HOME_CODE" = "000" ]; then
    if [[ "$BASE_URL" == https://* ]]; then
        BASE_URL="http://${BASE_URL#https://}"
        HOME_META="$(public_get "$BASE_URL/" "$HOME_BODY" "$HOME_HEADERS")"
        HOME_CODE="$(meta_code "$HOME_META")"
        FINAL_URL="$(meta_url "$HOME_META")"
        REMOTE_IP="$(meta_ip "$HOME_META")"
    fi
fi

[ -n "$FINAL_URL" ] && BASE_URL="${FINAL_URL%/}"
detect_waf "$HOME_HEADERS" "$HOME_BODY"
detect_wordpress "$HOME_BODY" || true
extract_wp_version "$HOME_BODY" || true
collect_components "$HOME_BODY"
analyze_headers "$HOME_HEADERS"

REST_API_STATUS="$(probe_route '/wp-json/' 'wp-json')"
XMLRPC_STATUS="$(probe_route '/xmlrpc.php' 'xmlrpc')"
WP_CRON_STATUS="$(probe_route '/wp-cron.php?doing_wp_cron=sitesmuggler' 'wp-cron')"
WP_LOGIN_STATUS="$(probe_route '/wp-login.php' 'wp-login')"
WP_INSTALL_STATUS="$(probe_route '/wp-admin/install.php' 'wp-install')"
WP_SIGNUP_STATUS="$(probe_route '/wp-signup.php' 'wp-signup')"
USERS_ENDPOINT_STATUS="$(probe_route '/wp-json/wp/v2/users?per_page=1' 'wp-users')"

if [ "$REST_API_STATUS" = "200" ] && grep -Eqi '"namespaces"|"routes"|wp/v2' "$TMPDIR/wp-json.body" 2>/dev/null; then
    WORDPRESS_DETECTED=1
fi

if [ "$USERS_ENDPOINT_STATUS" = "200" ] && grep -Eq '"id"[[:space:]]*:' "$TMPDIR/wp-users.body" 2>/dev/null; then
    USERS_EXPOSED=1
fi

if [ -z "$WORDPRESS_VERSION" ] && [ -s "$TMPDIR/wp-json.body" ]; then
    WORDPRESS_VERSION="$(grep -Eio 'wordpress\.org[^"[:space:]]*[?&](v|ver)=[0-9]+(\.[0-9]+){1,3}' "$TMPDIR/wp-json.body" 2>/dev/null \
        | grep -Eo '[0-9]+(\.[0-9]+){1,3}' | head -1 || true)"
    [ -n "$WORDPRESS_VERSION" ] && WORDPRESS_VERSION_SOURCE="REST API generator"
fi

README_STATUS="$(probe_route '/readme.html' 'readme')"
LICENSE_STATUS="$(probe_route '/license.txt' 'license')"
DEBUGLOG_STATUS="$(probe_route '/wp-content/debug.log' 'debug-log')"
CONFIGBAK_STATUS="$(probe_route '/wp-config.php.bak' 'wp-config-bak')"
CONFIGOLD_STATUS="$(probe_route '/wp-config.php.old' 'wp-config-old')"
GIT_STATUS="$(probe_route '/.git/HEAD' 'git-head')"
ENV_STATUS="$(probe_route '/.env' 'env')"

measure_ttfb "$BASE_URL/"

printf '============================================================\n'
printf ' CHECK WORDPRESS STATUS\n'
printf ' Remote WordPress / public surface checker\n'
printf ' Version %s\n' "$VERSION"
printf '============================================================\n\n'
printf 'Target  : %s\n' "$BASE_URL"
printf 'Domain  : %s\n' "$DOMAIN"
printf 'Date    : %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')"

section "1. HTTP / PLATFORM"
status_route "Homepage" "$HOME_CODE"
print_line "Final URL" "${FINAL_URL:-non determinato}"
print_line "Remote IP" "${REMOTE_IP:-non determinato}"
print_line "WAF / reverse proxy" "${WAF:-non rilevato}"
print_line "Server header" "${SERVER_HINT:-non esposto}"
print_line "X-Powered-By" "${PHP_HINT:-non esposto}"
print_line "Cache technology" "${CACHE_TECH:-non rilevata}"
print_line "Cache hint" "${CACHE_HINT:-non determinata}"
print_line "Cache-Control" "${CACHE_CONTROL:-non esposto}"

section "2. WORDPRESS DETECTION"
if [ "$WORDPRESS_DETECTED" -eq 1 ]; then
    print_line "[OK] WordPress" "rilevato"
else
    print_line "[WARN] WordPress" "non rilevato con certezza"
fi

if [ -n "$WORDPRESS_VERSION" ]; then
    print_line "WordPress version" "$WORDPRESS_VERSION"
    print_line "Version source" "$WORDPRESS_VERSION_SOURCE"
else
    print_line "WordPress version" "non determinata pubblicamente"
fi

if [ "$GENERATOR_EXPOSED" -eq 1 ]; then
    print_line "[INFO] Meta generator" "versione WordPress esposta"
else
    print_line "[OK]   Meta generator" "non espone la versione"
fi

print_line "Plugin visibili" "$PLUGIN_COUNT"
print_component_list "Plugin" "$PLUGIN_LIST" 20
print_line "Theme visibili" "$THEME_COUNT"
print_component_list "Theme" "$THEME_LIST" 10

section "3. WORDPRESS PUBLIC ROUTES"
status_route "REST API /wp-json/" "$REST_API_STATUS"
status_route "XML-RPC /xmlrpc.php" "$XMLRPC_STATUS"
status_route "WP Cron /wp-cron.php" "$WP_CRON_STATUS"
status_route "Login /wp-login.php" "$WP_LOGIN_STATUS"
status_route "Install /wp-admin/install.php" "$WP_INSTALL_STATUS"
status_route "Signup /wp-signup.php" "$WP_SIGNUP_STATUS"
status_route "REST users /wp-json/wp/v2/users" "$USERS_ENDPOINT_STATUS"

if [ "$USERS_EXPOSED" -eq 1 ]; then
    print_line "[WARN] REST user enumeration" "utenti pubblicamente enumerabili"
else
    print_line "[OK]   REST user enumeration" "non rilevata"
fi

section "4. COMMON EXPOSURES"
status_route "readme.html" "$README_STATUS"
status_route "license.txt" "$LICENSE_STATUS"
status_route "wp-content/debug.log" "$DEBUGLOG_STATUS"
status_route "wp-config.php.bak" "$CONFIGBAK_STATUS"
status_route "wp-config.php.old" "$CONFIGOLD_STATUS"
status_route ".git/HEAD" "$GIT_STATUS"
status_route ".env" "$ENV_STATUS"

if [ "$DEBUGLOG_STATUS" = "200" ]; then
    print_line "[CRIT] debug.log" "accessibile pubblicamente"
fi
if [ "$CONFIGBAK_STATUS" = "200" ] || [ "$CONFIGOLD_STATUS" = "200" ]; then
    print_line "[CRIT] wp-config backup" "possibile esposizione credenziali/configurazione"
fi
if [ "$GIT_STATUS" = "200" ]; then
    print_line "[CRIT] .git" "repository metadata accessibile"
fi
if [ "$ENV_STATUS" = "200" ]; then
    print_line "[CRIT] .env" "file ambiente accessibile"
fi

section "5. SECURITY HEADERS"
print_security_header "HSTS" "strict-transport-security" "$HOME_HEADERS"
print_security_header "CSP" "content-security-policy" "$HOME_HEADERS"
print_security_header "X-Content-Type-Options" "x-content-type-options" "$HOME_HEADERS"
print_security_header "Referrer-Policy" "referrer-policy" "$HOME_HEADERS"
print_security_header "Permissions-Policy" "permissions-policy" "$HOME_HEADERS"
print_line "Security headers score" "$SECURITY_HEADERS_SCORE / 5"

section "6. PERFORMANCE"
if [ "$TTFB_VALID" -gt 0 ]; then
    print_line "TTFB runs valid" "$TTFB_VALID / $TTFB_RUNS"
    print_line "TTFB median" "${TTFB_MEDIAN} ms"
    print_line "TTFB average" "${TTFB_AVERAGE} ms"
    print_line "TTFB min / max" "${TTFB_MIN} / ${TTFB_MAX} ms"
else
    print_line "TTFB" "non determinabile"
fi

section "7. QUICK ASSESSMENT"
ISSUES=0
CRITICAL=0

if [ "$WORDPRESS_DETECTED" -eq 0 ]; then
    print_line "[WARN] Platform" "WordPress non confermato"
    ISSUES=$((ISSUES + 1))
fi
if [ "$GENERATOR_EXPOSED" -eq 1 ]; then
    print_line "[WARN] Version disclosure" "meta generator espone la versione"
    ISSUES=$((ISSUES + 1))
fi
if [ "$USERS_EXPOSED" -eq 1 ]; then
    print_line "[WARN] User enumeration" "REST users accessibile"
    ISSUES=$((ISSUES + 1))
fi
if [ "$XMLRPC_STATUS" = "200" ] || [ "$XMLRPC_STATUS" = "405" ]; then
    print_line "[INFO] XML-RPC" "endpoint raggiungibile; verificare se necessario"
fi
if [ "$README_STATUS" = "200" ]; then
    print_line "[WARN] readme.html" "accessibile"
    ISSUES=$((ISSUES + 1))
fi
if [ "$DEBUGLOG_STATUS" = "200" ]; then
    print_line "[CRIT] debug.log" "esposto"
    CRITICAL=$((CRITICAL + 1))
fi
if [ "$CONFIGBAK_STATUS" = "200" ] || [ "$CONFIGOLD_STATUS" = "200" ]; then
    print_line "[CRIT] wp-config backup" "esposto"
    CRITICAL=$((CRITICAL + 1))
fi
if [ "$GIT_STATUS" = "200" ]; then
    print_line "[CRIT] .git" "esposto"
    CRITICAL=$((CRITICAL + 1))
fi
if [ "$ENV_STATUS" = "200" ]; then
    print_line "[CRIT] .env" "esposto"
    CRITICAL=$((CRITICAL + 1))
fi
if [ "$SECURITY_HEADERS_SCORE" -lt 3 ]; then
    print_line "[WARN] Security headers" "$SECURITY_HEADERS_SCORE / 5"
    ISSUES=$((ISSUES + 1))
fi
if [ "$TTFB_VALID" -gt 0 ] && [ "$TTFB_MEDIAN" -gt 1000 ]; then
    print_line "[WARN] TTFB" "mediana > 1000 ms"
    ISSUES=$((ISSUES + 1))
elif [ "$TTFB_VALID" -gt 0 ] && [ "$TTFB_MEDIAN" -gt 600 ]; then
    print_line "[INFO] TTFB" "mediana > 600 ms"
fi

if [ "$CRITICAL" -eq 0 ] && [ "$ISSUES" -eq 0 ]; then
    print_line "Result" "nessuna anomalia evidente dal controllo remoto"
else
    print_line "Result" "$CRITICAL criticità / $ISSUES warning"
fi

printf '\nNote: controllo remoto non autenticato; non sostituisce audit filesystem, plugin e configurazione server.\n'
