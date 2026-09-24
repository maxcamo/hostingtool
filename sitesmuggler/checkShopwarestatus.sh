#!/usr/bin/env bash
set -u

VERSION="1.0.1"
TARGET="${1:-}"
TTFB_RUNS="${TTFB_RUNS:-10}"

TMPDIR=""
BASE_URL=""
DOMAIN=""
FINAL_URL=""
REMOTE_IP=""
WAF=""
SHOPWARE_FAMILY=""
SHOPWARE_VERSION=""
VERSION_SOURCE=""
VERSION_PUBLIC=0
SENSITIVE=0

TTFB_MEDIAN=""
TTFB_AVG=""
TTFB_MIN=""
TTFB_MAX=""
CACHE_MEDIAN=""
CACHE_AVG=""
CACHE_MIN=""
CACHE_MAX=""

JS_CDN="non determinata"
IMG_CDN="non determinata"

UA="SiteSmuggler-ShopwareStatus/1.0.1"
BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

cleanup() {
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

pl() {
    printf '%-56s %s\n' "$1" "$2"
}

status() {
    local label code
    label="$1"
    code="${2:-000}"

    case "$code" in
        200|201|202|204|301|302|303|307|308|400) pl "[ACTIVE] $label" "HTTP $code" ;;
        401|403|405) pl "[BLOCK]  $label" "HTTP $code" ;;
        404) pl "[OFF]    $label" "HTTP 404" ;;
        000|'') pl "[WARN]   $label" "HTTP 000" ;;
        *) pl "[REACH]  $label" "HTTP $code" ;;
    esac
}

normalize() {
    TARGET="${TARGET%/}"

    if [[ "$TARGET" =~ ^https?:// ]]; then
        BASE_URL="$TARGET"
    else
        BASE_URL="https://$TARGET"
    fi

    DOMAIN="${BASE_URL#*://}"
    DOMAIN="${DOMAIN%%/*}"
    DOMAIN="${DOMAIN%%:*}"
    DOMAIN="${DOMAIN%.}"
    DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
}

get_url() {
    local url body head out rc errfile errmsg
    url="$1"
    body="$2"
    head="$3"
    errfile="$TMPDIR/curl.$RANDOM.err"

    out="$(curl -ksSL \
        --max-redirs 8 \
        --connect-timeout 8 \
        --max-time 25 \
        -A "$UA" \
        -D "$head" \
        -o "$body" \
        -w '%{http_code}|%{url_effective}|%{remote_ip}' \
        "$url" 2>"$errfile")"
    rc=$?

    if [ "$rc" -eq 0 ]; then
        printf '%s' "$out"
    else
        errmsg="$(tail -1 "$errfile" 2>/dev/null | tr '|' '/' | tr '\n\r' '  ')"
        printf '000|||%s' "${errmsg:-curl exit code $rc}"
    fi
}

meta_code() { printf '%s' "$1" | cut -d'|' -f1; }
meta_url()  { printf '%s' "$1" | cut -d'|' -f2; }
meta_ip()   { printf '%s' "$1" | cut -d'|' -f3; }
meta_error(){ printf '%s' "$1" | cut -d'|' -f4-; }

waf() {
    local t
    t="$(cat "$1" "$2" 2>/dev/null | tr '[:upper:]' '[:lower:]')"
    WAF=""

    grep -Eq 'cf-ray:|server:[[:space:]]*cloudflare|cf-cache-status:' <<<"$t" && WAF="Cloudflare"
    [ -z "$WAF" ] && grep -Eq 'x-sucuri-id:|x-sucuri-cache:|server:[[:space:]]*sucuri' <<<"$t" && WAF="Sucuri"
    [ -z "$WAF" ] && grep -Eq 'x-iinfo:|incapsula|imperva' <<<"$t" && WAF="Imperva/Incapsula"
    [ -z "$WAF" ] && grep -Eq 'x-amz-cf-id:|x-amz-cf-pop:|cloudfront' <<<"$t" && WAF="AWS CloudFront/CDN"
    [ -z "$WAF" ] && grep -Eq 'fastly|x-served-by:.*cache-' <<<"$t" && WAF="Fastly/CDN"
    [ -z "$WAF" ] && grep -Eq 'akamai|x-akamai-' <<<"$t" && WAF="Akamai"
    [ -z "$WAF" ] && grep -Eq 'x-varnish:|via:.*varnish' <<<"$t" && WAF="Varnish/Reverse proxy"
    true
}

extract_version() {
    local f v
    f="$1"
    [ -s "$f" ] || return 1

    v="$(grep -Eio 'Shopware[[:space:]/_-]*[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' "$f" 2>/dev/null \
        | grep -Eo '[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' \
        | head -1 || true)"

    if [ -z "$v" ]; then
        v="$(grep -Eio '"version"[[:space:]]*:[[:space:]]*"[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?"' "$f" 2>/dev/null \
            | grep -Eo '[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' \
            | head -1 || true)"
    fi

    [ -n "$v" ] && printf '%s' "$v"
}

set_version() {
    local value source
    value="$1"
    source="$2"

    [ -n "$value" ] || return 0

    if [ -z "$SHOPWARE_VERSION" ]; then
        SHOPWARE_VERSION="$value"
        VERSION_SOURCE="$source"
    fi

    case "$value" in
        5.*) SHOPWARE_FAMILY="Shopware 5" ;;
        6.*) SHOPWARE_FAMILY="Shopware 6" ;;
    esac
}

detect_family() {
    local f
    f="$1"
    [ -s "$f" ] || return 0

    if grep -Eqi '/bundles/storefront/|/bundles/[A-Za-z0-9_-]+/|/theme/[^"[:space:]]+\.(css|js)|sw-cache-hash|shopware storefront|data-swag-' "$f" 2>/dev/null; then
        SHOPWARE_FAMILY="Shopware 6"
        return
    fi

    if grep -Eqi '/engine/Shopware/|/themes/Frontend/|shopware\.js|Shopware\.Controller|emotion--|is--ctl-' "$f" 2>/dev/null; then
        SHOPWARE_FAMILY="Shopware 5"
        return
    fi

    grep -Eqi 'Shopware' "$f" 2>/dev/null && SHOPWARE_FAMILY="Shopware (family non determinata)"
}

sensitive() {
    local path re label b h m c
    path="$1"
    re="$2"
    label="$3"
    b="$TMPDIR/s.$RANDOM"
    h="$b.h"

    m="$(get_url "$BASE_URL$path" "$b" "$h")"
    c="$(meta_code "$m")"

    if [ "$c" = "200" ] && grep -Eqi "$re" "$b" 2>/dev/null; then
        pl "[CRITICAL] $label" "HTTP 200 - contenuto sensibile leggibile"
        SENSITIVE=$((SENSITIVE + 1))
    elif [ "$c" = "200" ]; then
        pl "[INFO] $label" "HTTP 200 ma contenuto non corrispondente (fallback probabile)"
    else
        status "$label" "$c"
    fi
}

ms() {
    awk -v s="$1" 'BEGIN { printf "%.0f", s * 1000 }'
}

stats() {
    local f p n avg min max med
    f="$1"
    p="$2"

    n="$(wc -l < "$f" | tr -d ' ')"
    [ "$n" -gt 0 ] || return 1

    avg="$(awk '{s+=$1} END {if(NR) printf "%.0f", s/NR}' "$f")"
    min="$(sort -n "$f" | head -1)"
    max="$(sort -n "$f" | tail -1)"
    med="$(sort -n "$f" | awk '{a[NR]=$1} END {if(NR%2) printf "%.0f",a[(NR+1)/2]; else printf "%.0f",(a[NR/2]+a[NR/2+1])/2}')"

    if [ "$p" = "n" ]; then
        TTFB_MEDIAN="$med"
        TTFB_AVG="$avg"
        TTFB_MIN="$min"
        TTFB_MAX="$max"
    else
        CACHE_MEDIAN="$med"
        CACHE_AVG="$avg"
        CACHE_MIN="$min"
        CACHE_MAX="$max"
    fi
}

cache_summary() {
    local head value
    head="$1"

    value="$(grep -Ei '^(cf-cache-status|x-cache|x-cache-hits|x-sucuri-cache|age|x-varnish|cache-control):' "$head" 2>/dev/null \
        | tail -4 \
        | tr '\n' ' ' \
        | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"

    [ -n "$value" ] && printf '%s' "$value"
}

benchmark() {
    local mode url vals i r rc c t total tms totalms testurl sep head cache
    mode="$1"
    url="$2"
    vals="$TMPDIR/${mode}.val"

    : > "$vals"

    if [ "$mode" = "cache" ]; then
        echo "Warm-up..."
        curl -ksSL --connect-timeout 8 --max-time 30 -A "$BROWSER" -o /dev/null "$url" 2>/dev/null || true
    fi

    for ((i=1; i<=TTFB_RUNS; i++)); do
        testurl="$url"
        head="$TMPDIR/${mode}.${i}.h"
        cache=""

        if [ "$mode" = "nocache" ]; then
            sep='?'
            [[ "$url" == *\?* ]] && sep='&'
            testurl="${url}${sep}sitesmuggler_ttfb=$(date +%s)-$$-$i"
            r="$(curl -ksSL \
                --max-redirs 8 \
                --connect-timeout 8 \
                --max-time 30 \
                -A "$BROWSER" \
                -H 'Cache-Control: no-cache' \
                -H 'Pragma: no-cache' \
                -o /dev/null \
                -w '%{http_code}|%{time_starttransfer}|%{time_total}' \
                "$testurl" 2>/dev/null)"
            rc=$?
        else
            r="$(curl -ksSL \
                --max-redirs 8 \
                --connect-timeout 8 \
                --max-time 30 \
                -A "$BROWSER" \
                -D "$head" \
                -o /dev/null \
                -w '%{http_code}|%{time_starttransfer}|%{time_total}' \
                "$testurl" 2>/dev/null)"
            rc=$?
        fi

        if [ "$rc" -ne 0 ] || [ -z "$r" ]; then
            r="000|0|0"
        fi

        IFS='|' read -r c t total <<< "$r"
        tms="$(ms "${t:-0}")"
        totalms="$(ms "${total:-0}")"

        printf '%s %02d | HTTP=%s | TTFB=%4s ms | TOTAL=%4s ms' "${mode^^}" "$i" "$c" "$tms" "$totalms"

        if [ "$mode" = "cache" ] && [ -s "$head" ]; then
            cache="$(cache_summary "$head" || true)"
            [ -n "$cache" ] && printf ' | CACHE=%s' "$cache"
        fi

        printf '\n'

        case "$c" in
            2??|3??)
                [ "$tms" -gt 0 ] 2>/dev/null && printf '%s\n' "$tms" >> "$vals"
                ;;
        esac
    done

    if [ "$mode" = "nocache" ]; then
        stats "$vals" "n" || true
    else
        stats "$vals" "c" || true
    fi
}

origin() {
    local u scheme host
    u="$1"
    scheme="${u%%:*}"
    host="${u#*://}"
    host="${host%%/*}"
    printf '%s://%s' "$scheme" "$host"
}

resolve_asset() {
    local src page base
    src="$1"
    page="$2"
    base="$(origin "$page")"

    case "$src" in
        ''|data:*|blob:*|javascript:*) return 1 ;;
        //*) printf '%s:%s' "${page%%:*}" "$src" ;;
        http://*|https://*) printf '%s' "$src" ;;
        /*) printf '%s%s' "$base" "$src" ;;
        *) return 1 ;;
    esac
}

assets() {
    local typ html page out rawfile src resolved
    typ="$1"
    html="$2"
    page="$3"
    out="$TMPDIR/${typ}.urls"
    rawfile="$TMPDIR/${typ}.raw"

    : > "$out"
    : > "$rawfile"

    [ -s "$html" ] || {
        printf '%s' "$out"
        return
    }

    if [ "$typ" = "js" ]; then
        grep -Eio "<script[^>]+src=[\"'][^\"']+[\"']" "$html" 2>/dev/null \
            | sed -E "s/.*src=[\"']([^\"']+)[\"'].*/\1/" > "$rawfile" || true
    else
        grep -Eio "<img[^>]+(src|data-src)=[\"'][^\"']+[\"']" "$html" 2>/dev/null \
            | sed -E "s/.*(src|data-src)=[\"']([^\"']+)[\"'].*/\2/" > "$rawfile" || true
    fi

    while IFS= read -r src; do
        [ -n "$src" ] || continue
        resolved="$(resolve_asset "$src" "$page" || true)"
        [ -n "$resolved" ] && printf '%s\n' "$resolved"
    done < "$rawfile" | sort -u > "$out"

    printf '%s' "$out"
}

cdn_check() {
    local typ list n u host h txt prov found total
    typ="$1"
    list="$2"
    n=0
    found=""

    if [ ! -f "$list" ]; then
        pl "[INFO] ${typ^^} assets" "nessun asset rilevato"
        return
    fi

    total="$(wc -l < "$list" | tr -d ' ')"

    if [ "$total" -le 0 ]; then
        pl "[INFO] ${typ^^} assets" "nessun asset rilevato"
        return
    fi

    while IFS= read -r u; do
        [ -n "$u" ] || continue

        host="${u#*://}"
        host="${host%%/*}"
        h="$TMPDIR/cdn.${typ}.${n}"

        curl -ksSIL \
            --max-redirs 5 \
            --connect-timeout 5 \
            --max-time 12 \
            -A "$UA" \
            -D "$h" \
            -o /dev/null \
            "$u" 2>/dev/null || true

        txt="$(tr '[:upper:]' '[:lower:]' < "$h" 2>/dev/null || true)"
        prov=""

        grep -Eq 'cloudflare|cf-cache-status|cf-ray' <<<"$txt" && prov="Cloudflare"
        [ -z "$prov" ] && grep -Eq 'cloudfront|x-amz-cf-' <<<"$txt" && prov="AWS CloudFront"
        [ -z "$prov" ] && grep -Eq 'sucuri|x-sucuri-' <<<"$txt" && prov="Sucuri"
        [ -z "$prov" ] && grep -Eq 'fastly|x-served-by' <<<"$txt" && prov="Fastly"
        [ -z "$prov" ] && grep -Eq 'akamai|x-akamai-' <<<"$txt" && prov="Akamai"
        [ -z "$prov" ] && grep -Eq 'bunnycdn|cdn-pullzone' <<<"$txt" && prov="Bunny CDN"

        if [ -n "$prov" ]; then
            pl "[CDN] ${typ^^} asset" "$prov | $host"
            case ",$found," in
                *",$prov,"*) ;;
                *) found="${found:+$found, }$prov" ;;
            esac
        else
            pl "[INFO] ${typ^^} asset" "$host | CDN non identificata"
        fi

        n=$((n + 1))
        [ "$n" -ge 6 ] && break
    done < "$list"

    pl "[INFO] ${typ^^} asset URLs" "$total rilevati; $n verificati"

    if [ -n "$found" ]; then
        if [ "$typ" = "js" ]; then
            JS_CDN="$found"
        else
            IMG_CDN="$found"
        fi
    fi
}

route_probe() {
    local path label b h m
    path="$1"
    label="$2"
    b="$TMPDIR/route.$RANDOM"
    h="$b.h"
    m="$(get_url "$BASE_URL$path" "$b" "$h")"
    status "$label ($path)" "$(meta_code "$m")"
}

if [ -z "$TARGET" ]; then
    clear
    read -r -p "Dominio Shopware: " TARGET
fi

normalize

if [ -z "$DOMAIN" ] || [[ "$DOMAIN" != *.* ]]; then
    echo "[ERROR] Dominio non valido: $DOMAIN"
    exit 1
fi

command -v curl >/dev/null 2>&1 || {
    echo "[ERROR] curl non trovato"
    exit 1
}

TMPDIR="$(mktemp -d /tmp/checkShopwareStatus.XXXXXX)"

echo "============================================================"
echo " CHECK SHOPWARE STATUS - REMOTE v$VERSION"
echo "============================================================"
echo "Target : $BASE_URL"
echo "Date   : $(date)"
echo

echo "== 1. PUBLIC STATUS / WAF =="

HOME="$TMPDIR/home"
HEAD="$TMPDIR/home.h"
META="$(get_url "$BASE_URL/" "$HOME" "$HEAD")"
C="$(meta_code "$META")"
FINAL_URL="$(meta_url "$META")"
REMOTE_IP="$(meta_ip "$META")"

status "Homepage" "$C"

if [ "$C" = "000" ]; then
    ERR="$(meta_error "$META")"
    [ -n "$ERR" ] && pl "[ERROR] Connessione" "$ERR"

    if command -v getent >/dev/null 2>&1; then
        DNS_IP="$(getent ahostsv4 "$DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')"
        if [ -n "$DNS_IP" ]; then
            pl "[INFO] DNS" "$DOMAIN -> $DNS_IP"
        else
            pl "[ERROR] DNS" "$DOMAIN non risolve da questo server"
        fi
    fi

    echo
    echo "[STOP] Homepage non raggiungibile: interrompo i probe per evitare una serie di HTTP 000."
    exit 2
fi

pl "[INFO] Final URL" "${FINAL_URL:-n/d}"
pl "[INFO] Remote IP" "${REMOTE_IP:-n/d}"
waf "$HEAD" "$HOME"
pl "[INFO] WAF/CDN" "${WAF:-non identificato}"
detect_family "$HOME"
pl "[RESULT] Shopware family" "${SHOPWARE_FAMILY:-non determinata}"

echo
echo "== 2. VERSION FINGERPRINT =="

V="$(extract_version "$HOME" || true)"
[ -n "$V" ] && set_version "$V" "homepage HTML"

for E in \
    "/api/_info/config|Admin info config" \
    "/api/_info/openapi3.json|Admin OpenAPI" \
    "/store-api/_info/openapi3.json|Store API OpenAPI"
do
    P="${E%%|*}"
    L="${E#*|}"
    B="$TMPDIR/ep.$RANDOM"
    H="$B.h"
    M="$(get_url "$BASE_URL$P" "$B" "$H")"
    EC="$(meta_code "$M")"
    EV="$(extract_version "$B" || true)"

    status "$L ($P)" "$EC"

    if [ "$EC" = "200" ] && [ -n "$EV" ]; then
        pl "[LEAK] Shopware version" "$EV via $P"
        VERSION_PUBLIC=1
        set_version "$EV" "$P"
    fi

    if [ "$P" = "/api/_info/config" ] && [ "$EC" = "200" ] \
        && grep -Eq '"shopId"|"appUrl"|"versionRevision"|"bundles"' "$B" 2>/dev/null
    then
        pl "[WARN] Admin info disclosure" "config amministrativa pubblicamente leggibile"
    fi
done

pl "[RESULT] Shopware version" "${SHOPWARE_VERSION:-non determinata con affidabilita}"
[ -n "$VERSION_SOURCE" ] && pl "[INFO] Version source" "$VERSION_SOURCE"

echo
echo "== 3. EXPOSED SURFACE / SECURITY =="

route_probe "/admin" "Shopware 6 Administration"
route_probe "/backend" "Shopware 5 Backend"
route_probe "/api/" "Admin API root"
route_probe "/api/_info/entity-schema.json" "Entity schema"
route_probe "/api/_info/stoplightio.html" "API browser"
route_probe "/recovery/install/" "Recovery installer"
route_probe "/recovery/update/" "Recovery updater"
route_probe "/install/" "Installer"

echo "-- Sensitive files --"
sensitive "/.env" 'APP_ENV=|APP_SECRET=|DATABASE_URL=|MAILER_DSN=' ".env"
sensitive "/.git/HEAD" '^ref:[[:space:]]+refs/heads/' ".git/HEAD"
sensitive "/composer.json" '"(name|require)"[[:space:]]*:' "composer.json"

echo "-- Public bundle/plugin fingerprints --"
grep -Eio '/bundles/[A-Za-z0-9_-]+/' "$HOME" 2>/dev/null \
    | sed -E 's#^/bundles/##;s#/$##' \
    | sort -fu \
    | head -20 \
    | while read -r x; do pl "[DETECTED] Public bundle" "$x"; done || true

grep -Eio '/engine/Shopware/Plugins/(Community|Local|Default)/[^/"[:space:]]+' "$HOME" 2>/dev/null \
    | sed -E 's#^.*/Plugins/##' \
    | sort -fu \
    | head -20 \
    | while read -r x; do pl "[DETECTED] Public plugin" "$x"; done || true

echo
echo "== 4. ASSET CDN CHECK =="

PAGE="${FINAL_URL:-$BASE_URL/}"
J="$(assets js "$HOME" "$PAGE")"
I="$(assets img "$HOME" "$PAGE")"
cdn_check "js" "$J"
cdn_check "img" "$I"

echo
echo "== 5. TTFB BENCHMARK =="
echo "-- NO-CACHE / CACHE-BUSTER --"
benchmark "nocache" "$PAGE"

echo "-- WARM CACHE --"
benchmark "cache" "$PAGE"

echo
echo "== 6. SUMMARY =="

echo "WAF/CDN          : ${WAF:-non identificato}"
echo "Shopware family  : ${SHOPWARE_FAMILY:-non determinata}"
echo "Shopware version : ${SHOPWARE_VERSION:-non determinata} ${VERSION_SOURCE:+($VERSION_SOURCE)}"
echo "Version exposure : $([ "$VERSION_PUBLIC" -eq 1 ] && echo RILEVATA || echo non rilevata)"
echo "Sensitive files  : $SENSITIVE esposizioni confermate"
echo "Remote IP        : ${REMOTE_IP:-n/d}"
echo "JS CDN           : $JS_CDN"
echo "Image CDN        : $IMG_CDN"

if [ -n "$TTFB_MEDIAN" ]; then
    echo "TTFB no-cache    : median ${TTFB_MEDIAN} ms | avg ${TTFB_AVG} | range ${TTFB_MIN}-${TTFB_MAX}"
else
    echo "TTFB no-cache    : non determinato"
fi

if [ -n "$CACHE_MEDIAN" ]; then
    echo "TTFB cached      : median ${CACHE_MEDIAN} ms | avg ${CACHE_AVG} | range ${CACHE_MIN}-${CACHE_MAX}"
else
    echo "TTFB cached      : non determinato"
fi

echo
echo "ACTIVE/REACH = route raggiungibile; non significa vulnerabile."
echo "CRITICAL sui file sensibili solo se il contenuto corrisponde realmente al file richiesto."
echo "Checker remoto: nessun login, payload o exploit; solo GET/HEAD e benchmark HTTP."
