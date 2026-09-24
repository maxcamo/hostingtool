#!/usr/bin/env bash
set -u

VERSION="1.0.0"
TARGET="${1:-}"
TTFB_RUNS="${TTFB_RUNS:-10}"
TMPDIR=""
BASE_URL=""; DOMAIN=""; FINAL_URL=""; REMOTE_IP=""
WAF=""; SHOPWARE_FAMILY=""; SHOPWARE_VERSION=""; VERSION_SOURCE=""
VERSION_PUBLIC=0; SENSITIVE=0
TTFB_MEDIAN=""; TTFB_AVG=""; TTFB_MIN=""; TTFB_MAX=""
CACHE_MEDIAN=""; CACHE_AVG=""; CACHE_MIN=""; CACHE_MAX=""
JS_CDN="non determinata"; IMG_CDN="non determinata"
UA="SiteSmuggler-ShopwareStatus/1.0"
BROWSER="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/150 Safari/537.36"

cleanup(){ [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"; }
trap cleanup EXIT
pl(){ printf '%-56s %s\n' "$1" "$2"; }
status(){
  case "${2:-000}" in
    200|201|202|204|301|302|303|307|308|400) pl "[ACTIVE] $1" "HTTP $2";;
    401|403|405) pl "[BLOCK]  $1" "HTTP $2";;
    404) pl "[OFF]    $1" "HTTP 404";;
    000|'') pl "[WARN]   $1" "HTTP 000";;
    *) pl "[REACH]  $1" "HTTP $2";;
  esac
}

normalize(){
  TARGET="${TARGET%/}"
  [[ "$TARGET" =~ ^https?:// ]] && BASE_URL="$TARGET" || BASE_URL="https://$TARGET"
  DOMAIN="${BASE_URL#*://}"; DOMAIN="${DOMAIN%%/*}"; DOMAIN="${DOMAIN%%:*}"; DOMAIN="${DOMAIN%.}"
  DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"
}
get(){
  local url="$1" body="$2" head="$3" out rc
  out="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 25 -A "$UA" -D "$head" -o "$body" -w '%{http_code}|%{url_effective}|%{remote_ip}' "$url" 2>/dev/null)"; rc=$?
  [ "$rc" -eq 0 ] && printf '%s' "$out" || printf '000||'
}
code(){ printf '%s' "$1" | cut -d'|' -f1; }
eff(){ printf '%s' "$1" | cut -d'|' -f2; }
ip(){ printf '%s' "$1" | cut -d'|' -f3; }

waf(){
  local t; t="$(cat "$1" "$2" 2>/dev/null | tr '[:upper:]' '[:lower:]')"; WAF=""
  grep -Eq 'cf-ray:|server:[[:space:]]*cloudflare|cf-cache-status:' <<<"$t" && WAF="Cloudflare"
  [ -z "$WAF" ] && grep -Eq 'x-sucuri-id:|x-sucuri-cache:|server:[[:space:]]*sucuri' <<<"$t" && WAF="Sucuri"
  [ -z "$WAF" ] && grep -Eq 'x-iinfo:|incapsula|imperva' <<<"$t" && WAF="Imperva/Incapsula"
  [ -z "$WAF" ] && grep -Eq 'x-amz-cf-id:|x-amz-cf-pop:|cloudfront' <<<"$t" && WAF="AWS CloudFront/CDN"
  [ -z "$WAF" ] && grep -Eq 'fastly|x-served-by:.*cache-' <<<"$t" && WAF="Fastly/CDN"
  [ -z "$WAF" ] && grep -Eq 'akamai|x-akamai-' <<<"$t" && WAF="Akamai"
  [ -z "$WAF" ] && grep -Eq 'x-varnish:|via:.*varnish' <<<"$t" && WAF="Varnish/Reverse proxy"
  true
}

extract_version(){
  local f="$1" v
  [ -s "$f" ] || return 1
  v="$(grep -Eio 'Shopware[[:space:]/_-]*[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' "$f" 2>/dev/null | grep -Eo '[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' | head -1 || true)"
  [ -z "$v" ] && v="$(grep -Eio '"version"[[:space:]]*:[[:space:]]*"[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?"' "$f" 2>/dev/null | grep -Eo '[56](\.[0-9]+){1,3}([.-][A-Za-z0-9]+)?' | head -1 || true)"
  [ -n "$v" ] && printf '%s' "$v"
}
set_version(){
  [ -n "$1" ] || return 0
  if [ -z "$SHOPWARE_VERSION" ]; then SHOPWARE_VERSION="$1"; VERSION_SOURCE="$2"; fi
  case "$1" in 5.*) SHOPWARE_FAMILY="Shopware 5";; 6.*) SHOPWARE_FAMILY="Shopware 6";; esac
}
detect_family(){
  local f="$1"
  grep -Eqi '/bundles/storefront/|/bundles/[A-Za-z0-9_-]+/|/theme/[^"[:space:]]+\.(css|js)|sw-cache-hash|shopware storefront' "$f" 2>/dev/null && { SHOPWARE_FAMILY="Shopware 6"; return; }
  grep -Eqi '/engine/Shopware/|/themes/Frontend/|shopware\.js|Shopware\.Controller|emotion--|is--ctl-' "$f" 2>/dev/null && { SHOPWARE_FAMILY="Shopware 5"; return; }
  grep -Eqi 'Shopware' "$f" 2>/dev/null && SHOPWARE_FAMILY="Shopware (family non determinata)"
}

sensitive(){
  local path="$1" re="$2" label="$3" b="$TMPDIR/s.$$" h="$TMPDIR/sh.$$" m c
  m="$(get "$BASE_URL$path" "$b" "$h")"; c="$(code "$m")"
  if [ "$c" = 200 ] && grep -Eqi "$re" "$b" 2>/dev/null; then pl "[CRITICAL] $label" "HTTP 200 - contenuto sensibile leggibile"; SENSITIVE=$((SENSITIVE+1))
  elif [ "$c" = 200 ]; then pl "[INFO] $label" "HTTP 200 ma contenuto non corrispondente (fallback probabile)"
  else status "$label" "$c"; fi
}

ms(){ awk -v s="$1" 'BEGIN{printf "%.0f",s*1000}'; }
stats(){
  local f="$1" p="$2" n
  n="$(wc -l < "$f" | tr -d ' ')"; [ "$n" -gt 0 ] || return 1
  local a mi ma me
  a="$(awk '{s+=$1}END{printf "%.0f",s/NR}' "$f")"; mi="$(sort -n "$f"|head -1)"; ma="$(sort -n "$f"|tail -1)"; me="$(sort -n "$f"|awk '{a[NR]=$1}END{if(NR%2)printf "%.0f",a[(NR+1)/2];else printf "%.0f",(a[NR/2]+a[NR/2+1])/2}')"
  if [ "$p" = n ]; then TTFB_MEDIAN="$me"; TTFB_AVG="$a"; TTFB_MIN="$mi"; TTFB_MAX="$ma"; else CACHE_MEDIAN="$me"; CACHE_AVG="$a"; CACHE_MIN="$mi"; CACHE_MAX="$ma"; fi
}
benchmark(){
  local mode="$1" url="$2" vals="$TMPDIR/$mode.val" i r c t total tms totalms testurl sep head cache
  : > "$vals"
  [ "$mode" = cache ] && { echo "Warm-up..."; curl -ksSL --connect-timeout 8 --max-time 30 -A "$BROWSER" -o /dev/null "$url" 2>/dev/null || true; }
  for ((i=1;i<=TTFB_RUNS;i++)); do
    testurl="$url"; head="$TMPDIR/$mode.$i.h"
    if [ "$mode" = nocache ]; then sep='?'; [[ "$url" == *\?* ]] && sep='&'; testurl="${url}${sep}sitesmuggler_ttfb=$(date +%s)-$$-$i"; fi
    if [ "$mode" = nocache ]; then
      r="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 30 -A "$BROWSER" -H 'Cache-Control: no-cache' -H 'Pragma: no-cache' -o /dev/null -w '%{http_code}|%{time_starttransfer}|%{time_total}' "$testurl" 2>/dev/null)"
    else
      r="$(curl -ksSL --max-redirs 8 --connect-timeout 8 --max-time 30 -A "$BROWSER" -D "$head" -o /dev/null -w '%{http_code}|%{time_starttransfer}|%{time_total}' "$testurl" 2>/dev/null)"
    fi
    IFS='|' read -r c t total <<<"${r:-000|0|0}"; tms="$(ms "${t:-0}")"; totalms="$(ms "${total:-0}")"
    printf '%s %02d | HTTP=%s | TTFB=%4s ms | TOTAL=%4s ms' "${mode^^}" "$i" "$c" "$tms" "$totalms"
    if [ "$mode" = cache ] && [ -s "$head" ]; then cache="$(grep -Ei '^(cf-cache-status|x-cache|x-cache-hits|x-sucuri-cache|age|x-varnish):' "$head" | tail -3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g')"; [ -n "$cache" ] && printf ' | %s' "$cache"; fi
    printf '\n'; case "$c" in 2??|3??) [ "$tms" -gt 0 ] 2>/dev/null && echo "$tms" >> "$vals";; esac
  done
  stats "$vals" "$([ "$mode" = nocache ] && echo n || echo c)" || true
}

origin(){ local u="$1"; printf '%s://%s' "${u%%:*}" "$(printf '%s' "${u#*://}"|cut -d/ -f1)"; }
assets(){
  local typ="$1" html="$2" page="$3" out="$TMPDIR/$typ.urls" raw src base
  : > "$out"; base="$(origin "$page")"
  if [ "$typ" = js ]; then grep -Eio "<script[^>]+src=[\"'][^\"']+[\"']" "$html" 2>/dev/null | sed -E "s/.*src=[\"']([^\"']+)[\"'].*/\1/" > "$TMPDIR/raw" || true
  else grep -Eio "<img[^>]+(src|data-src)=[\"'][^\"']+[\"']" "$html" 2>/dev/null | sed -E "s/.*(src|data-src)=[\"']([^\"']+)[\"'].*/\2/" > "$TMPDIR/raw" || true; fi
  while IFS= read -r src; do case "$src" in //*) echo "${page%%:*}:$src";; http*) echo "$src";; /*) echo "$base$src";; esac; done < "$TMPDIR/raw" | sort -u > "$out"
  printf '%s' "$out"
}
cdn_check(){
  local typ="$1" list="$2" n=0 u host h txt prov found="" total
  total="$(wc -l < "$list" | tr -d ' ')"; [ "$total" -gt 0 ] || { pl "[INFO] ${typ^^} assets" "nessun asset rilevato"; return; }
  while IFS= read -r u; do [ -n "$u" ] || continue; host="${u#*://}"; host="${host%%/*}"; h="$TMPDIR/cdn.$typ.$n"; curl -ksSIL --connect-timeout 5 --max-time 12 -A "$UA" -D "$h" -o /dev/null "$u" 2>/dev/null || true; txt="$(tr '[:upper:]' '[:lower:]' < "$h" 2>/dev/null)"; prov=""
    grep -Eq 'cloudflare|cf-cache-status|cf-ray' <<<"$txt" && prov="Cloudflare"; [ -z "$prov" ] && grep -Eq 'cloudfront|x-amz-cf-' <<<"$txt" && prov="AWS CloudFront"; [ -z "$prov" ] && grep -Eq 'sucuri|x-sucuri-' <<<"$txt" && prov="Sucuri"; [ -z "$prov" ] && grep -Eq 'fastly|x-served-by' <<<"$txt" && prov="Fastly"; [ -z "$prov" ] && grep -Eq 'akamai|x-akamai-' <<<"$txt" && prov="Akamai"
    [ -n "$prov" ] && { pl "[CDN] ${typ^^} asset" "$prov | $host"; found="${found:+$found, }$prov"; } || pl "[INFO] ${typ^^} asset" "$host | CDN non identificata"
    n=$((n+1)); [ "$n" -ge 6 ] && break
  done < "$list"
  [ -n "$found" ] && { [ "$typ" = js ] && JS_CDN="$found" || IMG_CDN="$found"; }
}

[ -z "$TARGET" ] && { clear; read -r -p "Dominio Shopware: " TARGET; }
normalize
[ -z "$DOMAIN" ] || [[ "$DOMAIN" != *.* ]] && { echo "[ERROR] Dominio non valido"; exit 1; }
command -v curl >/dev/null || { echo "[ERROR] curl non trovato"; exit 1; }
TMPDIR="$(mktemp -d /tmp/checkShopwareStatus.XXXXXX)"

echo "============================================================"
echo " CHECK SHOPWARE STATUS - REMOTE v$VERSION"
echo "============================================================"
echo "Target : $BASE_URL"; echo "Date   : $(date)"; echo

echo "== 1. PUBLIC STATUS / WAF =="
HOME="$TMPDIR/home"; HEAD="$TMPDIR/home.h"; META="$(get "$BASE_URL/" "$HOME" "$HEAD")"; C="$(code "$META")"; FINAL_URL="$(eff "$META")"; REMOTE_IP="$(ip "$META")"
status "Homepage" "$C"; pl "[INFO] Final URL" "${FINAL_URL:-n/d}"; pl "[INFO] Remote IP" "${REMOTE_IP:-n/d}"; waf "$HEAD" "$HOME"; pl "[INFO] WAF/CDN" "${WAF:-non identificato}"; detect_family "$HOME"; pl "[RESULT] Shopware family" "${SHOPWARE_FAMILY:-non determinata}"

echo; echo "== 2. VERSION FINGERPRINT =="
V="$(extract_version "$HOME" || true)"; [ -n "$V" ] && set_version "$V" "homepage HTML"
for E in "/api/_info/config|Admin info config" "/api/_info/openapi3.json|Admin OpenAPI" "/store-api/_info/openapi3.json|Store API OpenAPI"; do
  P="${E%%|*}"; L="${E#*|}"; B="$TMPDIR/ep.$RANDOM"; H="$B.h"; M="$(get "$BASE_URL$P" "$B" "$H")"; EC="$(code "$M")"; EV="$(extract_version "$B" || true)"; status "$L ($P)" "$EC"
  if [ "$EC" = 200 ] && [ -n "$EV" ]; then pl "[LEAK] Shopware version" "$EV via $P"; VERSION_PUBLIC=1; set_version "$EV" "$P"; fi
  if [ "$P" = "/api/_info/config" ] && [ "$EC" = 200 ] && grep -Eq '"shopId"|"appUrl"|"versionRevision"|"bundles"' "$B" 2>/dev/null; then pl "[WARN] Admin info disclosure" "config amministrativa pubblicamente leggibile"; fi
done
pl "[RESULT] Shopware version" "${SHOPWARE_VERSION:-non determinata con affidabilita}"; [ -n "$VERSION_SOURCE" ] && pl "[INFO] Version source" "$VERSION_SOURCE"

echo; echo "== 3. EXPOSED SURFACE / SECURITY =="
for E in "/admin|Shopware 6 Administration" "/backend|Shopware 5 Backend" "/api/|Admin API root" "/api/_info/entity-schema.json|Entity schema" "/api/_info/stoplightio.html|API browser" "/recovery/install/|Recovery installer" "/recovery/update/|Recovery updater" "/install/|Installer"; do P="${E%%|*}"; L="${E#*|}"; B="$TMPDIR/r.$RANDOM"; H="$B.h"; M="$(get "$BASE_URL$P" "$B" "$H")"; status "$L ($P)" "$(code "$M")"; done

echo "-- Sensitive files --"
sensitive "/.env" 'APP_ENV=|APP_SECRET=|DATABASE_URL=|MAILER_DSN=' ".env"
sensitive "/.git/HEAD" '^ref:[[:space:]]+refs/heads/' ".git/HEAD"
sensitive "/composer.json" '"(name|require)"[[:space:]]*:' "composer.json"

echo "-- Public bundle/plugin fingerprints --"
grep -Eio '/bundles/[A-Za-z0-9_-]+/' "$HOME" 2>/dev/null | sed -E 's#^/bundles/##;s#/$##' | sort -fu | head -20 | while read -r x; do pl "[DETECTED] Public bundle" "$x"; done || true
grep -Eio '/engine/Shopware/Plugins/(Community|Local|Default)/[^/"[:space:]]+' "$HOME" 2>/dev/null | sed -E 's#^.*/Plugins/##' | sort -fu | head -20 | while read -r x; do pl "[DETECTED] Public plugin" "$x"; done || true

echo; echo "== 4. ASSET CDN CHECK =="
PAGE="${FINAL_URL:-$BASE_URL/}"; J="$(assets js "$HOME" "$PAGE")"; I="$(assets img "$HOME" "$PAGE")"; cdn_check js "$J"; cdn_check img "$I"

echo; echo "== 5. TTFB BENCHMARK =="
echo "-- NO-CACHE / CACHE-BUSTER --"; benchmark nocache "$PAGE"; echo "-- WARM CACHE --"; benchmark cache "$PAGE"

echo; echo "== 6. SUMMARY =="
echo "WAF/CDN          : ${WAF:-non identificato}"
echo "Shopware family  : ${SHOPWARE_FAMILY:-non determinata}"
echo "Shopware version : ${SHOPWARE_VERSION:-non determinata} ${VERSION_SOURCE:+($VERSION_SOURCE)}"
echo "Version exposure : $([ "$VERSION_PUBLIC" -eq 1 ] && echo RILEVATA || echo non rilevata)"
echo "Sensitive files  : $SENSITIVE esposizioni confermate"
echo "Remote IP        : ${REMOTE_IP:-n/d}"
echo "JS CDN           : $JS_CDN"
echo "Image CDN        : $IMG_CDN"
[ -n "$TTFB_MEDIAN" ] && echo "TTFB no-cache    : median ${TTFB_MEDIAN} ms | avg ${TTFB_AVG} | range ${TTFB_MIN}-${TTFB_MAX}"
[ -n "$CACHE_MEDIAN" ] && echo "TTFB cached      : median ${CACHE_MEDIAN} ms | avg ${CACHE_AVG} | range ${CACHE_MIN}-${CACHE_MAX}"
echo
echo "ACTIVE/REACH = route raggiungibile; non significa vulnerabile."
echo "CRITICAL sui file sensibili solo se il contenuto corrisponde realmente al file richiesto."
echo "Checker remoto: nessun login, payload o exploit; solo GET/HEAD e benchmark HTTP."
