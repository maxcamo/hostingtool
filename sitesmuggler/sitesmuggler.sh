#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

VERSION="4.0.0"
HARDENING_VERSION="v4"

NGINX_DIR="/etc/nginx"
SITE_DIR="$NGINX_DIR/sitesmuggler"
HARDEN_CONF="$SITE_DIR/hardening-magento2-${HARDENING_VERSION}.conf"
REPORT_DIR="/root/sitesmuggler-reports"
BACKUP_ROOT="/root/sitesmuggler-backups"

DOMAIN="${1:-}"
MEDIA_ACTION_ARG="${2:-}"
STAMP="$(date +%Y%m%d-%H%M%S)"

FAIL=0
VHOST=""
MAGE_ROOT=""
BACKEND=""
REPORT=""
BACKUP_DIR=""
TMPDIR=""
CANARY_DIR=""
HARDENING_EXISTED=0

declare -a STORES=()
declare -a SEARCH_DIRS=()

die(){ echo "[ERROR] $*" >&2; exit 1; }
ok(){ printf "[OK]   %s\n" "$*"; }
info(){ printf "[INFO] %s\n" "$*"; }
warn(){ printf "[WARN] %s\n" "$*"; }
pass(){ printf "[PASS] %-52s %s\n" "$1" "$2"; }
fail(){ printf "[FAIL] %-52s %s\n" "$1" "$2"; FAIL=1; }

cleanup(){
    [ -n "${CANARY_DIR:-}" ] && [ -d "$CANARY_DIR" ] && rm -rf "$CANARY_DIR"
    [ -n "${TMPDIR:-}" ] && [ -d "$TMPDIR" ] && rm -rf "$TMPDIR"
}
trap cleanup EXIT

[ "$(id -u)" -eq 0 ] || die "Eseguire come root"
command -v nginx >/dev/null 2>&1 || die "nginx non trovato"
command -v curl >/dev/null 2>&1 || die "curl non trovato"
command -v python3 >/dev/null 2>&1 || die "python3 non trovato"

if [ -z "$DOMAIN" ]; then
    clear
    echo "============================================================"
    echo " SITESMUGGLER"
    echo " Magento 2 Nginx Hardening"
    echo " Version $VERSION"
    echo "============================================================"
    echo
    read -r -p "Dominio Magento: " DOMAIN
fi

DOMAIN="${DOMAIN#https://}"
DOMAIN="${DOMAIN#http://}"
DOMAIN="${DOMAIN%%/*}"
DOMAIN="${DOMAIN%%:*}"
DOMAIN="${DOMAIN%.}"
DOMAIN="$(printf '%s' "$DOMAIN" | tr '[:upper:]' '[:lower:]')"

[ -n "$DOMAIN" ] || die "Dominio non specificato"
if ! [[ "$DOMAIN" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || [[ "$DOMAIN" != *.* ]]; then
    die "Dominio non valido: $DOMAIN"
fi

mkdir -p "$REPORT_DIR" "$BACKUP_ROOT"
REPORT="$REPORT_DIR/${DOMAIN}-${STAMP}.txt"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
exec > >(tee "$REPORT") 2>&1

echo "============================================================"
echo " SITESMUGGLER - UNIVERSAL MAGENTO2 NGINX HARDENING"
echo "============================================================"
echo
echo "Version    : $VERSION"
echo "Date       : $(date)"
echo "Hostname   : $(hostname -f 2>/dev/null || hostname)"
echo "Domain     : $DOMAIN"
echo "Report     : $REPORT"
echo

echo "============================================================"
echo " 1. PRECHECK NGINX"
echo "============================================================"
if ! nginx -t; then
    die "nginx -t fallisce PRIMA dell'hardening. Nessuna modifica eseguita."
fi
ok "Configurazione Nginx iniziale valida"

for DIR in "$NGINX_DIR/sites-enabled" "$NGINX_DIR/conf.d"; do
    [ -d "$DIR" ] && SEARCH_DIRS+=("$DIR")
done
[ "${#SEARCH_DIRS[@]}" -gt 0 ] || die "Nessuna directory Nginx valida trovata"

echo
echo "============================================================"
echo " 2. DISCOVERY VHOST MAGENTO"
echo "============================================================"

mapfile -t CANDIDATES < <(
    grep -RIlF --include='*.conf' "$DOMAIN" "${SEARCH_DIRS[@]}" 2>/dev/null |
    while read -r FILE; do
        if grep -qE 'fastcgi_pass[[:space:]]' "$FILE" &&
           grep -qE 'MAGE_ROOT|root[[:space:]].*/pub|root[[:space:]]+\$MAGE_ROOT/pub' "$FILE"; then
            echo "$FILE"
        fi
    done | sort -u
)

if [ "${#CANDIDATES[@]}" -eq 0 ]; then
    echo
    echo "File Nginx che contengono il dominio:"
    grep -RIlF --include='*.conf' "$DOMAIN" "${SEARCH_DIRS[@]}" 2>/dev/null || true
    die "Nessun vhost Magento/FastCGI trovato automaticamente"
fi

if [ "${#CANDIDATES[@]}" -gt 1 ]; then
    echo
    echo "Vhost candidati:"
    printf ' - %s\n' "${CANDIDATES[@]}"
    die "Più vhost Magento candidati. Nessuna modifica automatica eseguita."
fi

VHOST="${CANDIDATES[0]}"
ok "Backend vhost: $VHOST"

DISCOVERY="$(python3 - "$VHOST" "$DOMAIN" <<'PY'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
domain = sys.argv[2]
text = path.read_text(errors='replace')

def matching_brace(data, brace_start):
    depth=0; quote=None; comment=False; escaped=False
    for i in range(brace_start, len(data)):
        c=data[i]
        if comment:
            if c=='\n': comment=False
            continue
        if quote:
            if escaped:
                escaped=False; continue
            if c=='\\':
                escaped=True; continue
            if c==quote: quote=None
            continue
        if c=='#': comment=True; continue
        if c in ("'", '"'): quote=c; continue
        if c=='{': depth+=1
        elif c=='}':
            depth-=1
            if depth==0: return i+1
    return None

blocks=[]
for m in re.finditer(r'(?m)^\s*server\s*\{', text):
    brace=text.find('{', m.start())
    end=matching_brace(text, brace)
    if end is None: continue
    block=text[m.start():end]
    if 'fastcgi_pass' not in block: continue
    if not (re.search(r'\bMAGE_ROOT\b', block) or re.search(r'(?m)^\s*root\s+[^;]*/pub\s*;', block)):
        continue
    names=[]
    for sm in re.finditer(r'(?is)\bserver_name\s+([^;]+);', block):
        names.extend(sm.group(1).split())
    blocks.append((block, names))

target=None
for item in blocks:
    if domain in item[1]:
        target=item; break
if target is None and len(blocks)==1:
    target=blocks[0]
if target is None:
    print('DISCOVERY_ERROR=server_block')
    raise SystemExit(0)

block,names=target
mage_root=''
m=re.search(r'(?m)^\s*set\s+\$MAGE_ROOT\s+([^;]+);', block)
if m: mage_root=m.group(1).strip()
if not mage_root:
    m=re.search(r'(?m)^\s*root\s+([^;]+);', block)
    if m and m.group(1).strip().endswith('/pub'):
        mage_root=m.group(1).strip()[:-4]

backend=''
for m in re.finditer(r'(?m)^\s*listen\s+([^; ]+)', block):
    value=m.group(1).strip()
    if value.startswith('127.0.0.1:') or value.startswith('[::1]:'):
        backend=value; break
    if value.isdigit():
        backend=f'127.0.0.1:{value}'; break

print(f'MAGE_ROOT={mage_root}')
print(f'BACKEND={backend}')
for name in names:
    if '.' in name and '*' not in name and '$' not in name and name not in ('localhost','127.0.0.1'):
        print(f'STORE={name}')
PY
)"

if echo "$DISCOVERY" | grep -q '^DISCOVERY_ERROR='; then
    echo "$DISCOVERY"
    die "Impossibile identificare il server{} Magento in modo sicuro"
fi

while IFS='=' read -r KEY VALUE; do
    case "$KEY" in
        MAGE_ROOT) MAGE_ROOT="$VALUE" ;;
        BACKEND) BACKEND="$VALUE" ;;
        STORE) STORES+=("$VALUE") ;;
    esac
done <<< "$DISCOVERY"

[ -n "$MAGE_ROOT" ] || die "Impossibile determinare MAGE_ROOT"
[ -d "$MAGE_ROOT/pub" ] || die "Directory Magento non trovata: $MAGE_ROOT/pub"

if [ -z "$BACKEND" ]; then
    BACKEND="127.0.0.1:8080"
    warn "Backend non rilevato dal listen. Uso fallback: $BACKEND"
fi
[ "${#STORES[@]}" -gt 0 ] || STORES=("$DOMAIN")

ok "MAGE_ROOT: $MAGE_ROOT"
ok "Backend: $BACKEND"
echo
echo "Store/domain rilevati:"
for STORE in "${STORES[@]}"; do echo " - $STORE"; done

echo
echo "============================================================"
echo " 3. BACKUP"
echo "============================================================"
mkdir -p "$BACKUP_DIR"
cp -a "$VHOST" "$BACKUP_DIR/"
if [ -f "$HARDEN_CONF" ]; then
    HARDENING_EXISTED=1
    cp -a "$HARDEN_CONF" "$BACKUP_DIR/"
fi
ok "Backup vhost: $BACKUP_DIR/$(basename "$VHOST")"

rollback(){
    echo
    echo "============================================================"
    echo " ROLLBACK AUTOMATICO"
    echo "============================================================"
    echo
    [ -f "$BACKUP_DIR/$(basename "$VHOST")" ] && cp -a "$BACKUP_DIR/$(basename "$VHOST")" "$VHOST"
    if [ "$HARDENING_EXISTED" -eq 1 ]; then
        [ -f "$BACKUP_DIR/$(basename "$HARDEN_CONF")" ] && cp -a "$BACKUP_DIR/$(basename "$HARDEN_CONF")" "$HARDEN_CONF"
    else
        rm -f "$HARDEN_CONF"
    fi
    if nginx -t; then
        systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
        echo "[ROLLBACK] Configurazione precedente ripristinata"
    else
        echo "[CRITICAL] Configurazione ripristinata non valida: controllare manualmente"
    fi
}

echo
echo "============================================================"
echo " 4. HARDENING"
echo "============================================================"
mkdir -p "$SITE_DIR"
cat > "$HARDEN_CONF" <<'EOF'
# ============================================================
# SITESMUGGLER - Magento 2 Nginx Hardening - V4
# Context: server {}
# ============================================================

if ($request_method ~* "^(TRACE|TRACK)$") { return 405; }

if ($uri ~* "(^|/)\.(git|svn|hg)(/|$)") { return 404; }
if ($uri ~* "(^|/)\.env([./]|$)") { return 404; }
if ($uri ~* "(^|/)\.(user\.ini|htaccess|htpasswd)(/|$)") { return 404; }

if ($uri ~* "^/(composer\.(json|lock)|auth\.json|package(-lock)?\.json|grunt-config\.json|gulpfile\.js|phpunit\.xml(\.dist)?)$") { return 404; }
if ($uri ~* "^/(app/etc|vendor|var|generated|dev/tests|phpserver)(/|$)") { return 404; }
if ($uri ~* "\.(php|phtml|phar|ini|conf|env)\.(bak|old|orig|save|swp|tmp|txt)$") { return 404; }

# Con root $MAGE_ROOT/pub gli URI pubblici sono /media/ e /static/.
# Blocca qualsiasi codice eseguibile caricato nelle directory pubbliche writable/statiche.
if ($uri ~* "^/(media|static)/.*\.(php[0-9]*|phtml|phar|phps|cgi|pl|py|sh|bash|zsh)(/|$)") { return 404; }
EOF
ok "Hardening scritto: $HARDEN_CONF"

PATCH_OUTPUT="$(python3 - "$VHOST" "$DOMAIN" "$HARDEN_CONF" <<'PY'
from pathlib import Path
import re, sys
vhost=Path(sys.argv[1]); domain=sys.argv[2]; include_path=sys.argv[3]
text=vhost.read_text(errors='replace')

def matching_brace(data, brace_start):
    depth=0; quote=None; comment=False; escaped=False
    for i in range(brace_start, len(data)):
        c=data[i]
        if comment:
            if c=='\n': comment=False
            continue
        if quote:
            if escaped: escaped=False; continue
            if c=='\\': escaped=True; continue
            if c==quote: quote=None
            continue
        if c=='#': comment=True; continue
        if c in ("'", '"'): quote=c; continue
        if c=='{': depth+=1
        elif c=='}':
            depth-=1
            if depth==0: return i+1
    return None

blocks=[]
for m in re.finditer(r'(?m)^\s*server\s*\{', text):
    brace=text.find('{', m.start()); end=matching_brace(text, brace)
    if end is None: continue
    block=text[m.start():end]
    if 'fastcgi_pass' not in block: continue
    if not (re.search(r'\bMAGE_ROOT\b', block) or re.search(r'(?m)^\s*root\s+[^;]*/pub\s*;', block)):
        continue
    names=[]
    for sm in re.finditer(r'(?is)\bserver_name\s+([^;]+);', block):
        names.extend(sm.group(1).split())
    blocks.append((m.start(), end, block, names))

target=None
for item in blocks:
    if domain in item[3]: target=item; break
if target is None and len(blocks)==1: target=blocks[0]
if target is None: raise SystemExit('Impossibile determinare server{} Magento')
start,end,block,names=target

include_added=0; include_upgraded=0; custom_options_fixed=0; php_handler_restored=0

# Rileva eventuali include SiteSmuggler precedenti PRIMA della migrazione.
# Le versioni <= v3 potevano aver ancorato automaticamente l'handler PHP Magento.
old_include_pattern=re.compile(
    r'(?m)^[ \t]*include[ \t]+/etc/nginx/sitesmuggler/hardening-magento2-v([0-9]+)\.conf[ \t]*;[ \t]*$'
)
legacy_versions=[int(x) for x in old_include_pattern.findall(block)]
legacy_needs_php_restore=any(v <= 3 for v in legacy_versions)

new_line=f'    include {include_path};'
replaced=old_include_pattern.sub(new_line, block)
if replaced != block: include_upgraded=1
block=replaced

if include_path not in block:
    anchors=[
        re.compile(r'(?m)^([ \t]*autoindex\s+off\s*;[^\n]*\n)'),
        re.compile(r'(?m)^([ \t]*root\s+\$MAGE_ROOT/pub\s*;[^\n]*\n)'),
        re.compile(r'(?m)^([ \t]*root\s+[^;]+/pub\s*;[^\n]*\n)'),
    ]
    inserted=False
    for anchor in anchors:
        m=anchor.search(block)
        if not m: continue
        pos=m.end(); block=block[:pos]+'\n'+new_line+'\n'+block[pos:]
        include_added=1; inserted=True; break
    if not inserted: raise SystemExit('Nessun punto sicuro per include SiteSmuggler')

# Con root $MAGE_ROOT/pub l'URI corretto è /media/custom_options/.
block,custom_options_fixed=re.subn(
    r'(?m)^([ \t]*location(?:[ \t]+\^~)?[ \t]+)/pub/media/custom_options/([ \t]*\{)',
    r'\1/media/custom_options/\2', block
)

# V4: NON ancora più automaticamente l'handler PHP Magento.
# Magento custom/multiregione può usare /eu/index.php, /it/index.php, ecc.
# Se rileviamo un'installazione proveniente da SiteSmuggler <= v3,
# ripristiniamo SOLO l'ancoraggio che le versioni precedenti avevano introdotto.
if legacy_needs_php_restore:
    anchored_pattern=re.compile(
        r'(?m)^([ \t]*)location\s+~\s+\^/\(([^\)\n]*\bindex\b[^\)\n]*)\)(?:\\\.|\.)php\$\s*\{'
    )
    def restore_handler(m):
        return f'{m.group(1)}location ~ ({m.group(2)})\\.php$ {{'
    block,php_handler_restored=anchored_pattern.subn(restore_handler, block, count=1)

generic_php_deny=bool(re.search(r'location\s+~\*?\s+[^{}\n]*\\?\.php\$\s*\{[^{}]*return\s+404', block, re.I|re.S))
vhost.write_text(text[:start]+block+text[end:])
print(f'include_added={include_added}')
print(f'include_upgraded={include_upgraded}')
print(f'custom_options_fixed={custom_options_fixed}')
print(f'php_handler_restored={php_handler_restored}')
print(f'generic_php_deny={int(generic_php_deny)}')
PY
)"

echo "$PATCH_OUTPUT"
ok "Patch vhost completata"
if echo "$PATCH_OUTPUT" | grep -q 'generic_php_deny=0'; then
    warn "Generic PHP deny non rilevato automaticamente; il canary reale farà comunque il test"
fi

echo
echo "============================================================"
echo " 5. NGINX TEST"
echo "============================================================"
if ! nginx -t; then
    rollback
    die "nginx -t fallito dopo hardening"
fi
ok "nginx -t PASSED"

if systemctl reload nginx 2>/dev/null; then
    ok "Nginx reload"
elif nginx -s reload; then
    ok "Nginx reload tramite nginx -s reload"
else
    rollback
    die "Reload Nginx fallito"
fi
sleep 1

echo
echo "============================================================"
echo " 6. EXISTING EXECUTABLE FILE CHECK"
echo "============================================================"

MEDIA_ACTION_RESULT="none"
MEDIA_EXEC_COUNT=0
MEDIA_ROOT="$MAGE_ROOT/pub/media"

scan_media_executables(){
    EXISTING_EXEC=()
    if [ -d "$MEDIA_ROOT" ]; then
        mapfile -d '' -t EXISTING_EXEC < <(
            find "$MEDIA_ROOT" -type f \( \
                -iname '*.php' -o -iname '*.php[0-9]*' -o -iname '*.phtml' -o \
                -iname '*.phar'  -o -iname '*.phps' \
            \) -print0 2>/dev/null
        )
    fi
}

scan_media_executables
MEDIA_EXEC_COUNT="${#EXISTING_EXEC[@]}"

if [ "$MEDIA_EXEC_COUNT" -gt 0 ]; then
    echo
    warn "Trovati $MEDIA_EXEC_COUNT file eseguibili già presenti in pub/media:"

    DISPLAY_LIMIT=200
    DISPLAYED=0
    for FILE in "${EXISTING_EXEC[@]}"; do
        echo "       $FILE"
        DISPLAYED=$((DISPLAYED + 1))
        if [ "$DISPLAYED" -ge "$DISPLAY_LIMIT" ]; then
            break
        fi
    done

    if [ "$MEDIA_EXEC_COUNT" -gt "$DISPLAY_LIMIT" ]; then
        echo "       ... altri $((MEDIA_EXEC_COUNT - DISPLAY_LIMIT)) file non mostrati"
    fi

    echo
    echo "Azione sui file trovati:"
    echo "  [Q] Quarantena fuori dal webroot (CONSIGLIATO)"
    echo "  [D] Cancella definitivamente"
    echo "  [N] Nessuna azione, lascia i file dove sono"
    echo

    MEDIA_ACTION="${SITESMUGGLER_MEDIA_ACTION:-${MEDIA_ACTION_ARG:-}}"

    if [ -z "$MEDIA_ACTION" ]; then
        if [ -t 0 ]; then
            read -r -p "Scelta [Q]: " MEDIA_ACTION
            MEDIA_ACTION="${MEDIA_ACTION:-Q}"
        else
            MEDIA_ACTION="N"
            warn "Sessione non interattiva: nessuna rimozione automatica"
        fi
    fi

    MEDIA_ACTION="$(printf '%s' "$MEDIA_ACTION" | tr '[:upper:]' '[:lower:]')"

    case "$MEDIA_ACTION" in
        q|quarantine|quarantena)
            QUARANTINE_DIR="/root/sitesmuggler-quarantine/${DOMAIN}-${STAMP}"
            MANIFEST="$QUARANTINE_DIR/manifest.tsv"
            mkdir -p "$QUARANTINE_DIR"
            printf 'sha256\toriginal_path\tquarantine_path\n' > "$MANIFEST"

            MOVED=0
            for FILE in "${EXISTING_EXEC[@]}"; do
                [ -f "$FILE" ] || continue
                REL="${FILE#"$MEDIA_ROOT"/}"
                DEST="$QUARANTINE_DIR/$REL"
                mkdir -p "$(dirname "$DEST")"
                HASH="$(sha256sum -- "$FILE" | awk '{print $1}')"
                printf '%s\t%s\t%s\n' "$HASH" "$FILE" "$DEST" >> "$MANIFEST"
                mv -- "$FILE" "$DEST"
                MOVED=$((MOVED + 1))
            done

            chmod -R go-rwx "$QUARANTINE_DIR" 2>/dev/null || true
            MEDIA_ACTION_RESULT="quarantined:$MOVED"
            ok "Quarantena completata: $MOVED file"
            ok "Directory: $QUARANTINE_DIR"
            ;;

        d|delete|cancella|cancellazione)
            CONFIRM="${SITESMUGGLER_MEDIA_DELETE_CONFIRM:-}"

            if [ "$CONFIRM" != "DELETE" ]; then
                if [ -t 0 ]; then
                    echo
                    warn "CANCELLAZIONE DEFINITIVA di $MEDIA_EXEC_COUNT file"
                    read -r -p "Scrivi DELETE per confermare: " CONFIRM
                fi
            fi

            if [ "$CONFIRM" != "DELETE" ]; then
                warn "Cancellazione annullata. Nessun file rimosso."
                MEDIA_ACTION_RESULT="none"
            else
                DELETE_MANIFEST_DIR="/root/sitesmuggler-deletion-manifests"
                DELETE_MANIFEST="$DELETE_MANIFEST_DIR/${DOMAIN}-${STAMP}.tsv"
                mkdir -p "$DELETE_MANIFEST_DIR"
                printf 'sha256\tdeleted_path\n' > "$DELETE_MANIFEST"

                DELETED=0
                for FILE in "${EXISTING_EXEC[@]}"; do
                    [ -f "$FILE" ] || continue
                    HASH="$(sha256sum -- "$FILE" | awk '{print $1}')"
                    printf '%s\t%s\n' "$HASH" "$FILE" >> "$DELETE_MANIFEST"
                    rm -f -- "$FILE"
                    DELETED=$((DELETED + 1))
                done

                MEDIA_ACTION_RESULT="deleted:$DELETED"
                ok "Cancellazione completata: $DELETED file"
                ok "Manifest SHA256: $DELETE_MANIFEST"
            fi
            ;;

        n|none|no|nessuna)
            MEDIA_ACTION_RESULT="none"
            warn "File lasciati sul filesystem. L'hardening ne blocca l'accesso HTTP."
            ;;

        *)
            MEDIA_ACTION_RESULT="none"
            warn "Scelta non riconosciuta: nessuna azione sui file"
            ;;
    esac

    # Verifica dopo eventuale quarantena/cancellazione.
    scan_media_executables
    REMAINING_EXEC_COUNT="${#EXISTING_EXEC[@]}"

    if [ "$REMAINING_EXEC_COUNT" -eq 0 ]; then
        pass "Executable files rimasti in pub/media" "NESSUNO"
    else
        warn "Restano $REMAINING_EXEC_COUNT file eseguibili in pub/media"
    fi
else
    pass "Executable files già presenti in pub/media" "NESSUNO"
fi

TMPDIR="$(mktemp -d /tmp/sitesmuggler.XXXXXX)"

request_backend(){
    local HOST="$1" URI="$2" OUTPUT="$3" CODE RC
    set +e
    CODE="$(curl -sS --max-time 15 -H "Host: $HOST" -o "$OUTPUT" -w "%{http_code}" "http://${BACKEND}${URI}")"
    RC=$?
    set -e
    [ "$RC" -eq 0 ] && printf "%s" "$CODE" || printf "000"
}

request_graphql(){
    local HOST="$1" OUTPUT="$2" CODE RC
    set +e
    CODE="$(curl -sS --max-time 15 -X POST -H "Host: $HOST" -H "Content-Type: application/json" \
        --data '{"query":"{__typename}"}' -o "$OUTPUT" -w "%{http_code}" "http://${BACKEND}/graphql")"
    RC=$?
    set -e
    [ "$RC" -eq 0 ] && printf "%s" "$CODE" || printf "000"
}

request_public(){
    local HOST="$1" URI="$2" OUTPUT="$3" CODE RC
    set +e
    CODE="$(curl -ksSL --max-redirs 5 --max-time 20 -o "$OUTPUT" -w "%{http_code}" "https://${HOST}${URI}")"
    RC=$?
    set -e
    [ "$RC" -eq 0 ] && printf "%s" "$CODE" || printf "000"
}

echo
echo "============================================================"
echo " 7. SECURITY CHECK"
echo "============================================================"

for STORE in "${STORES[@]}"; do
    echo
    echo "------------------------------------------------------------"
    echo " STORE: $STORE"
    echo "------------------------------------------------------------"

    BODY="$TMPDIR/frontend"
    CODE="$(request_backend "$STORE" "/" "$BODY")"
    case "$CODE" in 2??|3??|401|403) pass "Frontend /" "HTTP $CODE" ;; 000|5??) fail "Frontend /" "HTTP $CODE" ;; *) warn "Frontend /" "HTTP $CODE" ;; esac

    BODY="$TMPDIR/customer"
    CODE="$(request_backend "$STORE" "/customer/account/" "$BODY")"
    case "$CODE" in 2??|3??|401|403) pass "/customer/account/" "HTTP $CODE" ;; 000|5??) fail "/customer/account/" "HTTP $CODE" ;; *) warn "/customer/account/" "HTTP $CODE" ;; esac

    BODY="$TMPDIR/rest"
    CODE="$(request_backend "$STORE" "/rest/V1/store/storeConfigs" "$BODY")"
    case "$CODE" in 2??|400|401|403) pass "Magento REST" "HTTP $CODE" ;; *) warn "Magento REST" "HTTP $CODE" ;; esac

    BODY="$TMPDIR/graphql"
    CODE="$(request_graphql "$STORE" "$BODY")"
    case "$CODE" in 2??|400|401|403|405) pass "Magento GraphQL" "HTTP $CODE" ;; *) warn "Magento GraphQL" "HTTP $CODE" ;; esac

    for URI in "/.git/config" "/.svn/entries" "/.env" "/.env.local" "/composer.json" "/composer.lock" "/auth.json" "/app/etc/env.php" "/vendor/autoload.php" "/var/log/system.log"; do
        SAFE_NAME="$(printf '%s' "${STORE}_${URI}" | tr '/.' '__')"
        BODY="$TMPDIR/$SAFE_NAME"
        CODE="$(request_backend "$STORE" "$URI" "$BODY")"
        case "$CODE" in 403|404) pass "$URI" "HTTP $CODE" ;; *) fail "$URI" "HTTP $CODE - ATTESO 403/404" ;; esac
    done
done

echo
echo "============================================================"
echo " 8. CODE EXECUTION CANARY - PUB/MEDIA"
echo "============================================================"
CANARY_NAME="sitesmuggler_canary_$$"
CANARY_DIR="$MAGE_ROOT/pub/media/$CANARY_NAME"
mkdir -p "$CANARY_DIR"
cat > "$CANARY_DIR/index.php" <<'PHP'
<?php header('Content-Type: text/plain'); echo 'SITESMUGGLER_INDEX_PHP_EXECUTED';
PHP
cat > "$CANARY_DIR/shell.php" <<'PHP'
<?php header('Content-Type: text/plain'); echo 'SITESMUGGLER_SHELL_PHP_EXECUTED';
PHP
cat > "$CANARY_DIR/probe.phtml" <<'PHTML'
SITESMUGGLER_PHTML_EXPOSED
PHTML
chmod 755 "$CANARY_DIR"
chmod 644 "$CANARY_DIR/index.php" "$CANARY_DIR/shell.php" "$CANARY_DIR/probe.phtml"

BODY="$TMPDIR/canary-index"
CODE="$(request_backend "$DOMAIN" "/media/$CANARY_NAME/index.php" "$BODY")"
if grep -q 'SITESMUGGLER_INDEX_PHP_EXECUTED' "$BODY" 2>/dev/null; then fail "pub/media/index.php" "ESEGUITO - CRITICO"; else case "$CODE" in 403|404) pass "pub/media/index.php" "BLOCCATO HTTP $CODE" ;; *) fail "pub/media/index.php" "HTTP $CODE - risposta inattesa" ;; esac; fi

BODY="$TMPDIR/canary-shell"
CODE="$(request_backend "$DOMAIN" "/media/$CANARY_NAME/shell.php" "$BODY")"
if grep -q 'SITESMUGGLER_SHELL_PHP_EXECUTED' "$BODY" 2>/dev/null; then fail "pub/media/shell.php" "ESEGUITO - CRITICO"; else case "$CODE" in 403|404) pass "pub/media/shell.php" "BLOCCATO HTTP $CODE" ;; *) fail "pub/media/shell.php" "HTTP $CODE - risposta inattesa" ;; esac; fi

BODY="$TMPDIR/canary-phtml"
CODE="$(request_backend "$DOMAIN" "/media/$CANARY_NAME/probe.phtml" "$BODY")"
if grep -q 'SITESMUGGLER_PHTML_EXPOSED' "$BODY" 2>/dev/null; then fail "pub/media/probe.phtml" "CONTENUTO ESPOSTO - CRITICO"; else case "$CODE" in 403|404) pass "pub/media/probe.phtml" "BLOCCATO HTTP $CODE" ;; *) fail "pub/media/probe.phtml" "HTTP $CODE - risposta inattesa" ;; esac; fi
rm -rf "$CANARY_DIR"; CANARY_DIR=""

echo
echo "============================================================"
echo " 9. CUSTOM OPTIONS CHECK"
echo "============================================================"
if grep -qE 'location([[:space:]]+\^~)?[[:space:]]+/pub/media/custom_options/' "$VHOST"; then
    fail "custom_options location" "Ancora presente /pub/media/custom_options/"
else
    pass "custom_options path" "Nessuna location errata /pub/media/custom_options/"
fi
if grep -qE 'location([[:space:]]+\^~)?[[:space:]]+/media/custom_options/' "$VHOST"; then
    pass "custom_options location" "/media/custom_options/"
fi

echo
echo "============================================================"
echo " 10. PUBLIC EDGE CHECK"
echo "============================================================"
for STORE in "${STORES[@]}"; do
    BODY="$TMPDIR/public-$(printf '%s' "$STORE" | tr '.' '_')"
    CODE="$(request_public "$STORE" "/" "$BODY")"
    case "$CODE" in
        2??|3??|401|403) pass "HTTPS $STORE (redirect final)" "HTTP $CODE" ;;
        000) warn "HTTPS $STORE" "HTTP 000 - DNS/connessione non disponibile" ;;
        4??|5??) fail "HTTPS $STORE (redirect final)" "HTTP $CODE" ;;
        *) warn "HTTPS $STORE" "HTTP $CODE" ;;
    esac
done

echo
echo "============================================================"
if [ "$FAIL" -eq 0 ]; then
    echo " SITESMUGGLER HARDENING: PASSED"
    echo "============================================================"
    echo
    echo "Version     : $VERSION"
    echo "Domain      : $DOMAIN"
    echo "Vhost       : $VHOST"
    echo "Magento     : $MAGE_ROOT"
    echo "Backend     : $BACKEND"
    echo "Hardening   : $HARDEN_CONF"
echo "Media action: $MEDIA_ACTION_RESULT"
    echo "Backup      : $BACKUP_DIR/$(basename "$VHOST")"
    echo "Report      : $REPORT"
    echo
    echo "Store verificati:"
    for STORE in "${STORES[@]}"; do echo " - $STORE"; done
    echo
    exit 0
fi

echo " SITESMUGGLER HARDENING: FAILED"
echo "============================================================"
rollback
echo
echo "[ERROR] Uno o più controlli critici sono falliti."
echo "[ERROR] Configurazione precedente ripristinata."
echo "Report: $REPORT"
exit 1

