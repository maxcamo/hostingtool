#!/usr/bin/env bash
clear
set -Eeuo pipefail
# Segnala anche gli errori imprevisti: con set -e una pipeline puo' fermare lo script.
trap 'rc=$?; echo "ERRORE: interruzione inattesa alla riga ${LINENO} (exit ${rc})." >&2' ERR

if (( EUID != 0 )); then
  echo 'ERRORE: eseguire come root (sudo bash script.sh).'
  exit 1
fi
if ! command -v apt-get >/dev/null || ! command -v dpkg-query >/dev/null; then
  echo 'ERRORE: script previsto per server Ubuntu/Debian con pacchetti APT.'
  exit 1
fi

printf '=== SERVER: %s ===\n' "$(hostname -f 2>/dev/null || hostname)"
echo "Versione script: 2026-10-22.3 (diagnostica APT)"
. /etc/os-release
printf 'Sistema: %s\n' "${PRETTY_NAME:-sconosciuto}"

mapfile -t PHP_PKGS < <(
  dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev}\n' 2>/dev/null |
  awk '$2=="ii" && ($1 ~ /^php[0-9]+\.[0-9]+($|-)/ || $1 ~ /^libapache2-mod-php[0-9]+\.[0-9]+(:[^ ]+)?$/) {print $1}' |
  sort -u
)
if (( ${#PHP_PKGS[@]} == 0 )); then
  echo 'Nessun pacchetto PHP versionato individuato: controllo manuale necessario.'
  exit 1
fi

mapfile -t PHP_VERS < <(
  printf '%s\n' "${PHP_PKGS[@]}" |
  sed -nE 's/^(php|libapache2-mod-php)([0-9]+\.[0-9]+)(-.*)?(:.*)?$/\2/p' |
  sort -Vu
)
if (( ${#PHP_VERS[@]} == 0 )); then
  echo 'Impossibile individuare le serie PHP: controllo manuale necessario.'
  exit 1
fi

printf '\n=== PACCHETTI PHP INSTALLATI ===\n'
printf '%s\n' "${PHP_PKGS[@]}"
printf '\n=== SERIE PHP RILEVATE ===\n'
printf '%s\n' "${PHP_VERS[@]}"

# Per PHP 8.1 e precedenti e per backport della distribuzione serve una verifica dedicata.
declare -A MIN=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
for v in "${PHP_VERS[@]}"; do
  if [[ -z "${MIN[$v]:-}" ]]; then
    echo "STOP: PHP $v necessita di una verifica specifica dei backport/compatibilita'."
    exit 1
  fi
done

# Memorizza i servizi attivi prima dell'aggiornamento.
FPM_ACTIVE=()
for v in "${PHP_VERS[@]}"; do
  if systemctl is-active --quiet "php${v}-fpm"; then
    FPM_ACTIVE+=("$v")
  fi
done
APACHE_MODPHP=0
if systemctl is-active --quiet apache2 && command -v apache2ctl >/dev/null 2>&1 &&
   apache2ctl -M 2>/dev/null | grep -Eq 'php(_[0-9]+)?_module'; then
  APACHE_MODPHP=1
fi
if (( ${#FPM_ACTIVE[@]} == 0 && APACHE_MODPHP == 0 )); then
  echo 'STOP: nessun servizio PHP-FPM attivo o Apache con mod_php rilevato.'
  echo 'Verificare manualmente il runtime web (CGI, LiteSpeed, container, ecc.).'
  exit 1
fi

printf '\n=== AGGIORNAMENTO INDICE APT ===\n'
apt-get update

printf '\n=== VERIFICA VERSIONI DISPONIBILI ===\n'
for v in "${PHP_VERS[@]}"; do
  echo "Controllo PHP $v: lettura apt-cache policy..."
  if ! policy_output=$(apt-cache policy "php${v}-common" 2>&1); then
    printf 'STOP: impossibile consultare APT per PHP %s. Output:\n%s\n' "$v" "$policy_output"
    exit 1
  fi
  if ! candidate=$(awk '$1 == "Candidate:" { print $2; found=1; exit } END { if (!found) exit 1 }' <<< "$policy_output"); then
    printf 'STOP: nessuna versione candidata per PHP %s. Output:\n%s\n' "$v" "$policy_output"
    exit 1
  fi
  echo "PHP $v: candidato $candidate (minimo upstream ${MIN[$v]})"
  if [[ -z "$candidate" || "$candidate" == '(none)' ]] ||
     ! dpkg --compare-versions "$candidate" ge "${MIN[$v]}"; then
    echo "STOP: candidato non verificabile come patchato per PHP $v."
    echo 'Potrebbe trattarsi di una patch backport Ubuntu/Debian: verificare gli avvisi del distributore.'
    exit 1
  fi
done

printf '\n=== SIMULAZIONE AGGIORNAMENTO ===\n'
simulation=$(apt-get -s --no-remove install --only-upgrade --no-install-recommends "${PHP_PKGS[@]}")
printf '%s\n' "$simulation"
if grep -Eq '^Remv ' <<< "$simulation"; then
  echo 'STOP: simulazione con rimozioni di pacchetti.'
  exit 1
fi
if ! grep -q '^Inst ' <<< "$simulation"; then
  echo 'Nessun aggiornamento APT previsto. Verifico le versioni installate.'
  for v in "${PHP_VERS[@]}"; do
    installed=$(dpkg-query -W -f='${Version}' "php${v}-common")
    if ! dpkg --compare-versions "$installed" ge "${MIN[$v]}"; then
      echo "STOP: PHP $v installato ($installed) ancora sotto il minimo ${MIN[$v]} (es. pacchetto bloccato)."
      exit 1
    fi
    echo "PHP $v: $installed OK"
  done
  exit 0
fi

printf '\nATTENZIONE: l\x27aggiornamento puo\x27 riavviare PHP-FPM/Apache e interrompere richieste in corso.\n'
read -r -p 'Per aggiornare digita AGGIORNA: ' CONFIRM
if [[ "$CONFIRM" != 'AGGIORNA' ]]; then
  echo 'Operazione annullata.'
  exit 0
fi

printf '\n=== BACKUP CONFIGURAZIONE ===\n'
if [[ -d /etc/php ]]; then
  backup="/root/php-config-$(hostname -s)-$(date +%Y%m%d_%H%M%S).tar.gz"
  tar -czf "$backup" -C /etc php
  echo "Backup creato: $backup"
fi

printf '\n=== INSTALLAZIONE PATCH PHP ===\n'
apt-get -y --no-remove install --only-upgrade --no-install-recommends "${PHP_PKGS[@]}"

printf '\n=== VERIFICA CONFIGURAZIONE FPM E RIAVVIO ===\n'
for v in "${FPM_ACTIVE[@]}"; do
  "php-fpm${v}" -t
  systemctl restart "php${v}-fpm"
  systemctl is-active --quiet "php${v}-fpm" || { echo "ERRORE: php${v}-fpm non attivo"; exit 1; }
  echo "php${v}-fpm: ATTIVO"
done
if (( APACHE_MODPHP )); then
  apache2ctl configtest
  systemctl restart apache2
  systemctl is-active --quiet apache2 || { echo 'ERRORE: Apache non attivo'; exit 1; }
  echo 'Apache con mod_php: ATTIVO'
fi

printf '\n=== VERIFICA VERSIONI INSTALLATE ===\n'
for v in "${PHP_VERS[@]}"; do
  installed=$(dpkg-query -W -f='${Version}' "php${v}-common")
  echo "PHP $v: $installed"
  dpkg --compare-versions "$installed" ge "${MIN[$v]}" || { echo "ERRORE: PHP $v sotto la versione minima"; exit 1; }
done
printf '\nPATCH PHP VERIFICATA SUI PACCHETTI. Controllare HTTP e log applicativi del sito.\n'
