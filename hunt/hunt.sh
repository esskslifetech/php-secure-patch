#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: hunt/hunt.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Post-patch compromise hunting for PHP2Shell (CVE-2026-109618/109619),
# CVE-2024-4577 and general webshell indicators — the exact indicators named
# by CISA, NCSC-NL and watchTowr:
#
#   1. unusually large multipart/form-data POSTs (OOM-trigger steering)
#   2. session.upload_progress probes (PHP_SESSION_UPLOAD_PROGRESS in requests)
#   3. php-cgi argument-injection probes (%ad / "-d " / "-s " in query strings)
#   4. "Allowed memory size exhausted" bursts in PHP error logs
#   5. recently created/modified .php files in web roots (webshells)
#
# Usage:
#   ./hunt/hunt.sh                          # auto-discover logs + report
#   ./hunt/hunt.sh --log access.log --log more.log
#   ./hunt/hunt.sh --error-log /var/log/php.log --webroot /var/www --days 14
#   ./hunt/hunt.sh --fail-on-findings       # exit 1 when anything is found
# ==============================================================================
set -u
PSP_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
. "$PSP_ROOT/lib/common.sh"

LOGS=(); ERRLOGS=(); WEBROOTS=(); DAYS=14; MAX_BYTES=1048576; FAIL_ON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --log)        shift; LOGS[${#LOGS[@]}]="${1:-}" ;;
    --error-log)  shift; ERRLOGS[${#ERRLOGS[@]}]="${1:-}" ;;
    --webroot)    shift; WEBROOTS[${#WEBROOTS[@]}]="${1:-}" ;;
    --days)       shift; DAYS="${1:-14}" ;;
    --max-bytes)  shift; MAX_BYTES="${1:-1048576}" ;;
    --fail-on-findings) FAIL_ON=1 ;;
    --help|-h)    awk 'NR>1 { if (/^# =+$/ && ++r == 2) exit; sub(/^# ?/, ""); print }' "$0"
                  exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

FINDINGS=0
finding() { # finding <severity> <message>
  FINDINGS=$((FINDINGS+1))
  printf '%s[%s]%s %s\n' "$C_RED" "$1" "$C_RESET" "$2"
}

# ---- discover logs when not given -------------------------------------------
if [ "${#LOGS[@]}" -eq 0 ] && [ "${#ERRLOGS[@]}" -eq 0 ]; then
  for f in /var/log/nginx/*access*.log /var/log/apache2/*access*.log \
           /var/log/apache2/*access_log /var/log/httpd/*access_log \
           /var/log/httpd/*access*.log /var/log/lighttpd/*access*.log \
           /usr/local/lsws/logs/*access*.log; do
    [ -f "$f" ] && [ -r "$f" ] && LOGS[${#LOGS[@]}]="$f"
  done
  for f in /var/log/php*-fpm.log /var/log/php_errors.log /var/log/php.log \
           /var/log/apache2/*error*.log /var/log/nginx/*error*.log \
           /var/log/httpd/*error_log; do
    [ -f "$f" ] && [ -r "$f" ] && ERRLOGS[${#ERRLOGS[@]}]="$f"
  done
  if [ "${#LOGS[@]}" -eq 0 ] && [ "${#ERRLOGS[@]}" -eq 0 ]; then
    warn "no server logs found/readable — pass --log / --error-log explicitly"
  fi
fi

step "PHP2Shell / php-cgi compromise hunt"
info "window: last $DAYS day(s), large-request threshold: $MAX_BYTES bytes"

# ---- 1-3: access-log indicators ---------------------------------------------
for log in ${LOGS[@]+"${LOGS[@]}"}; do
  [ -f "$log" ] || { warn "skipping $log (not found)"; continue; }
  info "scanning access log: $log"

  # 1. oversized POSTs (bytes field of combined log format > threshold)
  hits="$(awk -v max="$MAX_BYTES" -v days="$DAYS" '
    {
      # combined log: ... "METHOD PATH HTTP/x" STATUS BYTES ...
      if (match($0, /"[A-Z]+ [^"]*"/)) {
        req = substr($0, RSTART+1, RLENGTH-2)
        method = substr(req, 1, index(req, " ")-1)
      } else next
      if (method != "POST") next
      # find status+bytes after the closing quote
      rest = substr($0, RSTART+RLENGTH)
      if (match(rest, /[0-9]+ [0-9-]+/)) {
        size = substr(rest, RSTART, RLENGTH)
        sub(/^[0-9]+ /, "", size)
        if (size ~ /^[0-9]+$/ && size+0 > max) print
      }
    }' "$log" | head -20)"
  [ -n "$hits" ] && finding "HIGH" "large POST bodies (>$MAX_BYTES B) in $log — possible OOM-trigger attempts:" && printf '%s\n' "$hits" | sed 's/^/        /'

  # 2. session.upload_progress probes (PHP2Shell producer probing)
  hits="$(grep -iEn 'PHP_SESSION_UPLOAD_PROGRESS|upload_progress' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "HIGH" "session.upload_progress probes in $log (PHP2Shell CVE-2026-109619):" && printf '%s\n' "$hits" | sed 's/^/        /'

  # 3. php-cgi argument-injection probes (CVE-2024-4577 / CVE-2012-1823)
  hits="$(grep -iEn '%ad|%AD.*(-d%20|-s%20|-d\+|-s\+)|\?-[ds] |allow_url_include|auto_prepend_file' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "CRITICAL" "php-cgi argument-injection probes in $log (CVE-2024-4577 family):" && printf '%s\n' "$hits" | sed 's/^/        /'
done

# ---- 4. OOM bursts in error logs --------------------------------------------
for log in ${ERRLOGS[@]+"${ERRLOGS[@]}"}; do
  [ -f "$log" ] || { warn "skipping $log (not found)"; continue; }
  info "scanning error log: $log"
  n="$(grep -c 'Allowed memory size exhausted\|Out of memory\|memory_limit' "$log" 2>/dev/null || echo 0)"
  if [ "$n" -gt 5 ]; then
    finding "HIGH" "$n memory-exhaustion events in $log — burst may mark CVE-2026-109618 OOM-probing:"
    grep -En 'Allowed memory size exhausted|Out of memory' "$log" | tail -5 | sed 's/^/        /'
  fi
done

# ---- 5. webroot integrity ----------------------------------------------------
if [ "${#WEBROOTS[@]}" -eq 0 ]; then
  for d in /var/www /srv/www /usr/share/nginx/html; do
    [ -d "$d" ] && WEBROOTS[${#WEBROOTS[@]}]="$d"
  done
fi
for root in ${WEBROOTS[@]+"${WEBROOTS[@]}"}; do
  [ -d "$root" ] || { warn "skipping $root (not found)"; continue; }
  info "scanning web root for fresh droppings: $root (last $DAYS days)"
  # recently modified/created PHP files
  hits="$(find "$root" -type f -name '*.php' -mtime "-$DAYS" 2>/dev/null \
    | grep -vE '/vendor/|/node_modules/|/cache/|/storage/framework/' | head -20)"
  [ -n "$hits" ] && finding "MEDIUM" "PHP files modified in the last $DAYS days under $root (review, esp. webshells):" && printf '%s\n' "$hits" | sed 's/^/        /'
  # classic dropper locations: hidden php, double extensions, php in upload dirs
  hits="$(find "$root" -type f \( -name '.*\.php' -o -name '*.php.jpg' -o -name '*.php.png' -o -name '*.php.txt' \) 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "HIGH" "suspicious filenames under $root (hidden/double-extension PHP):" && printf '%s\n' "$hits" | sed 's/^/        /'
  hits="$(find "$root" -type d -iname '*upload*' 2>/dev/null | while read -r d; do find "$d" -maxdepth 2 -type f -name '*.php' 2>/dev/null; done | head -10)"
  [ -n "$hits" ] && finding "HIGH" "PHP executable inside upload directories under $root:" && printf '%s\n' "$hits" | sed 's/^/        /'
done

step "Hunt summary"
if [ "$FINDINGS" = 0 ]; then
  ok "no indicators found in the scanned data (not a clean bill of health — it is a point-in-time view)"
  exit 0
fi
warn "$FINDINGS finding(s) — investigate each hit; they are indicators, not proof, of compromise"
if [ "$FAIL_ON" = 1 ]; then exit 1; fi
exit 0
