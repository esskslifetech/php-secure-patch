#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: hunt/hunt.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Post-patch compromise hunting for PHP2Shell (CVE-2026-109618/109619),
# HTTP2Shell (CVE-2026-111497), CVE-2024-4577 and general webshell indicators —
# the indicators named by CISA, NCSC-NL, watchTowr and the Brotli advisory:
#
#   1. unusually large multipart/form-data POSTs (OOM-trigger steering)
#   2. session.upload_progress probes (PHP_SESSION_UPLOAD_PROGRESS in requests)
#   3. php-cgi argument-injection probes (%ad / "-d " / "-s " in query strings)
#   4. "Allowed memory size exhausted" bursts in PHP error logs
#   5. recently created/modified .php files in web roots (webshells)
#   6. HTTP2Shell decode failures — BLOCK_SWITCH / error -17 in application logs.
#      This is the highest-value IOC in the whole set: on a PATCHED runtime the
#      new error code can only appear when somebody sent a trigger, so it is a
#      detection, not a crash to be tolerated.
#   7. ~23 MB (2^24-command) compressed request bodies: the known RCE payload
#      shape. A 23 MB body is never an accident.
#
# Usage:
#   ./hunt/hunt.sh                          # auto-discover logs + report
#   ./hunt/hunt.sh --log access.log --log more.log
#   ./hunt/hunt.sh --error-log /var/log/php.log --app-log /var/log/node.log
#   ./hunt/hunt.sh --webroot /var/www --days 14
#   ./hunt/hunt.sh --fail-on-findings       # exit 1 when anything is found
# ==============================================================================
set -u
P2S_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
. "$P2S_ROOT/lib/common.sh"

usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

LOGS=(); ERRLOGS=(); APPLOGS=(); WEBROOTS=(); DAYS=14; MAX_BYTES=1048576; FAIL_ON=0

while [ $# -gt 0 ]; do
  case "$1" in
    --log)        shift; LOGS[${#LOGS[@]}]="${1:-}" ;;
    --error-log)  shift; ERRLOGS[${#ERRLOGS[@]}]="${1:-}" ;;
    --app-log)    shift; APPLOGS[${#APPLOGS[@]}]="${1:-}" ;;
    --webroot)    shift; WEBROOTS[${#WEBROOTS[@]}]="${1:-}" ;;
    --days)       shift; DAYS="${1:-14}" ;;
    --max-bytes)  shift; MAX_BYTES="${1:-1048576}" ;;
    --fail-on-findings) FAIL_ON=1 ;;
    --help|-h)    usage; exit 0 ;;
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

# application logs: the HTTP2Shell decode-failure IOC lives here, not in access logs
if [ "${#APPLOGS[@]}" -eq 0 ]; then
  for f in /var/log/node*.log /var/log/nodejs/*.log /var/log/pm2/*.log \
           /root/.pm2/logs/*.log /home/*/.pm2/logs/*.log \
           /var/log/python*.log /var/log/*app*.log \
           /var/log/protection2shell/*.log /var/log/gunicorn/*.log /var/log/uvicorn*.log; do
    [ -f "$f" ] && [ -r "$f" ] && APPLOGS[${#APPLOGS[@]}]="$f"
  done
fi

step "PHP2Shell / HTTP2Shell compromise hunt"
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
  [ -n "$hits" ] && finding "HIGH" "large POST bodies (>$MAX_BYTES B) in $log — OOM-trigger steering (PHP2Shell) or the ~23 MB Brotli RCE payload shape (HTTP2Shell):" && printf '%s\n' "$hits" | sed 's/^/        /'

  # 1b. Brotli-compressed request bodies, when the log format carries headers
  hits="$(grep -iEn 'content-encoding[:=][^\"]*br' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "MEDIUM" "Brotli-compressed request bodies in $log (HTTP2Shell CVE-2026-111497) — legitimate APIs rarely POST 'br':" && printf '%s\n' "$hits" | sed 's/^/        /'

  # 1c. our own containment guard firing: someone is probing the blocked path
  hits="$(grep -cE '\" 415 ' "$log" 2>/dev/null)"
  [ -n "$hits" ] || hits=0
  if [ "$hits" -gt 20 ] 2>/dev/null; then
    finding "LOW" "$hits x HTTP 415 responses in $log — the deny-brotli guard is being exercised (probe traffic, or a broken client):"
    grep -E '\" 415 ' "$log" | tail -5 | sed 's/^/        /'
  fi

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
  n="$(grep -c 'Allowed memory size exhausted\|Out of memory\|memory_limit' "$log" 2>/dev/null)"
  [ -n "$n" ] || n=0
  if [ "$n" -gt 5 ]; then
    finding "HIGH" "$n memory-exhaustion events in $log — burst may mark CVE-2026-109618 OOM-probing:"
    grep -En 'Allowed memory size exhausted|Out of memory' "$log" | tail -5 | sed 's/^/        /'
  fi
done

# ---- 4b. HTTP2Shell decode failures (highest-value IOC) ----------------------
HUH_SEEN=""
for log in ${APPLOGS[@]+"${APPLOGS[@]}"} ${ERRLOGS[@]+"${ERRLOGS[@]}"}; do
  [ -f "$log" ] || { debug "skipping $log (not found)"; continue; }
  case " $HUH_SEEN " in *" $log "*) continue ;; esac
  HUH_SEEN="$HUH_SEEN $log"
  info "scanning application log for Brotli decode failures: $log"

  # On a PATCHED decoder the new error code is emitted *instead of* corrupting
  # memory. Seeing it means somebody sent a trigger to this host.
  hits="$(grep -iEn 'BLOCK_SWITCH|ERROR_FORMAT_BLOCK_SWITCH|brotli[^ ]*error[ :=-]*-17|error[ :=-]*-17[^0-9]' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "CRITICAL" "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17) in $log — an HTTP2Shell trigger reached a PATCHED decoder:" && printf '%s\n' "$hits" | sed 's/^/        /'

  # Generic decode failures: a corrupted stream, or the tiny DoS payload that
  # spins the decoder. Noisier than -17, still worth seeing.
  hits="$(grep -iEn 'brotli.*(invalid|corrupt|unexpected|malformed)|ERR__ERROR_FORMAT|DecompressionStream.*brotli' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "HIGH" "Brotli decode/format errors in $log (HTTP2Shell — DoS is the floor of this bug):" && printf '%s\n' "$hits" | sed 's/^/        /'

  # Process death consistent with a decoder overflow (or the DoS spin being killed).
  hits="$(grep -iEn 'segmentation fault|SIGSEGV|SIGABRT|heap-buffer-overflow|brotli.*(crash|abort)' "$log" 2>/dev/null | head -10)"
  [ -n "$hits" ] && finding "HIGH" "crash/OOM signatures in $log — possible HTTP2Shell memory corruption or DoS:" && printf '%s\n' "$hits" | sed 's/^/        /'
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
