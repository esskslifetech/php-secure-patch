#!/usr/bin/env bash
# ==============================================================================
#  protection2shell — PHP2Shell + HTTP2Shell: detect, contain, fix, verify
#  Author: ESS KS Life Tech — MIT licensed, see LICENSE
# ==============================================================================
#  One command that:
#    1. detects the OS, every PHP install/version/SAPI, web servers, projects,
#       and every Brotli decoder carrier (libbrotli, Node, Bun, Python wheels,
#       Envoy, .NET, curl, PHP extensions, vendored source trees)
#    2. audits PHP2Shell (CVE-2026-109618/109619), HTTP2Shell (CVE-2026-111497),
#       CVE-2026-115560, CVE-2024-4577, CVE-2019-11043 and general hardening
#    3. contains: refuses br request bodies at the edge, disables in-process
#       decompression, kills exploit producers, recycles workers, optionally
#       quarantines webshell-shaped files  (--contain, or --auto)
#    4. fixes everything it safely can: package upgrades, ini/FPM hardening,
#       nginx guards, source patches for PHP and Brotli, worker restarts
#    5. verifies the result instead of trusting exit codes  (--verify)
#
#  Usage: ./setup.sh [options]
#    (no flags)         detect + audit + print report (read-only)
#    --auto             the whole job, unattended: contain + fix + verify
#    --fix              apply fixes (backs up everything first)
#    --contain          containment only: cut the exploit channel, no upgrades
#    --quarantine       also move webshell-shaped files out of web roots
#    --verify           re-check every item and report ok/pending/unknown
#    --yes, -y          never prompt
#    --dry-run          print what would change, change nothing
#    --strict           shared-hosting grade hardening (display_errors off, ...)
#    --lockdown         pm.max_requests=1: breaks CVE-2026-109619 cross-request reuse
#    --oom-mitigation   write memory_limit=-1 for vulnerable runtimes (CVE-2026-109618
#                       interim mitigation; you must add an OS/container memory cap)
#    --no-upgrade       skip package upgrades
#    --source-dir DIR   also apply patches/ to a php-src tree
#    --brotli-src DIR   also patch a Brotli source/vendored tree (repeatable)
#    --scan-path DIR    extra project root (repeatable)
#    --json FILE        write machine-readable report to FILE
#    --rollback [DIR]   restore a previous backup set
#    --verbose          debug output
#    --help             this text
#
#  Exit codes: 0 = ok / 2 = vulnerable state remains / 1 = error
# ==============================================================================
# --- end of help ---
# Re-exec under bash when invoked as `sh setup.sh` (dash on Debian/Ubuntu, BSD
# sh on macOS, some CI runners): the scripts use bash arrays and [[ ]], and a
# silent syntax error is the most common "it will not install" report.
if [ -z "${BASH_VERSION:-}" ]; then
  command -v bash >/dev/null 2>&1 || {
    echo "protection2shell needs bash — install it (apt install bash / brew install bash) and retry" >&2
    exit 1
  }
  exec bash "$0" "$@"
fi

set -u

P2S_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
export P2S_ROOT
# shellcheck source=lib/common.sh
. "$P2S_ROOT/lib/common.sh"
. "$P2S_ROOT/lib/detect.sh"
. "$P2S_ROOT/lib/brotli_db.sh"
. "$P2S_ROOT/lib/detect_brotli.sh"
. "$P2S_ROOT/lib/cve_db.sh"
. "$P2S_ROOT/lib/fix.sh"
. "$P2S_ROOT/lib/contain.sh"
. "$P2S_ROOT/lib/verify.sh"
. "$P2S_ROOT/lib/report.sh"

# print the header comment block only: stops at the closing rule, so shell
# lines and directives below it never reach --help output
usage() { awk 'NR == 1 { next } /^# ?--- end of help ---/ { exit } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

SCAN_PATHS=""
JSON_OUT=""
ROLLBACK_DIR=""
DO_FIX=0
P2S_BROTLI_SRC=""
P2S_SOURCE_DIR=""

while [ $# -gt 0 ]; do
  case "$1" in
    --auto)         DO_FIX=1; P2S_YES=1; P2S_CONTAIN=1; P2S_VERIFY=1 ;;
    --fix)          DO_FIX=1 ;;
    --contain)      P2S_CONTAIN=1 ;;
    --quarantine)   P2S_QUARANTINE=1; P2S_CONTAIN=1 ;;
    --verify)       P2S_VERIFY=1 ;;
    --yes|-y)       P2S_YES=1 ;;
    --dry-run)      P2S_DRY_RUN=1 ;;
    --strict)       P2S_STRICT=1 ;;
    --lockdown)     P2S_LOCKDOWN=1 ;;
    --oom-mitigation) P2S_OOM_MITIGATION=1 ;;
    --no-upgrade)   P2S_NO_UPGRADE=1 ;;
    --source-dir)   shift; P2S_SOURCE_DIR="${1:-}"; [ -n "$P2S_SOURCE_DIR" ] || die "--source-dir needs a path" ;;
    --brotli-src)   shift; [ -n "${1:-}" ] || die "--brotli-src needs a path"
                    P2S_BROTLI_SRC="$P2S_BROTLI_SRC ${1:-}" ;;
    --scan-path)    shift; SCAN_PATHS="$SCAN_PATHS ${1:-}"; [ -n "${1:-}" ] || die "--scan-path needs a path" ;;
    --json)         shift; JSON_OUT="${1:-}"; [ -n "$JSON_OUT" ] || die "--json needs a file path" ;;
    --rollback)     ROLLBACK_DIR="__AUTO__"
                    # optional next arg = backup dir (must not look like a flag)
                    if [ $# -ge 2 ]; then
                      case "$2" in
                        -*) : ;;
                        *)  shift; ROLLBACK_DIR="$1" ;;
                      esac
                    fi
                    ;;
    --verbose)      P2S_VERBOSE=1 ;;
    --help|-h)      usage; exit 0 ;;
    *)              die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

export P2S_DRY_RUN P2S_YES P2S_VERBOSE P2S_STRICT P2S_LOCKDOWN P2S_OOM_MITIGATION P2S_NO_UPGRADE
export P2S_CONTAIN P2S_QUARANTINE P2S_VERIFY P2S_SCAN_PATHS="$SCAN_PATHS"
export P2S_BROTLI_SRC

# ------------------------------------------------------------------------------
# rollback mode
# ------------------------------------------------------------------------------
if [ -n "$ROLLBACK_DIR" ]; then
  if [ "$ROLLBACK_DIR" = "__AUTO__" ]; then
    # bare --rollback: pick the newest backup set (new location, or the legacy
    # php-secure-patch tree if this host was patched by v1.x)
    base="$(p2s_backup_base)"
    ROLLBACK_DIR="$(ls -1d "$base"/*/ 2>/dev/null | tail -1)"
    [ -n "$ROLLBACK_DIR" ] || die "no backup sets found under $base"
  fi
  ROLLBACK_DIR="${ROLLBACK_DIR%/}"
  [ -d "$ROLLBACK_DIR" ] || die "backup set not found: $ROLLBACK_DIR"
  step "Rolling back from $ROLLBACK_DIR"
  P2S_BACKUP_DIR="$ROLLBACK_DIR"
  restore_backups
  fix_restart_workers
  ok "rollback complete"
  exit 0
fi

# ------------------------------------------------------------------------------
# phase 1: detect
# ------------------------------------------------------------------------------
step "protection2shell — PHP2Shell + HTTP2Shell response toolkit"
info "mode: $([ "$DO_FIX" = 1 ] && echo FIX || echo AUDIT-ONLY)$([ "$P2S_CONTAIN" = 1 ] && echo ' + CONTAIN') $([ "$P2S_DRY_RUN" = 1 ] && echo '(dry-run)')"

step "Detecting system, PHP runtimes, web servers"
detect_all

step "Detecting PHP projects"
detect_projects "$SCAN_PATHS"

step "Detecting Brotli decoder carriers (HTTP2Shell)"
detect_brotli_all

# ------------------------------------------------------------------------------
# phase 2: audit
# ------------------------------------------------------------------------------
step "Auditing CVEs and hardening posture"
audit_all

vuln=0
for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
  case "$(printf '%s' "$r" | cut -d'|' -f2)" in VULNERABLE|MITIGATE) vuln=$((vuln+1)) ;; esac
done
brotli_vuln="$(brotli_critical_count)"
vuln=$((vuln + brotli_vuln))
if [ "$vuln" -gt 0 ]; then
  warn "$vuln vulnerable/mitigate finding(s) present"
else
  ok "no unaddressed CVE exposure found"
fi

# ------------------------------------------------------------------------------
# phase 2.5: contain — stop exploitation from spreading before patching
# ------------------------------------------------------------------------------
if [ "$P2S_CONTAIN" = 1 ]; then
  if [ "$vuln" -gt 0 ] || [ "$P2S_FORCE_CONTAIN" = 1 ]; then
    contain_all || true
  else
    info "nothing to contain (no vulnerable carrier found; --force-contain to apply anyway)"
  fi
fi

# ------------------------------------------------------------------------------
# phase 3: fix — close the vulnerability permanently
# ------------------------------------------------------------------------------
if [ "$DO_FIX" = 1 ]; then
  if [ "$vuln" -gt 0 ] || [ "${#HARDENING_RECORDS[@]}" -gt 0 ] || [ "$P2S_CONTAIN" = 1 ]; then
    if [ "$P2S_CONTAIN" = 1 ] || confirm "Apply automatic fixes (backups kept under ${P2S_BACKUP_DIR:-<backup dir>})?"; then
      if ! fix_all; then
        err "remediation failed — some actions did not complete"
      fi
      # re-detect + re-audit after fixes so the report shows the new posture
      step "Re-auditing after fixes"
      detect_php_all; detect_fpm; detect_webservers
      detect_brotli_lib; detect_brotli_node; detect_brotli_python
      audit_all
      vuln=0
      for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
        case "$(printf '%s' "$r" | cut -d'|' -f2)" in VULNERABLE|MITIGATE) vuln=$((vuln+1)) ;; esac
      done
      vuln=$((vuln + $(brotli_critical_count)))
    else
      info "fixes skipped by user"
    fi
  else
    ok "nothing to fix"
  fi
else
  info "audit-only mode — run './setup.sh --auto' to contain + fix + verify"
fi

# ------------------------------------------------------------------------------
# phase 4: verify — never report success without checking
# ------------------------------------------------------------------------------
verify_rc=0
if [ "$P2S_VERIFY" = 1 ] || [ "$DO_FIX" = 1 ] || [ "$P2S_CONTAIN" = 1 ]; then
  verify_all || verify_rc=1
fi

# ------------------------------------------------------------------------------
# phase 5: report
# ------------------------------------------------------------------------------
report_human
[ -n "$JSON_OUT" ] && report_json "$JSON_OUT"

if [ "$DO_FIX" = 1 ] && [ "$P2S_DRY_RUN" != 1 ]; then
  [ "$vuln" -gt 0 ] && exit 2
  exit 0
fi
if [ "$P2S_CONTAIN" = 1 ] && [ "$P2S_DRY_RUN" != 1 ]; then
  # containment leaves the vulnerability open by design; exposure "remains"
  [ "$vuln" -gt 0 ] && exit 2
fi
[ "$verify_rc" != 0 ] && [ "$P2S_VERIFY" = 1 ] && exit 2
report_exit_code
exit $?
