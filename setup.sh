#!/usr/bin/env bash
# ==============================================================================
#  php-secure-patch — PHP2Shell & friends: detect, audit, fix — automatically
#  Author: ESS KS Life Tech — MIT licensed, see LICENSE
# ==============================================================================
#  One command that:
#    1. detects the OS, every PHP install/version/SAPI, web servers and projects
#    2. audits against CVE-2026-109618, CVE-2026-109619, CVE-2026-115560,
#       CVE-2024-4577, CVE-2019-11043 and general PHP hardening
#    3. fixes everything it safely can (packages, ini, FPM pools, nginx guards,
#       worker restarts) with full backups + rollback
#
#  Usage: ./setup.sh [options]
#    (no flags)         detect + audit + print report (read-only)
#    --fix              apply fixes (backs up everything first)
#    --yes, -y          never prompt
#    --dry-run          print what would change, change nothing
#    --strict           shared-hosting grade hardening (display_errors off, ...)
#    --lockdown         pm.max_requests=1: breaks CVE-2026-109619 cross-request reuse
#    --oom-mitigation   write memory_limit=-1 for vulnerable runtimes (CVE-2026-109618
#                       interim mitigation; you must add an OS/container memory cap)
#    --no-upgrade       skip package upgrades
#    --source-dir DIR   also apply patches/ to a php-src tree
#    --scan-path DIR    extra project root (repeatable)
#    --json FILE        write machine-readable report to FILE
#    --rollback [DIR]   restore a previous backup set
#    --verbose          debug output
#    --help             this text
#
#  Exit codes: 0 = ok / 2 = vulnerable state remains / 1 = error
# ==============================================================================
set -u

PSP_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
export PSP_ROOT
# shellcheck source=lib/common.sh
. "$PSP_ROOT/lib/common.sh"
. "$PSP_ROOT/lib/detect.sh"
. "$PSP_ROOT/lib/cve_db.sh"
. "$PSP_ROOT/lib/fix.sh"
. "$PSP_ROOT/lib/report.sh"

# print the header comment block only: stops at the closing rule, so shell
# lines and directives below it never reach --help output
usage() { awk 'NR>1 { if (/^# =+$/ && ++r == 2) exit; sub(/^# ?/, ""); print }' "$0"; }

SCAN_PATHS=""
JSON_OUT=""
ROLLBACK_DIR=""
DO_FIX=0

while [ $# -gt 0 ]; do
  case "$1" in
    --fix)          DO_FIX=1 ;;
    --yes|-y)       PSP_YES=1 ;;
    --dry-run)      PSP_DRY_RUN=1 ;;
    --strict)       PSP_STRICT=1 ;;
    --lockdown)     PSP_LOCKDOWN=1 ;;
    --oom-mitigation) PSP_OOM_MITIGATION=1 ;;
    --no-upgrade)   PSP_NO_UPGRADE=1 ;;
    --source-dir)   shift; PSP_SOURCE_DIR="${1:-}"; [ -n "$PSP_SOURCE_DIR" ] || die "--source-dir needs a path" ;;
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
    --verbose)      PSP_VERBOSE=1 ;;
    --help|-h)      usage; exit 0 ;;
    *)              die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

export PSP_DRY_RUN PSP_YES PSP_VERBOSE PSP_STRICT PSP_LOCKDOWN PSP_OOM_MITIGATION PSP_NO_UPGRADE

# ------------------------------------------------------------------------------
# rollback mode
# ------------------------------------------------------------------------------
if [ -n "$ROLLBACK_DIR" ]; then
  if [ "$ROLLBACK_DIR" = "__AUTO__" ]; then
    # bare --rollback: pick the newest backup set
    base="/var/backups/php-secure-patch"; [ -d "$base" ] || base="$HOME/.php-secure-patch/backups"
    ROLLBACK_DIR="$(ls -1d "$base"/*/ 2>/dev/null | tail -1)"
    [ -n "$ROLLBACK_DIR" ] || die "no backup sets found under $base"
  fi
  ROLLBACK_DIR="${ROLLBACK_DIR%/}"
  [ -d "$ROLLBACK_DIR" ] || die "backup set not found: $ROLLBACK_DIR"
  step "Rolling back from $ROLLBACK_DIR"
  PSP_BACKUP_DIR="$ROLLBACK_DIR"
  restore_backups
  fix_restart_workers
  ok "rollback complete"
  exit 0
fi

# ------------------------------------------------------------------------------
# phase 1: detect
# ------------------------------------------------------------------------------
step "php-secure-patch — PHP2Shell response toolkit"
info "mode: $([ "$DO_FIX" = 1 ] && echo FIX || echo AUDIT-ONLY) $([ "$PSP_DRY_RUN" = 1 ] && echo '(dry-run)')"

step "Detecting system, PHP runtimes, web servers"
detect_all

step "Detecting PHP projects"
detect_projects "$SCAN_PATHS"

# ------------------------------------------------------------------------------
# phase 2: audit
# ------------------------------------------------------------------------------
step "Auditing CVEs and hardening posture"
audit_all

vuln=0
for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
  case "$(printf '%s' "$r" | cut -d'|' -f2)" in VULNERABLE|MITIGATE) vuln=$((vuln+1)) ;; esac
done
if [ "$vuln" -gt 0 ]; then
  warn "$vuln vulnerable/mitigate CVE finding(s) present"
else
  ok "no unaddressed CVE exposure found"
fi

# ------------------------------------------------------------------------------
# phase 3: fix
# ------------------------------------------------------------------------------
if [ "$DO_FIX" = 1 ]; then
  if [ "$vuln" -gt 0 ] || [ "${#HARDENING_RECORDS[@]}" -gt 0 ]; then
    if confirm "Apply automatic fixes (backups kept under ${PSP_BACKUP_DIR:-<backup dir>})?"; then
      if ! fix_all; then
        err "remediation failed — some actions did not complete"
      fi
      # re-audit after fixes so the report shows the new posture
      step "Re-auditing after fixes"
      detect_php_all; detect_fpm; detect_webservers
      audit_all
      vuln=0
      for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
        case "$(printf '%s' "$r" | cut -d'|' -f2)" in VULNERABLE|MITIGATE) vuln=$((vuln+1)) ;; esac
      done
    else
      info "fixes skipped by user"
    fi
  else
    ok "nothing to fix"
  fi
else
  info "audit-only mode — run './setup.sh --fix' (as root) to remediate"
fi

# ------------------------------------------------------------------------------
# phase 4: report
# ------------------------------------------------------------------------------
report_human
[ -n "$JSON_OUT" ] && report_json "$JSON_OUT"

if [ "$DO_FIX" = 1 ] && [ "$PSP_DRY_RUN" != 1 ]; then
  if [ "$vuln" -gt 0 ]; then
    exit 2
  fi
  exit 0
fi
report_exit_code
exit $?
