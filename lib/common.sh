#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: lib/common.sh
# Shared helpers: logging, dry-run aware execution, backups, version compare,
# JSON escaping, service control.  bash 3.2+ compatible (macOS ships 3.2).
# ==============================================================================

[ -n "${PSP_COMMON_LOADED:-}" ] && return 0
PSP_COMMON_LOADED=1

# ---- paths ------------------------------------------------------------------
PSP_ROOT="${PSP_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
PSP_LIB="$PSP_ROOT/lib"
PSP_PATCHES="$PSP_ROOT/patches"
PSP_HARDENING="$PSP_ROOT/hardening"

# ---- global behaviour flags (set by setup.sh) --------------------------------
PSP_DRY_RUN="${PSP_DRY_RUN:-0}"
PSP_YES="${PSP_YES:-0}"
PSP_VERBOSE="${PSP_VERBOSE:-0}"
PSP_STRICT="${PSP_STRICT:-0}"       # 1 = shared-hosting grade hardening
PSP_LOCKDOWN="${PSP_LOCKDOWN:-0}"   # 1 = pm.max_requests=1 (breaks the cross-request requirement)
PSP_OOM_MITIGATION="${PSP_OOM_MITIGATION:-0}"  # 1 = write memory_limit=-1 for vulnerable runtimes
PSP_NO_UPGRADE="${PSP_NO_UPGRADE:-0}"
PSP_BACKUP_DIR="${PSP_BACKUP_DIR:-}"
PSP_ACTIONS=()                      # log of actions performed/planned

# ---- colours ----------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RESET=$'\033[0m'; C_RED=$'\033[31m'; C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'
  C_BLUE=$'\033[34m'; C_CYAN=$'\033[36m'; C_BOLD=$'\033[1m'
else
  C_RESET=''; C_RED=''; C_GREEN=''; C_YELLOW=''; C_BLUE=''; C_CYAN=''; C_BOLD=''
fi

log()   { printf '%s\n' "$*"; }
info()  { printf '%s[INFO]%s %s\n' "$C_BLUE" "$C_RESET" "$*"; }
ok()    { printf '%s[ OK ]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[WARN]%s %s\n' "$C_YELLOW" "$C_RESET" "$*" >&2; }
err()   { printf '%s[FAIL]%s %s\n' "$C_RED" "$C_RESET" "$*" >&2; }
die()   { err "$*"; exit 1; }
step()  { printf '\n%s==> %s%s\n' "$C_BOLD" "$*" "$C_RESET"; }
debug() { [ "$PSP_VERBOSE" = 1 ] && printf '[dbg ] %s\n' "$*" >&2; return 0; }

action_note() { # remember what we did (or would do) for the final report
  PSP_ACTIONS[${#PSP_ACTIONS[@]}]="$1"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- run wrapper: honours --dry-run -----------------------------------------
run() {
  if [ "$PSP_DRY_RUN" = 1 ]; then
    printf '%s[dry ]%s %s\n' "$C_CYAN" "$C_RESET" "$*"
    return 0
  fi
  debug "exec: $*"
  "$@"
}

# ---- confirmations ----------------------------------------------------------
confirm() { # confirm "question" -> 0 yes / 1 no. Auto-yes with PSP_YES=1.
  [ "$PSP_YES" = 1 ] && return 0
  [ "$PSP_DRY_RUN" = 1 ] && return 0
  local ans
  printf '%s [y/N]: ' "$*" >&2
  read -r ans || return 1
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---- backups ----------------------------------------------------------------
psp_backup_init() {
  if [ -z "$PSP_BACKUP_DIR" ]; then
    local base
    if [ "$(id -u)" = 0 ]; then base="/var/backups/php-secure-patch"; else base="$HOME/.php-secure-patch/backups"; fi
    PSP_BACKUP_DIR="$base/$(date +%Y%m%d-%H%M%S)"
  fi
  if [ "$PSP_DRY_RUN" != 1 ]; then
    mkdir -p "$PSP_BACKUP_DIR" || die "cannot create backup dir $PSP_BACKUP_DIR"
    : > "$PSP_BACKUP_DIR/MANIFEST.txt"
  fi
  info "backup directory: $PSP_BACKUP_DIR"
}

backup_file() { # backup_file <file> -> echoes backup path, records in manifest
  local f="$1" dest
  [ -f "$f" ] || return 1
  if [ "$PSP_DRY_RUN" = 1 ]; then
    printf '%s\n' "(dry-run-no-backup)"
    return 0
  fi
  dest="$PSP_BACKUP_DIR/files/${f#/}"
  mkdir -p "$(dirname "$dest")"
  cp -p "$f" "$dest" || return 1
  printf '%s\n' "$f" >> "$PSP_BACKUP_DIR/MANIFEST.txt"
  printf '%s\n' "$dest"
}

record_created() { # record_created <file> — track files we CREATE so rollback removes them
  local f="$1"
  [ "$PSP_DRY_RUN" = 1 ] && return 0
  [ -n "$PSP_BACKUP_DIR" ] || return 0
  printf '%s\n' "$f" >> "$PSP_BACKUP_DIR/CREATED.txt"
}

restore_backups() { # restore everything listed in MANIFEST.txt; delete CREATED.txt entries
  local mf="$PSP_BACKUP_DIR/MANIFEST.txt" cf="$PSP_BACKUP_DIR/CREATED.txt" f dest
  if [ -f "$mf" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      dest="$PSP_BACKUP_DIR/files/${f#/}"
      if [ -f "$dest" ]; then
        if [ "$PSP_DRY_RUN" = 1 ]; then
          info "[dry] would restore $f"
        else
          cp -p "$dest" "$f" && ok "restored $f" || err "could not restore $f"
        fi
      fi
    done < "$mf"
  fi
  if [ -f "$cf" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if [ -f "$f" ]; then
        if [ "$PSP_DRY_RUN" = 1 ]; then
          info "[dry] would remove created file $f"
        else
          rm -f "$f" && ok "removed created file $f" || err "could not remove $f"
        fi
      fi
    done < "$cf"
  fi
}

# ---- version comparison -----------------------------------------------------
version_ge() { # version_ge A B  -> 0 if A >= B
  awk -v a="$1" -v b="$2" 'BEGIN {
    n = split(a, A, "."); m = split(b, B, ".")
    max = (n > m) ? n : m
    for (i = 1; i <= max; i++) {
      x = (i <= n) ? A[i] + 0 : 0
      y = (i <= m) ? B[i] + 0 : 0
      if (x > y) exit 0
      if (x < y) exit 1
    }
    exit 0
  }'
}
version_lt() { ! version_ge "$1" "$2"; }

version_major_minor() { printf '%s\n' "$1" | awk -F. '{print $1"."$2}'; }

# ---- misc -------------------------------------------------------------------
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/}"
  printf '%s' "$s"
}

# sed -i that works on both GNU and BSD sed
sed_inplace() { # sed_inplace <expr> <file>
  local expr="$1" file="$2" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/psp.XXXXXX")" || return 1
  sed "$expr" "$file" > "$tmp" && mv "$tmp" "$file"
}

require_root_for() {
  if [ "$(id -u)" != 0 ] && [ "$PSP_DRY_RUN" != 1 ]; then
    die "action '$1' needs root. Re-run with sudo, or use --dry-run to preview."
  fi
}

# ---- service management -----------------------------------------------------
svc_is_unit() { have_cmd systemctl && systemctl list-unit-files "$1.service" >/dev/null 2>&1; }

svc_restart() { # svc_restart <name> — restart (recycles workers: required after PHP2Shell patch)
  local s="$1"
  if [ "$PSP_DRY_RUN" = 1 ]; then info "[dry] would restart service: $s"; return 0; fi
  if svc_is_unit "$s"; then
    systemctl restart "$s" 2>/dev/null && ok "restarted $s" && return 0
    systemctl reload "$s" 2>/dev/null && ok "reloaded $s" && return 0
  fi
  if have_cmd service; then
    service "$s" restart 2>/dev/null && ok "restarted $s" && return 0
    service "$s" reload 2>/dev/null && ok "reloaded $s" && return 0
  fi
  # fall back to direct signals for process name $s
  if have_cmd pkill; then
    pkill -HUP -x "$s" 2>/dev/null && ok "sent SIGHUP to $s" && return 0
  fi
  warn "could not restart '$s' automatically — restart it manually (workers must be recycled!)"
  return 1
}

svc_test_config() { # svc_test_config <nginx|apache|php-fpm> <config-command...>
  local name="$1"; shift
  if [ "$PSP_DRY_RUN" = 1 ]; then return 0; fi
  if "$@" >/dev/null 2>&1; then
    ok "$name configuration test passed"
    return 0
  fi
  err "$name configuration test FAILED"
  return 1
}
