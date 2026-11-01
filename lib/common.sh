#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/common.sh
# Shared helpers: logging, dry-run aware execution, backups, version compare,
# JSON escaping, service control.  bash 3.2+ compatible (macOS ships 3.2).
# ==============================================================================

[ -n "${P2S_COMMON_LOADED:-}" ] && return 0
P2S_COMMON_LOADED=1

# ---- paths ------------------------------------------------------------------
P2S_ROOT="${P2S_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
P2S_LIB="$P2S_ROOT/lib"
P2S_PATCHES="$P2S_ROOT/patches"
P2S_HARDENING="$P2S_ROOT/hardening"
P2S_CONTAIN_DIR="$P2S_ROOT/contain"

# ---- global behaviour flags (set by setup.sh) --------------------------------
P2S_DRY_RUN="${P2S_DRY_RUN:-0}"
P2S_YES="${P2S_YES:-0}"
P2S_VERBOSE="${P2S_VERBOSE:-0}"
P2S_STRICT="${P2S_STRICT:-0}"       # 1 = shared-hosting grade hardening
P2S_LOCKDOWN="${P2S_LOCKDOWN:-0}"   # 1 = pm.max_requests=1 (breaks the cross-request requirement)
P2S_OOM_MITIGATION="${P2S_OOM_MITIGATION:-0}"  # 1 = write memory_limit=-1 for vulnerable runtimes
P2S_NO_UPGRADE="${P2S_NO_UPGRADE:-0}"
P2S_CONTAIN="${P2S_CONTAIN:-0}"     # 1 = containment pass (cut the input channel)
P2S_QUARANTINE="${P2S_QUARANTINE:-0}"        # 1 = move suspicious droppings aside
P2S_QUARANTINE_DAYS="${P2S_QUARANTINE_DAYS:-30}"
P2S_FORCE_CONTAIN="${P2S_FORCE_CONTAIN:-0}"  # 1 = contain even if no carrier looks vulnerable
P2S_VERIFY="${P2S_VERIFY:-0}"
P2S_BACKUP_DIR="${P2S_BACKUP_DIR:-}"
P2S_TOOL_VERSION="2.0.1"            # protection2shell release (renamed from php-secure-patch 1.x)
P2S_ACTIONS=()                      # log of actions performed/planned

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
debug() { [ "$P2S_VERBOSE" = 1 ] && printf '[dbg ] %s\n' "$*" >&2; return 0; }

action_note() { # remember what we did (or would do) for the final report
  P2S_ACTIONS[${#P2S_ACTIONS[@]}]="$1"
}

have_cmd() { command -v "$1" >/dev/null 2>&1; }

# ---- run wrapper: honours --dry-run -----------------------------------------
run() {
  if [ "$P2S_DRY_RUN" = 1 ]; then
    printf '%s[dry ]%s %s\n' "$C_CYAN" "$C_RESET" "$*"
    return 0
  fi
  debug "exec: $*"
  "$@"
}

# ---- confirmations ----------------------------------------------------------
confirm() { # confirm "question" -> 0 yes / 1 no. Auto-yes with P2S_YES=1.
  [ "$P2S_YES" = 1 ] && return 0
  [ "$P2S_DRY_RUN" = 1 ] && return 0
  local ans
  printf '%s [y/N]: ' "$*" >&2
  read -r ans || return 1
  case "$ans" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

# ---- backups ----------------------------------------------------------------
#
# Rename note (v2.0.0): the project was called php-secure-patch up to v1.x. Old
# backup sets stay where they are and remain restorable: p2s_backup_base() falls
# back to the legacy location when the new one is empty, so an upgrade never
# strands somebody's rollback.
p2s_backup_base() {
  local base legacy
  if [ "$(id -u)" = 0 ]; then
    base="/var/backups/protection2shell"; legacy="/var/backups/php-secure-patch"
  else
    base="$HOME/.protection2shell/backups"; legacy="$HOME/.php-secure-patch/backups"
  fi
  if [ ! -d "$base" ] && [ -d "$legacy" ]; then printf '%s' "$legacy"; else printf '%s' "$base"; fi
}

# state dir holds containment artifacts (guards, snippets). Not a backup area.
p2s_state_dir() {
  local d
  if [ -n "${P2S_STATE_DIR:-}" ]; then d="$P2S_STATE_DIR"
  elif [ "$(id -u)" = 0 ]; then d="/etc/protection2shell"
  else d="$HOME/.protection2shell"
  fi
  printf '%s' "$d"
}

p2s_backup_init() {
  if [ -z "$P2S_BACKUP_DIR" ]; then
    P2S_BACKUP_DIR="$(p2s_backup_base)/$(date +%Y%m%d-%H%M%S)"
  fi
  if [ "$P2S_DRY_RUN" != 1 ]; then
    mkdir -p "$P2S_BACKUP_DIR" || die "cannot create backup dir $P2S_BACKUP_DIR"
    : > "$P2S_BACKUP_DIR/MANIFEST.txt"
  fi
  info "backup directory: $P2S_BACKUP_DIR"
}

# backup path a given absolute file would use inside the active backup set
backup_path_for() {
  printf '%s/files/%s' "$P2S_BACKUP_DIR" "$(printf '%s' "$1" | sed 's|^/||')"
}

backup_file() { # backup_file <file> -> echoes backup path, records in manifest
  local f="$1" dest
  [ -f "$f" ] || return 1
  if [ "$P2S_DRY_RUN" = 1 ]; then
    printf '%s\n' "(dry-run-no-backup)"
    return 0
  fi
  dest="$(backup_path_for "$f")"
  mkdir -p "$(dirname "$dest")"
  cp -p "$f" "$dest" || return 1
  printf '%s\n' "$f" >> "$P2S_BACKUP_DIR/MANIFEST.txt"
  printf '%s\n' "$dest"
}

# restore ONE file from the active backup set (used for validating an edit and
# rolling that edit back on its own, rather than the whole set)
restore_file() { # restore_file <absolute-path>
  local f="$1" src
  src="$(backup_path_for "$f")"
  if [ ! -f "$src" ]; then
    err "no backup for $f — cannot roll back this file"
    return 1
  fi
  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would restore $f"
    return 0
  fi
  cp -p "$src" "$f" && ok "rolled back $f" || { err "could not restore $f"; return 1; }
}

record_created() { # record_created <file> — track files we CREATE so rollback removes them
  local f="$1"
  [ "$P2S_DRY_RUN" = 1 ] && return 0
  [ -n "$P2S_BACKUP_DIR" ] || return 0
  printf '%s\n' "$f" >> "$P2S_BACKUP_DIR/CREATED.txt"
}

# quarantine: move a suspicious artifact OUT of the web root instead of deleting
# it. Reversible by rollback.sh, and the operator keeps the evidence.
quarantine_file() { # quarantine_file <absolute-path> -> echoes destination
  local f="$1" dest
  [ -e "$f" ] || return 1
  [ -L "$f" ] && { warn "refusing to quarantine symlink $f"; return 1; }
  if [ "$P2S_DRY_RUN" = 1 ]; then
    printf '%s\n' "[dry] would quarantine $f"
    return 0
  fi
  dest="$P2S_BACKUP_DIR/quarantine/${f#/}"
  mkdir -p "$(dirname "$dest")" || return 1
  mv -f "$f" "$dest" || return 1
  printf '%s|%s\n' "$f" "$dest" >> "$P2S_BACKUP_DIR/QUARANTINED.txt"
  printf '%s\n' "$dest"
}

restore_backups() { # restore everything listed in MANIFEST.txt; delete CREATED.txt entries
  local mf="$P2S_BACKUP_DIR/MANIFEST.txt" cf="$P2S_BACKUP_DIR/CREATED.txt"
  local qf="$P2S_BACKUP_DIR/QUARANTINED.txt" f dest orig
  if [ -f "$mf" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      dest="$(backup_path_for "$f")"
      if [ -f "$dest" ]; then
        if [ "$P2S_DRY_RUN" = 1 ]; then
          info "[dry] would restore $f"
        else
          cp -p "$dest" "$f" && ok "restored $f" || err "could not restore $f"
        fi
      fi
    done < "$mf"
  fi
  if [ -f "$qf" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      orig="${f%%|*}"
      dest="${f#*|}"
      if [ -f "$dest" ]; then
        if [ "$P2S_DRY_RUN" = 1 ]; then
          info "[dry] would return $dest to $orig"
        else
          mkdir -p "$(dirname "$orig")" && mv -f "$dest" "$orig" \
            && ok "quarantine released: $orig" || err "could not restore quarantined $orig"
        fi
      fi
    done < "$qf"
  fi
  if [ -f "$cf" ]; then
    while IFS= read -r f; do
      [ -n "$f" ] || continue
      if [ -f "$f" ] || [ -L "$f" ]; then
        if [ "$P2S_DRY_RUN" = 1 ]; then
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
  [ "$(id -u)" = 0 ] && return 0
  [ "$P2S_DRY_RUN" = 1 ] && return 0
  if ! have_cmd sudo; then
    die "action '$1' needs root and this host has no sudo.
       Read-only audit and reporting work without it:  ./setup.sh
       Preview the change without applying it:          ./setup.sh --contain --dry-run
       On Windows, run the audit in Git-Bash and apply the IIS guard with
       contain/windows-iis-http2shell.ps1 from an elevated PowerShell."
  fi
  die "action '$1' needs root. Re-run with sudo, or use --dry-run to preview."
}

# ---- service management -----------------------------------------------------
svc_is_unit() { have_cmd systemctl && systemctl list-unit-files "$1.service" >/dev/null 2>&1; }

svc_restart() { # svc_restart <name> — restart (recycles workers: required after PHP2Shell patch)
  local s="$1"
  if [ "$P2S_DRY_RUN" = 1 ]; then info "[dry] would restart service: $s"; return 0; fi
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
  if [ "$P2S_DRY_RUN" = 1 ]; then return 0; fi
  if "$@" >/dev/null 2>&1; then
    ok "$name configuration test passed"
    return 0
  fi
  err "$name configuration test FAILED"
  return 1
}
