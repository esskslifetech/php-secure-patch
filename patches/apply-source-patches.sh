#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: patches/apply-source-patches.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Applies the bundled security patches to a PHP source tree, choosing the right
# set for the tree's branch.  Every patch in this directory is extracted from
# official PHP releases and verified against the vulnerable trees (see
# patches/README.md).
#
# Usage:
#   ./apply-source-patches.sh /path/to/php-src [--dry-run] [--rebuild] [--force]
#
#   --dry-run   show what would be applied
#   --rebuild   after patching: ./buildconf --force && ./configure && make -j
#   --force     apply even if the tree already contains fixed versions
# ==============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
PSP_ROOT="$(cd "$HERE/.." && pwd -P)"
. "$PSP_ROOT/lib/common.sh"
. "$PSP_ROOT/lib/cve_db.sh"

SRC="${1:-}"; shift || true
[ -n "$SRC" ] && [ -d "$SRC" ] || die "usage: $0 /path/to/php-src [--dry-run] [--rebuild] [--force]"
SRC="$(cd "$SRC" && pwd -P)"

DRY=0; REBUILD=0; FORCE=0
for a in "$@"; do
  case "$a" in
    --dry-run) PSP_DRY_RUN=1; DRY=1 ;;
    --rebuild) REBUILD=1 ;;
    --force)   FORCE=1 ;;
  esac
done

# ---- identify the tree ------------------------------------------------------
[ -f "$SRC/main/php_version.h" ] || die "$SRC does not look like a php-src tree (no main/php_version.h)"
VER="$(sed -n 's/#define PHP_VERSION "\(.*\)".*/\1/p' "$SRC/main/php_version.h" | head -1)"
[ -n "$VER" ] || die "cannot determine PHP version of $SRC"
MM="$(version_major_minor "$VER")"
info "target tree: $SRC  (PHP $VER, branch $MM)"

applied=0

try_patch() { # try_patch <file> <label>
  local pf="$1" label="$2"
  [ -f "$pf" ] || { warn "patch missing: $pf"; return 1; }
  step "Applying: $label"
  if [ "$PSP_DRY_RUN" = 1 ]; then
    ( cd "$SRC" && patch -p1 --dry-run --forward --fuzz=3 < "$pf" ) \
      && ok "[dry] $label would apply cleanly" && return 0 \
      || { warn "[dry] $label does NOT apply cleanly to this tree"; return 1; }
  fi
  ( cd "$SRC" && patch -p1 --forward --fuzz=3 < "$pf" ) \
    && ok "$label applied" && return 0 \
    || { err "$label FAILED — apply manually (see patches/README.md)"; return 1; }
}

# ---- 1. PHP2Shell -----------------------------------------------------------
st="$(php2shell_status "$VER")"
if [ "$st" = "FIXED" ] && [ "$FORCE" != 1 ]; then
  ok "PHP $VER already contains the PHP2Shell fixes — skipping (use --force to apply anyway)"
else
  case "$MM" in
    8.2|8.3|8.4|8.5)
      if try_patch "$HERE/upstream-php2shell-CVE-2026-109618-109619.patch" \
           "CVE-2026-109618 + CVE-2026-109619 upstream engine fix"; then
        applied=$((applied+1))
      else
        warn "upstream patch failed on $MM — falling back to the legacy minimal backport"
        try_patch "$HERE/legacy/php2shell-minimal-backport-7.4-8.1.patch" \
          "PHP2Shell minimal backport (producer kill only)" && applied=$((applied+1))
      fi
      ;;
    7.4|8.0|8.1)
      warn "PHP $MM is end-of-life: only the minimal backport is possible"
      try_patch "$HERE/legacy/php2shell-minimal-backport-7.4-8.1.patch" \
        "PHP2Shell minimal backport (session.upload_progress producer kill)" && applied=$((applied+1))
      warn "the minimal backport does NOT fix the engine memory-safety bugs — migrate off $MM"
      ;;
    *)
      err "PHP $VER ($MM): no upstream patch set here — no supported branch and no upstream source backport"
      err "  ask your vendor/LTS channel for a backport (ESM / ELS / LTSS), otherwise migrate"
      ;;
  esac
fi

# ---- 2. CVE-2019-11043 ------------------------------------------------------
st="$(cve_2019_11043_status "$VER")"
if [ "$st" = "VULNERABLE" ]; then
  try_patch "$HERE/CVE-2019-11043-env-path-info-underflow.patch" \
    "CVE-2019-11043 env_path_info underflow fix" && applied=$((applied+1))
fi

# ---- 3. CVE-2024-4577 -------------------------------------------------------
st="$(cve_2024_4577_status "$VER")"
if [ "$st" = "VULNERABLE" ] || [ "$st" = "EOL-NO-FIX" ]; then
  try_patch "$HERE/CVE-2024-4577-php-cgi-argument-injection.patch" \
    "CVE-2024-4577 php-cgi argument injection fix (Windows)" && applied=$((applied+1))
fi

# ---- 4. rebuild -------------------------------------------------------------
if [ "$REBUILD" = 1 ] && [ "$PSP_DRY_RUN" != 1 ]; then
  step "Rebuilding PHP (this takes a while)"
  ( cd "$SRC" && ./buildconf --force && ./configure --disable-all --enable-cli --enable-fpm \
      --with-config-file-path=/etc/php && make -j"$(nproc 2>/dev/null || echo 2)" && make install ) \
    || die "rebuild failed — inspect the tree at $SRC"
  ok "rebuilt and installed — now RESTART every PHP worker (systemctl restart php*-fpm / reload apache)"
fi

step "Summary"
info "patched hunks applied: $applied"
info "next: rebuild PHP, then restart all workers — patches do nothing until workers are recycled"
