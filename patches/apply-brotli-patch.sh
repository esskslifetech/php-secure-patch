#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: patches/apply-brotli-patch.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
#
# Applies the CVE-2026-111497 (HTTP2Shell) fix to a Brotli source tree — the
# real fix for the case package managers cannot cover: Brotli is vendored, not
# linked. Node keeps it at deps/brotli, Bun vendors it, ClickHouse forks it,
# Arrow pins 1.0.9, DuckDB 1.1.0, PHP extensions and statically linked curl
# bundle their own copies. Patching the OS libbrotli fixes none of those.
#
# Usage:
#   ./apply-brotli-patch.sh /path/to/brotli [options]
#   ./apply-brotli-patch.sh --find-under /path/to/src-tree [options]
#
#   --find-under DIR  patch every Brotli tree found under DIR (max depth 6)
#   --dry-run         show what would be applied, change nothing
#   --fuzz            allow fuzzy matching (patch --fuzz=3); default is strict
#   --verify          verify the patched tree (source assertions + gcc syntax check)
#   --build           rebuild the library after patching (needs cmake)
#   --revert          reverse-apply the patch instead
#   --force           apply even if the tree already carries the fix
#
# Exit codes: 0 = patched (or nothing to do) / 1 = failure
# ==============================================================================
set -u

HERE="$(cd "$(dirname "$0")" && pwd -P)"
P2S_ROOT="$(cd "$HERE/.." && pwd -P)"
. "$P2S_ROOT/lib/common.sh"

PATCH_UPSTREAM="$HERE/brotli/upstream-brotli-CVE-2026-111497-1.2.0-to-1.2.1.patch"
PATCH_BACKPORT="$HERE/brotli/backport-brotli-CVE-2026-111497-1.0.x.patch"

TARGETS=""
FIND_UNDER=""
DRY=0; FUZZ=0; VERIFY=0; BUILD=0; REVERT=0; FORCE=0

usage() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --find-under) shift; FIND_UNDER="${1:-}"; [ -n "$FIND_UNDER" ] || die "--find-under needs a directory" ;;
    --dry-run)    DRY=1 ;;
    --fuzz)       FUZZ=1 ;;
    --verify)     VERIFY=1 ;;
    --build)      BUILD=1 ;;
    --revert)     REVERT=1 ;;
    --force)      FORCE=1 ;;
    --help|-h)    usage; exit 0 ;;
    -*)           die "unknown option: $1 (try --help)" ;;
    *)            TARGETS="$TARGETS $1" ;;
  esac
  shift
done

[ "$DRY" = 1 ] && P2S_DRY_RUN=1

# ------------------------------------------------------------------------------
# tree discovery / identification
# ------------------------------------------------------------------------------
brotli_version_of() { # <tree> -> x.y.z or empty
  local f="$1/c/common/version.h" maj min pat hex val
  [ -f "$f" ] || return 1
  maj="$(sed -n 's/^#define BROTLI_VERSION_MAJOR \([0-9]*\).*/\1/p' "$f" | head -1)"
  if [ -n "$maj" ]; then
    min="$(sed -n 's/^#define BROTLI_VERSION_MINOR \([0-9]*\).*/\1/p' "$f" | head -1)"
    pat="$(sed -n 's/^#define BROTLI_VERSION_PATCH \([0-9]*\).*/\1/p' "$f" | head -1)"
    printf '%s.%s.%s\n' "$maj" "${min:-0}" "${pat:-0}"
    return 0
  fi
  # Brotli <= 1.0.x encodes the whole version in one hex macro:
  #   #define BROTLI_VERSION 0x1000009   ->  1.0.9
  hex="$(sed -n 's/^#define BROTLI_VERSION \(0x[0-9a-fA-F]*\).*/\1/p' "$f" | head -1)"
  [ -n "$hex" ] || return 1
  val=$((hex))
  printf '%s.%s.%s\n' "$(( (val >> 24) & 255 ))" "$(( (val >> 12) & 4095 ))" "$(( val & 4095 ))"
}

find_trees() { # <dir> -> brotli source roots
  [ -d "$1" ] || return 0
  find "$1" -maxdepth 6 -type f -path '*/c/common/version.h' 2>/dev/null \
    | while IFS= read -r f; do
        printf '%s\n' "$(dirname "$(dirname "$(dirname "$f")")")"
      done | sort -u
}

# ------------------------------------------------------------------------------
# patch selection
# ------------------------------------------------------------------------------
# Prints "PATCH|<path>" or "SKIP|<reason>".  Deliberately not a return-code +
# global pair: callers use command substitution, which runs in a subshell, so a
# global assigned in here would never reach them (and `set -u` would abort on
# the read).  One line out, one parse in.
select_patch() { # <version>
  local v="$1"
  if version_ge "$v" 1.2.1; then printf '%s' "SKIP|already fixed ($v)"; return 0; fi
  if version_ge "$v" 1.1.0; then printf 'PATCH|%s' "$PATCH_UPSTREAM"; return 0; fi
  if version_ge "$v" 1.0.3; then printf 'PATCH|%s' "$PATCH_BACKPORT"; return 0; fi
  printf '%s' "SKIP|$v predates the affected range (1.0.3+)"
}

# ------------------------------------------------------------------------------
# apply
# ------------------------------------------------------------------------------
apply_one() { # <tree>
  local tree="$1" ver patch sel fuzzflag rc
  ver="$(brotli_version_of "$tree")" || {
    err "$tree does not look like a Brotli source tree (no c/common/version.h)"
    return 1
  }
  info "target tree: $tree  (Brotli $ver)"

  if [ "$REVERT" = 1 ]; then
    for patch in "$PATCH_UPSTREAM" "$PATCH_BACKPORT"; do
      [ -f "$patch" ] || continue
      if ( cd "$tree" && patch -p1 -R --forward --dry-run < "$patch" ) >/dev/null 2>&1; then
        step "Reverting $(basename "$patch")"
        if [ "$DRY" = 1 ]; then
          ( cd "$tree" && patch -p1 -R --forward --dry-run < "$patch" )
        else
          ( cd "$tree" && patch -p1 -R --forward < "$patch" ) \
            && ok "reverted in $tree" || { err "revert failed"; return 1; }
        fi
        return 0
      fi
    done
    warn "no bundled Brotli patch applies in reverse to $tree — nothing to revert"
    return 0
  fi

  sel="$(select_patch "$ver")"
  case "$sel" in
    'SKIP|'*)
      ok "$tree — $(printf '%s' "$sel" | cut -d'|' -f2-); no patch needed"
      [ "$VERIFY" = 1 ] && verify_tree "$tree"
      return 0 ;;
    'PATCH|'*)
      patch="$(printf '%s' "$sel" | cut -d'|' -f2-)" ;;
    *)
      err "internal: unexpected patch selection '$sel'"; return 1 ;;
  esac

  if grep -qs 'BROTLI_SAFE_WITH_STATUS' "$tree/c/dec/decode.c" && [ "$FORCE" != 1 ]; then
    ok "$tree already contains the fix (BROTLI_SAFE_WITH_STATUS present) — skipping"
    [ "$VERIFY" = 1 ] && verify_tree "$tree"
    return 0
  fi

  step "Applying $(basename "$patch") to $tree"
  fuzzflag="--fuzz=0"
  [ "$FUZZ" = 1 ] && fuzzflag="--fuzz=3"

  if [ "$DRY" = 1 ]; then
    if ( cd "$tree" && patch -p1 --forward --dry-run $fuzzflag < "$patch" ); then
      ok "[dry] patch applies cleanly"
      return 0
    fi
    if [ "$FUZZ" != 1 ] && ( cd "$tree" && patch -p1 --forward --dry-run --fuzz=3 < "$patch" ); then
      warn "[dry] applies only with fuzz — re-run with --fuzz to accept offsets"
      return 1
    fi
    err "[dry] patch does NOT apply to $tree"
    return 1
  fi

  # keep .orig copies so a revert is possible without git
  rc=0
  ( cd "$tree" && patch -p1 --forward -b $fuzzflag < "$patch" ) || rc=$?
  if [ "$rc" != 0 ]; then
    if [ "$FUZZ" != 1 ]; then
      warn "strict apply failed — retrying with --fuzz=3"
      ( cd "$tree" && patch -p1 --forward -b --fuzz=3 < "$patch" ) || rc=$?
    fi
  fi
  if [ "$rc" != 0 ]; then
    err "patch failed on $tree — inspect the reject files"
    return 1
  fi
  ok "patched $tree"

  [ "$VERIFY" = 1 ] && { verify_tree "$tree" || return 1; }
  [ "$BUILD" = 1 ] && rebuild_tree "$tree"
  return 0
}

# ------------------------------------------------------------------------------
# verification — source assertions plus a real compile of the decoder
# ------------------------------------------------------------------------------
verify_tree() { # <tree>
  local tree="$1" rc=0 tmp
  step "Verifying $tree"
  if grep -q 'BROTLI_SAFE_WITH_STATUS' "$tree/c/dec/decode.c"; then
    ok "decode.c propagates block-switch status (BROTLI_SAFE_WITH_STATUS)"
  else
    err "decode.c does not contain BROTLI_SAFE_WITH_STATUS"; rc=1
  fi
  if grep -q 'BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH' "$tree/c/dec/decode.c"; then
    ok "decode.c returns BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH"
  else
    err "decode.c does not return FORMAT_BLOCK_SWITCH"; rc=1
  fi
  if grep -q '_ERROR_FORMAT_, BLOCK_SWITCH, -17' "$tree/c/include/brotli/decode.h"; then
    ok "decode.h defines error code -17 (BLOCK_SWITCH)"
  else
    err "decode.h does not define -17"; rc=1
  fi

  if have_cmd gcc || have_cmd cc; then
    tmp="$(mktemp -d "${TMPDIR:-/tmp}/p2s-brotli.XXXXXX")"
    if ( comp="$(command -v gcc || command -v cc)"; \
         "$comp" -O2 -fsyntax-only -I "$tree/c/include" "$tree/c/dec/decode.c" ) 2>"$tmp/err"; then
      ok "decoder compiles against the patched headers"
    else
      err "decoder does not compile — see $tmp/err"
      sed 's/^/      /' "$tmp/err" | head -20
      rc=1
    fi
    rm -rf "$tmp"
  else
    warn "no C compiler available — skipped the compile check"
  fi
  [ "$rc" = 0 ] && ok "verification passed for $tree"
  return "$rc"
}

rebuild_tree() { # <tree>
  local tree="$1"
  if ! have_cmd cmake; then
    warn "cmake not found — rebuild manually:"
    warn "  cd $tree && cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"
    return 1
  fi
  step "Rebuilding $tree"
  ( cd "$tree" && cmake -B build -DCMAKE_BUILD_TYPE=Release >/dev/null \
      && cmake --build build -j"$(nproc 2>/dev/null || echo 2)" ) \
    && ok "built $tree/build" || { err "build failed — inspect $tree"; return 1; }
  warn "a rebuild is not a deployment: reinstall the artifact and RESTART every"
  warn "process that loaded the old library (containers must be rebuilt, not restarted"
  warn "from a cached layer)."
}

# ------------------------------------------------------------------------------
# main
# ------------------------------------------------------------------------------
ALL=""
if [ -n "$FIND_UNDER" ]; then
  [ -d "$FIND_UNDER" ] || die "--find-under '$FIND_UNDER' does not exist"
  step "Searching for Brotli source trees under $FIND_UNDER"
  found="$(find_trees "$FIND_UNDER")"
  if [ -z "$found" ]; then
    warn "no Brotli source trees found under $FIND_UNDER"
    exit 0
  fi
  printf '%s\n' "$found" | sed 's/^/  /'
  ALL="$ALL
$found"
fi
for t in $TARGETS; do
  [ -d "$t" ] || die "not a directory: $t"
  ALL="$ALL
$t"
done

ALL="$(printf '%s\n' "$ALL" | grep -v '^$' | sort -u)"
[ -n "$ALL" ] || { usage; exit 1; }

failed=0
for tree in $ALL; do
  apply_one "$tree" || failed=$((failed+1))
done

step "Summary"
if [ "$failed" -gt 0 ]; then
  err "$failed tree(s) failed — nothing was silently skipped"
  exit 1
fi
ok "all targets processed"
info "next: rebuild/redeploy the artifact, then restart every process that loaded it."
exit 0
