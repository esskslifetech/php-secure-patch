#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: rollback.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Restore a backup set created by setup.sh --fix/--contain (every modified file
# is recorded in MANIFEST.txt, every created file in CREATED.txt, and every
# quarantined file in QUARANTINED.txt), then recycle PHP workers again.
#
# Usage:
#   ./rollback.sh               # newest backup set
#   ./rollback.sh <backup-dir>  # specific set (see /var/backups/protection2shell/)
#   ./rollback.sh --list        # show available sets
# ==============================================================================
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
. "$P2S_ROOT/lib/common.sh"
. "$P2S_ROOT/lib/detect.sh"

# New location first; falls back to the php-secure-patch v1.x tree so backup
# sets taken before the rename stay restorable.
base="$(p2s_backup_base)"

case "${1:-}" in
  --list)
    step "Backup sets under $base"
    ls -1d "$base"/*/ 2>/dev/null || info "(none yet — run setup.sh --fix first)"
    exit 0
    ;;
  "")
    TARGET="$(ls -1d "$base"/*/ 2>/dev/null | tail -1 | sed 's:/$::')"
    [ -n "$TARGET" ] || die "no backup sets under $base — nothing to roll back"
    ;;
  *)
    TARGET="${1%/}"
    [ -d "$TARGET" ] || die "no such backup set: $TARGET"
    ;;
esac

step "Rolling back: $TARGET"
P2S_BACKUP_DIR="$TARGET"
restore_backups

step "Recycling PHP workers"
detect_php_all
detect_fpm
detect_webservers
for p in ${FPM_RECS[@]+"${FPM_RECS[@]}"}; do svc_restart "$(basename "$(printf '%s' "$p" | cut -d'|' -f1)")"; done
[ "$APACHE_PRESENT" = 1 ] && { svc_restart apache2; svc_restart httpd; }
[ "$NGINX_PRESENT" = 1 ] && svc_restart nginx
ok "rollback complete"
