#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: rollback.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Restore a backup set created by setup.sh --fix (every modified file is
# recorded in <backup>/MANIFEST.txt), then recycle PHP workers again.
#
# Usage:
#   ./rollback.sh               # newest backup set
#   ./rollback.sh <backup-dir>  # specific set (see /var/backups/php-secure-patch/)
#   ./rollback.sh --list        # show available sets
# ==============================================================================
set -u
PSP_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
. "$PSP_ROOT/lib/common.sh"
. "$PSP_ROOT/lib/detect.sh"

if [ "$(id -u)" != 0 ]; then
  base="$HOME/.php-secure-patch/backups"
else
  base="/var/backups/php-secure-patch"
fi

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
PSP_BACKUP_DIR="$TARGET"
restore_backups

step "Recycling PHP workers"
detect_php_all
detect_fpm
detect_webservers
for p in ${FPM_RECS[@]+"${FPM_RECS[@]}"}; do svc_restart "$(basename "$(printf '%s' "$p" | cut -d'|' -f1)")"; done
[ "$APACHE_PRESENT" = 1 ] && { svc_restart apache2; svc_restart httpd; }
[ "$NGINX_PRESENT" = 1 ] && svc_restart nginx
ok "rollback complete"
