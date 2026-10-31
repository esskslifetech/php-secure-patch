#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: install.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Installs the toolkit system-wide so it can be run as `php-secure-patch` from
# anywhere (cron, CI, other admins).  Pure file copies + a wrapper — nothing is
# compiled, nothing else is touched.
#
#   sudo ./install.sh                 # install to /opt/php-secure-patch
#   sudo ./install.sh --prefix /usr/local
#   sudo ./install.sh --uninstall     # remove again
# ==============================================================================
set -u
PSP_ROOT="$(cd "$(dirname "$0")" && pwd -P)"
. "$PSP_ROOT/lib/common.sh"

PREFIX="/opt"
UNINSTALL=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)    shift; PREFIX="${1:-/opt}" ;;
    --uninstall) UNINSTALL=1 ;;
    --help|-h)   awk 'NR>1 { if (/^# =+$/ && ++r == 2) exit; sub(/^# ?/, ""); print }' "$0"
                 exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

DEST="$PREFIX/php-secure-patch"
BIN=/usr/local/bin

if [ "$UNINSTALL" = 1 ]; then
  step "Uninstalling"
  rm -f "$BIN/php-secure-patch" "$BIN/php-secure-patch-rollback" "$BIN/php-secure-patch-hunt"
  rm -rf "$DEST"
  ok "removed $DEST and wrappers from $BIN"
  exit 0
fi

[ "$(id -u)" = 0 ] || die "run as root (installs into $PREFIX and $BIN)"

step "Installing to $DEST"
mkdir -p "$DEST"
cp -R "$PSP_ROOT/lib" "$PSP_ROOT/patches" "$PSP_ROOT/hardening" \
      "$PSP_ROOT/scanner" "$PSP_ROOT/hunt" "$PSP_ROOT/tests" "$DEST/"
cp "$PSP_ROOT/setup.sh" "$PSP_ROOT/rollback.sh" "$PSP_ROOT/install.sh" \
   "$PSP_ROOT/README.md" "$PSP_ROOT/SECURITY-RESEARCH.md" "$DEST/"
chmod +x "$DEST/setup.sh" "$DEST/rollback.sh" "$DEST/patches/apply-source-patches.sh" \
         "$DEST/tests/run-tests.sh" "$DEST/hunt/hunt.sh"

cat > "$BIN/php-secure-patch" <<EOF
#!/bin/sh
exec "$DEST/setup.sh" "\$@"
EOF
cat > "$BIN/php-secure-patch-rollback" <<EOF
#!/bin/sh
exec "$DEST/rollback.sh" "\$@"
EOF
cat > "$BIN/php-secure-patch-hunt" <<EOF
#!/bin/sh
exec "$DEST/hunt/hunt.sh" "\$@"
EOF
chmod +x "$BIN/php-secure-patch" "$BIN/php-secure-patch-rollback" "$BIN/php-secure-patch-hunt"

ok "installed. Try:  php-secure-patch   |   php-secure-patch --fix   |   php-secure-patch-hunt"
info "cron example (nightly audit, mail on exposure):"
info "  15 3 * * * root $BIN/php-secure-patch --json /var/log/php-secure-patch.json || echo PHP exposure | mail -s alert admin@example.com"
