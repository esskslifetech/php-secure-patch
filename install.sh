#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: install.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Installs the toolkit system-wide so it can be run as `protection2shell` from
# anywhere (cron, CI, other admins), and optionally schedules it so containment
# is re-asserted instead of applied once and forgotten.
# Pure file copies + wrappers — nothing is compiled, nothing else is touched.
#
#   sudo ./install.sh                 # install to /opt/protection2shell, wrappers in /usr/local/bin
#   sudo ./install.sh --prefix /usr/local
#   ./install.sh --prefix ~/.local/share/protection2shell --bin ~/.local/bin
#                                     # no root needed: user-level install
#   sudo ./install.sh --timer         # + daily containment re-assertion (systemd)
#   sudo ./install.sh --timer auto    # + daily contain+fix+verify (unattended)
#   sudo ./install.sh --uninstall     # remove wrappers, timer, cron entry
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
. "$P2S_ROOT/lib/common.sh"

usage() { awk 'NR == 1 { next } /^# ?--- end of help ---/ { exit } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; }

PREFIX="/opt"
UNINSTALL=0
TIMER=0
TIMER_MODE="contain"
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix)    shift; PREFIX="${1:-/opt}" ;;
    --bin)       shift; BIN="${1:-}" ; [ -n "$BIN" ] || die "--bin needs a directory" ;;
    --uninstall) UNINSTALL=1 ;;
    --timer)
      TIMER=1
      case "${2:-}" in
        audit|contain|auto) TIMER_MODE="$2"; shift ;;
      esac
      ;;
    --help|-h)   usage; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

DEST="$PREFIX/protection2shell"
BIN="${BIN:-/usr/local/bin}"
UNIT_DIR=/etc/systemd/system
CRON_FILE=/etc/cron.d/protection2shell
LOG_DIR=/var/log/protection2shell

# ------------------------------------------------------------------------------
remove_timer() {
  local removed=0
  if [ -f "$UNIT_DIR/protection2shell.timer" ]; then
    have_cmd systemctl && systemctl disable --now protection2shell.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/protection2shell.timer" "$UNIT_DIR/protection2shell.service"
    removed=1
  fi
  if [ -f "$CRON_FILE" ]; then
    rm -f "$CRON_FILE"
    removed=1
  fi
  have_cmd systemctl && systemctl daemon-reload >/dev/null 2>&1 || true
  [ "$removed" = 1 ] && ok "removed scheduled runs" || debug "no scheduled run found"
}

if [ "$UNINSTALL" = 1 ]; then
  step "Uninstalling protection2shell"
  remove_timer
  rm -f "$BIN/protection2shell" "$BIN/protection2shell-rollback" "$BIN/protection2shell-hunt"
  # legacy wrappers from the php-secure-patch era (only if they point at us)
  for legacy in "$BIN/php-secure-patch" "$BIN/php-secure-patch-rollback" "$BIN/php-secure-patch-hunt"; do
    [ -e "$legacy" ] && rm -f "$legacy"
  done
  rm -rf "$DEST"
  ok "removed $DEST and wrappers from $BIN"
  exit 0
fi

# Root is not required when both targets are writable by this user. The old
# check demanded root unconditionally, so a user install died with one line and
# no way forward — the most common "it will not install" case.
if [ "$(id -u)" != 0 ]; then
  if ! mkdir -p "$DEST" 2>/dev/null || ! mkdir -p "$BIN" 2>/dev/null; then
    die "cannot write $DEST or $BIN as $(id -un).
       Either run it with sudo:
         sudo ./install.sh --prefix $PREFIX --bin $BIN
       or install just for this user (no root):
         ./install.sh --prefix \"\$HOME/.local/share/protection2shell\" --bin \"\$HOME/.local/bin\""
  fi
fi

if [ "$TIMER" = 1 ] && [ "$(id -u)" != 0 ]; then
  die "--timer writes /etc/systemd/system and /etc/cron.d, so it needs sudo:
       sudo ./install.sh --prefix $PREFIX --bin $BIN --timer"
fi

step "Installing to $DEST"
mkdir -p "$DEST"
cp -R "$P2S_ROOT/lib" "$P2S_ROOT/patches" "$P2S_ROOT/hardening" \
      "$P2S_ROOT/contain" "$P2S_ROOT/scanner" "$P2S_ROOT/hunt" "$P2S_ROOT/tests" "$DEST/"
cp "$P2S_ROOT/setup.sh" "$P2S_ROOT/rollback.sh" "$P2S_ROOT/install.sh" \
   "$P2S_ROOT/README.md" "$P2S_ROOT/SECURITY-RESEARCH.md" "$DEST/"
for extra in LICENSE CHANGELOG.md INSTALL.md SECURITY.md CONTRIBUTING.md; do
  [ -f "$P2S_ROOT/$extra" ] && cp "$P2S_ROOT/$extra" "$DEST/"
done
if [ -d "$P2S_ROOT/docs" ]; then
  mkdir -p "$DEST/docs" && cp -R "$P2S_ROOT/docs/." "$DEST/docs/"
fi
chmod +x "$DEST/setup.sh" "$DEST/rollback.sh" \
         "$DEST/patches/apply-source-patches.sh" "$DEST/patches/apply-brotli-patch.sh" \
         "$DEST/tests/run-tests.sh" "$DEST/hunt/hunt.sh"

# `exec bash <script>` instead of executing the file directly: an archive
# extracted on Windows or copied through a zip loses the exec bit, and the
# wrapper would then fail with "Permission denied" for every command.
cat > "$BIN/protection2shell" <<EOF
#!/bin/sh
exec bash "$DEST/setup.sh" "\$@"
EOF
cat > "$BIN/protection2shell-rollback" <<EOF
#!/bin/sh
exec bash "$DEST/rollback.sh" "\$@"
EOF
cat > "$BIN/protection2shell-hunt" <<EOF
#!/bin/sh
exec bash "$DEST/hunt/hunt.sh" "\$@"
EOF
chmod +x "$BIN/protection2shell" "$BIN/protection2shell-rollback" "$BIN/protection2shell-hunt"

# ------------------------------------------------------------------------------
# legacy names: v1.x was php-secure-patch. Existing cron jobs and runbooks keep
# working for one release cycle instead of silently failing after the rename.
# ------------------------------------------------------------------------------
for pair in "php-secure-patch:protection2shell" \
            "php-secure-patch-rollback:protection2shell-rollback" \
            "php-secure-patch-hunt:protection2shell-hunt"; do
  legacy="${pair%%:*}"; current="${pair##*:}"
  if [ -e "$BIN/$legacy" ] && [ ! -L "$BIN/$legacy" ]; then
    warn "$BIN/$legacy exists and is not a symlink — leaving it alone"
    continue
  fi
  ln -sfn "$current" "$BIN/$legacy" && info "legacy alias: $legacy -> $current"
done

# ------------------------------------------------------------------------------
# scheduled re-assertion
# ------------------------------------------------------------------------------
schedule_timer() {
  mkdir -p "$LOG_DIR" || die "cannot create $LOG_DIR"
  case "$TIMER_MODE" in
    audit)   cmd="--json $LOG_DIR/report.json" ;;
    auto)    cmd="--auto --json $LOG_DIR/report.json" ;;
    *)       cmd="--contain --yes --json $LOG_DIR/report.json" ;;
  esac

  if have_cmd systemctl && [ -d "$UNIT_DIR" ]; then
    step "Installing systemd timer (mode: $TIMER_MODE)"
    cat > "$UNIT_DIR/protection2shell.service" <<EOF
[Unit]
Description=protection2shell — PHP2Shell/HTTP2Shell containment and audit
Documentation=file://$DEST/README.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN/protection2shell $cmd
# auditing is read-only in default mode; --contain rewrites documented config
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
EOF
    cat > "$UNIT_DIR/protection2shell.timer" <<EOF
[Unit]
Description=Daily protection2shell run (containment is re-asserted, not assumed)

[Timer]
OnBootSec=10min
OnUnitActiveSec=24h
RandomizedDelaySec=15min
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable --now protection2shell.timer >/dev/null 2>&1 \
      && ok "timer enabled: protection2shell.timer (daily, mode $TIMER_MODE)" \
      || { err "could not enable the timer — run: systemctl enable --now protection2shell.timer"; return 1; }
    return 0
  fi

  step "No systemd — falling back to cron (mode: $TIMER_MODE)"
  cat > "$CRON_FILE" <<EOF
# protection2shell — daily containment re-assertion (installed $(date -u +%F))
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
17 4 * * * root $BIN/protection2shell $cmd >/dev/null 2>&1
@reboot   root sleep 600 && $BIN/protection2shell $cmd >/dev/null 2>&1
EOF
  chmod 644 "$CRON_FILE"
  ok "cron entry installed: $CRON_FILE"
}

[ "$TIMER" = 1 ] && { schedule_timer || true; }

ok "installed. Try:"
case ":$PATH:" in
  *":$BIN:"*) ;;
  *) warn "$BIN is not in your PATH — add it:  export PATH=\"\$PATH:$BIN\"" ;;
esac
info "  protection2shell                 # audit this host (read-only)"
info "  protection2shell --contain       # cut the exploit channel now"
info "  protection2shell --auto          # contain + fix + verify, unattended"
info "  protection2shell-hunt            # post-patch compromise hunt"
info "  protection2shell-rollback --list"
info "legacy command names (php-secure-patch*) still work via symlinks."
