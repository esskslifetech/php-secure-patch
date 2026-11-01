#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: bootstrap (one-line installer)
#
#   curl -fsSL http://HOST:PORT/install.sh | bash -s -- http://HOST:PORT
#   wget -qO- http://HOST:PORT/install.sh | bash -s -- http://HOST:PORT
#
# Downloads the release zip, verifies its SHA-256, extracts it, and runs a
# read-only audit. Add --auto to follow with containment + fixes (needs sudo).
#
#   --dir DIR     extract here (default: ./protection2shell-<version>)
#   --auto        after extracting, run: sudo bash setup.sh --auto
#   --zip PATH    install from a local zip instead of downloading
#
# Environment: P2S_BASE_URL (instead of the positional URL), P2S_VERSION.
#
# Serve it next to the release zip (this is what the download page runs), or
# point it at any mirror:
#   bash scripts/bootstrap-install.sh --dir /opt/src https://mirror.example/p2s
# It refuses a non-zip response (proxies and captive portals answer 200 with
# HTML) and verifies SHA256SUMS before extracting anything.
# ==============================================================================
set -uo pipefail

VERSION="${P2S_VERSION:-2.0.1}"
ZIP="protection2shell-${VERSION}.zip"
BASE="${P2S_BASE_URL:-}"
DEST=""
AUTO=0
LOCAL_ZIP=""

while [ $# -gt 0 ]; do
  case "$1" in
    --dir) shift; DEST="${1:-}" ;;
    --auto) AUTO=1 ;;
    --zip) shift; LOCAL_ZIP="${1:-}" ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    http://*|https://*) BASE="$1" ;;
    *) echo "unknown argument: $1 (try --help)" >&2; exit 1 ;;
  esac
  shift
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/p2s-bootstrap.XXXXXX")" || die "cannot create a temp dir"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- helpers
fetch_to() { # <url> <dest>  -> 0 only when the body was written
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --max-time 300 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 300 -O "$2" "$1"
  else
    return 127
  fi
}

sha256_of() { # <file> -> hex, or empty when no tool is available
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r "$1" | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------- fetch
if [ -n "$LOCAL_ZIP" ]; then
  [ -f "$LOCAL_ZIP" ] || die "no such file: $LOCAL_ZIP"
  cp "$LOCAL_ZIP" "$TMP/$ZIP" || die "cannot read $LOCAL_ZIP"
  say "using local archive: $LOCAL_ZIP"
else
  [ -n "$BASE" ] || die "no download URL given, e.g.
       curl -fsSL http://host:8000/install.sh | bash -s -- http://host:8000"
  command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 \
    || die "need curl or wget to download — or pass --zip <local file>"
  BASE="${BASE%/}"
  say "downloading $BASE/$ZIP"
  fetch_to "$BASE/$ZIP" "$TMP/$ZIP" || die "download failed: $BASE/$ZIP"
  [ -s "$TMP/$ZIP" ] || die "downloaded file is empty"

  # A proxy, a captive portal or a wrong URL usually answers 200 with HTML.
  # Reject anything that is not a zip before it reaches the filesystem.
  if [ "$(head -c 2 "$TMP/$ZIP" | od -An -tx1 | tr -d ' \n')" != "504b" ]; then
    die "that URL did not return a zip. First bytes: $(head -c 60 "$TMP/$ZIP" | tr -d '\0' | tr '\n' ' ')
       If a proxy is interfering, download the zip in a browser, then run:
         bash install.sh --zip $ZIP"
  fi

  if fetch_to "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
    WANT="$(awk -v f="$ZIP" '$2 == f || $2 == "*"f {print $1}' "$TMP/SHA256SUMS" | head -1)"
    GOT="$(sha256_of "$TMP/$ZIP")"
    if [ -n "$WANT" ] && [ -n "$GOT" ]; then
      [ "$WANT" = "$GOT" ] || die "checksum mismatch — expected $WANT, got $GOT"
      ok "checksum verified ($GOT)"
    else
      warn "no checksum comparison possible (missing entry or sha tool)"
    fi
  else
    warn "SHA256SUMS unavailable — continuing without checksum verification"
  fi
fi

# ---------------------------------------------------------------- extract
DEST="${DEST:-$PWD/protection2shell-$VERSION}"
mkdir -p "$DEST" || die "cannot create $DEST"
say "extracting to $DEST"
if command -v unzip >/dev/null 2>&1; then
  unzip -q -o "$TMP/$ZIP" -d "$DEST" || die "unzip failed"
elif command -v python3 >/dev/null 2>&1; then
  python3 -m zipfile -e "$TMP/$ZIP" "$DEST" || die "python zipfile extraction failed"
else
  die "need unzip or python3 to extract the archive"
fi

ROOT="$DEST/protection2shell-$VERSION"
[ -f "$ROOT/setup.sh" ] || ROOT="$DEST"
[ -f "$ROOT/setup.sh" ] || die "extraction produced no setup.sh — the archive is incomplete"
chmod +x "$ROOT/setup.sh" "$ROOT/rollback.sh" "$ROOT/install.sh" \
         "$ROOT/hunt/hunt.sh" "$ROOT/patches/"*.sh 2>/dev/null
ok "extracted: $ROOT"

# ---------------------------------------------------------------- run
rc=0
if [ "$AUTO" = 1 ]; then
  if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
    RUN=""
  elif command -v sudo >/dev/null 2>&1; then
    RUN="sudo"
  else
    die "--auto needs root and this host has no sudo.
       Run the read-only audit instead:  cd '$ROOT' && bash setup.sh"
  fi
  say "contain + fix + verify (rewrites config; every file is backed up)"
  ( cd "$ROOT" && $RUN bash setup.sh --auto --yes ) || rc=$?
else
  say "read-only audit"
  ( cd "$ROOT" && bash setup.sh ) || rc=$?
fi

cat <<EOF

Installed at:  $ROOT
Next:
  cd "$ROOT"
  bash setup.sh                 # audit again any time
  sudo bash setup.sh --auto     # contain + fix + verify
  sudo ./install.sh             # optional: on PATH, daily containment timer

Exit code $rc: 0 = clean/fixed, 2 = exposure remains (read the report), 1 = error.
EOF
exit "$rc"
