#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/detect_brotli.sh
# HTTP2Shell carrier detection.
#
# Brotli is C with no stable ABI, so almost nobody links it dynamically: Node
# vendors it at deps/brotli, Bun vendors it, ClickHouse keeps a fork pinned at
# 1.2.0, Arrow pins 1.0.9, DuckDB vendors 1.1.0, PHP extensions bundle it,
# curl for Windows statically links it.  Patching the OS libbrotli therefore
# fixes almost none of them.  Detection is consequently per *carrier*, not per
# package: we look for every decoder instance that a request could reach.
#
# Records: BROTLI_RECS[] = carrier|name|version|path|evidence|certainty
#   carrier   libbrotli | node | bun | brotli | brotlicffi | envoy | dotnet |
#             curl | php | vendor
#   evidence  human string: what we actually observed (incl. capability probe)
#   certainty high | medium | low  — see brotli_certainty()
# ==============================================================================

[ -n "${P2S_DETECT_BROTLI_LOADED:-}" ] && return 0
P2S_DETECT_BROTLI_LOADED=1

BROTLI_RECS=()
P2S_BROTLI_SCAN_ROOTS=()
P2S_NODE_SERVICES=()

_brotli_sanitize() { printf '%s' "$1" | tr '|' '/' | tr '\n' ' '; }

_brotli_record() { # carrier name version path evidence certainty
  local carrier="$1" name="$2" ver="$3" path="$4" ev="$5" cert="$6" r c2 p2 v2
  ev="$(_brotli_sanitize "$ev")"
  name="$(_brotli_sanitize "$name")"
  path="$(_brotli_sanitize "$path")"
  for r in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    c2="$(printf '%s' "$r" | cut -d'|' -f1)"
    p2="$(printf '%s' "$r" | cut -d'|' -f4)"
    v2="$(printf '%s' "$r" | cut -d'|' -f3)"
    [ "$c2" = "$carrier" ] && [ "$p2" = "$path" ] && [ "$v2" = "$ver" ] && return 0
  done
  BROTLI_RECS[${#BROTLI_RECS[@]}]="$carrier|$name|$ver|$path|$ev|$cert"
  debug "brotli carrier: $carrier $name $ver ($path) marker-evidence=$ev"
}

# ------------------------------------------------------------------------------
# package version lookups (version *evidence*, never proof)
# ------------------------------------------------------------------------------
brotli_pkg_version() { # <package-name> -> version string or empty
  local p="$1"
  if have_cmd dpkg-query; then
    dpkg-query -W -f='${Version}\n' "$p" 2>/dev/null | head -1 | grep -v '^$'
  elif have_cmd rpm; then
    rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$p" 2>/dev/null | head -1 \
      | grep -v 'not installed' | grep -v '^$'
  elif have_cmd apk; then
    apk info -v "$p" 2>/dev/null | head -1 | sed "s/^$p-//" | grep -v '^$'
  elif have_cmd pacman; then
    pacman -Q "$p" 2>/dev/null | awk '{print $2}'
  elif have_cmd brew; then
    brew list --versions "$p" 2>/dev/null | awk '{print $2}'
  fi
}

_brotli_pkg_any() { # <pkg...> -> first version found
  local p v
  for p in "$@"; do
    v="$(brotli_pkg_version "$p")"
    [ -n "$v" ] && { printf '%s' "$v"; return 0; }
  done
  return 1
}

# ------------------------------------------------------------------------------
# 1. libbrotli (the shared library itself)
# ------------------------------------------------------------------------------
detect_brotli_lib() {
  local files="" f v marker cert ev pkgver
  if have_cmd ldconfig; then
    files="$(ldconfig -p 2>/dev/null | awk '/libbrotli(decomp|dec|common)/ {print $NF}' | sort -u)"
  fi
  for f in /usr/lib/*/libbrotlidec.so* /usr/lib/libbrotlidec.so* \
           /usr/local/lib/libbrotlidec.so* /lib/*/libbrotlidec.so* \
           /opt/homebrew/lib/libbrotlidec.so* /usr/lib64/libbrotlidec.so*; do
    [ -e "$f" ] && files="$files
$f"
  done
  files="$(printf '%s\n' "$files" | grep -v '^$' | sort -u)"
  [ -n "$files" ] || { debug "no libbrotli shared library found"; return 0; }

  pkgver=""
  if have_cmd pkg-config; then
    pkgver="$(pkg-config --modversion libbrotlidec 2>/dev/null | head -1)"
  fi
  [ -n "$pkgver" ] || pkgver="$(_brotli_pkg_any libbrotli1 libbrotlidec1 libbrotli brotli-libs libbrotli-dev 2>/dev/null || true)"

  # Prefer a real file for the probe (the ldconfig list may name a symlink).
  f="$(printf '%s\n' "$files" | while IFS= read -r x; do [ -r "$x" ] && { printf '%s\n' "$x"; break; }; done)"
  [ -n "$f" ] || f="$(printf '%s\n' "$files" | head -1)"
  marker="$(brotli_marker_probe "$f")"

  if [ "$marker" = "present" ]; then
    cert="high"
    ev="capability marker $BROTLI_FIX_MARKER present in $f — this build carries the fix"
    # Report the fixed version when the package string is older than the fix
    # (distro backports keep the upstream version).
    [ -n "$pkgver" ] || pkgver="$FIX_BROTLI"
  else
    cert="$(brotli_certainty "$pkgver" "$marker")"
    if [ -n "$pkgver" ]; then
      ev="package version $pkgver; marker $marker (absence is not proof of vulnerability)"
    else
      ev="no version metadata; marker $marker"
    fi
  fi

  _brotli_record "libbrotli" "libbrotlidec" "${pkgver:-unknown}" "$f" "$ev" "$cert"
}

# ------------------------------------------------------------------------------
# 2. Node.js / Bun (vendored decoder inside the runtime)
# ------------------------------------------------------------------------------
node_candidates() {
  command -v node 2>/dev/null
  for f in /usr/bin/node /usr/local/bin/node /opt/homebrew/bin/node \
           /usr/local/nodejs/bin/node /opt/node/bin/node; do
    [ -x "$f" ] && printf '%s\n' "$f"
  done
  # nvm / n / asdf layouts (one level, no recursive find)
  for f in "${NVM_DIR:-$HOME/.nvm}"/versions/node/*/bin/node \
           /usr/local/n/versions/node/*/bin/node \
           "$HOME"/.asdf/installs/nodejs/*/bin/node \
           /opt/*/bin/node /opt/node*/bin/node; do
    [ -x "$f" ] && printf '%s\n' "$f"
  done
}

detect_brotli_node() {
  local bin ver brot marker cert ev seen=""
  while IFS= read -r bin; do
    [ -n "$bin" ] || continue
    case " $seen " in *" $bin "*) continue ;; esac
    seen="$seen $bin"
    ver="$("$bin" -v 2>/dev/null | head -1 | sed 's/^v//')"
    [ -n "$ver" ] || continue
    brot="$("$bin" -p 'process.versions.brotli' 2>/dev/null | head -1)"
    marker="$(brotli_marker_probe "$bin")"
    cert="$(brotli_certainty "$ver" "$marker")"
    ev="node reports process.versions.brotli=${brot:-unknown} (unreliable — patched builds still report 1.2.0); marker $marker"
    _brotli_record "node" "node $ver" "$ver" "$bin" "$ev" "$cert"
  done <<EOF
$(node_candidates | sort -u)
EOF
}

detect_brotli_bun() {
  local bin ver marker cert ev
  bin="$(command -v bun 2>/dev/null || true)"
  [ -n "$bin" ] || return 0
  ver="$("$bin" -v 2>/dev/null | head -1 | sed 's/^v//')"
  marker="$(brotli_marker_probe "$bin")"
  cert="$(brotli_certainty "$ver" "$marker")"
  ev="bun $ver; marker $marker; no process-wide decompression workaround exists (per-call decompress:false only)"
  _brotli_record "bun" "bun $ver" "$ver" "$bin" "$ev" "$cert"
}

# Nodes that are actually serving something: systemd units whose ExecStart
# mentions node/bun.  Reported (never auto-edited) so the operator knows what
# must be restarted after a rebuild.
detect_node_services() {
  P2S_NODE_SERVICES=()
  have_cmd systemctl || return 0
  local u line
  for u in $(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}'); do
    line="$(systemctl show -p ExecStart --value "$u" 2>/dev/null)"
    case "$line" in
      *node*|*bun*|*npm*|*pm2*|*nuxt*|*next*) P2S_NODE_SERVICES[${#P2S_NODE_SERVICES[@]}]="$u" ;;
    esac
  done
  [ "${#P2S_NODE_SERVICES[@]}" -gt 0 ] && \
    info "node/bun services that must be restarted after a rebuild: ${P2S_NODE_SERVICES[*]}"
}

# ------------------------------------------------------------------------------
# 3. Python (brotli / brotlicffi wheels vendor the C decoder)
# ------------------------------------------------------------------------------
python_candidates() {
  command -v python3 2>/dev/null
  command -v python 2>/dev/null
  for f in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 \
           /usr/bin/python3.[0-9]*; do
    [ -x "$f" ] && printf '%s\n' "$f"
  done
  # virtualenvs commonly live next to the app
  for f in "${P2S_BROTLI_SCAN_ROOTS[@]+${P2S_BROTLI_SCAN_ROOTS[@]}}"; do
    [ -d "$f" ] || continue
    find "$f" -maxdepth 4 -type f -path '*/bin/python3' 2>/dev/null
  done
}

detect_brotli_python() {
  local py out pkg ver moddir so marker cert ev urllib3
  while IFS= read -r py; do
    [ -n "$py" ] || continue
    [ -x "$py" ] || continue
    out="$("$py" - 2>/dev/null <<'PYEOF'
import sys
def ver(mod):
    try:
        m = __import__(mod)
    except Exception:
        return None
    return getattr(m, "__version__", "unknown")
for name in ("brotli", "brotlicffi", "urllib3", "httpx", "aiohttp", "requests"):
    v = ver(name)
    if v is not None:
        print(name + "=" + str(v))
PYEOF
)"
    [ -n "$out" ] || continue
    urllib3="$(printf '%s\n' "$out" | awk -F= '$1=="urllib3"{print $2; exit}')"
    for pkg in brotli brotlicffi; do
      ver="$(printf '%s\n' "$out" | awk -F= -v p="$pkg" '$1==p{sub(/^[^=]*=/,""); print; exit}')"
      [ -n "$ver" ] || continue
      moddir="$("$py" - 2>/dev/null <<PYEOF
try:
    import $pkg, os
    print(os.path.dirname(getattr($pkg, "__file__", "") or ""))
except Exception:
    pass
PYEOF
)"
      so=""
      case "$moddir" in
        "") : ;;
        *) so="$(ls "$moddir"/*.so "$moddir"/*.pyd 2>/dev/null | head -1)" ;;
      esac
      marker="$(brotli_marker_probe "${so:-$moddir}")"
      cert="$(brotli_certainty "$ver" "$marker")"
      ev="python $pkg $ver; urllib3=${urllib3:-absent}; marker $marker"
      [ -n "$urllib3" ] && ev="$ev (urllib3 auto-decodes br responses once brotli is installed)"
      _brotli_record "$pkg" "$pkg $ver" "$ver" "$py" "$ev" "$cert"
    done
  done <<EOF
$(python_candidates | sort -u)
EOF
}

# ------------------------------------------------------------------------------
# 4. Envoy / Istio, .NET, curl, PHP extension
# ------------------------------------------------------------------------------
detect_brotli_envoy() {
  local bin ver
  bin="$(command -v envoy 2>/dev/null || true)"
  if [ -n "$bin" ]; then
    ver="$("$bin" --version 2>/dev/null | head -1 | sed -n 's/.*version: *\([0-9][0-9.]*\).*/\1/p')"
    [ -n "$ver" ] || ver="unknown"
    if grep -qsE 'brotli' /etc/envoy /etc/istio 2>/dev/null; then
      _brotli_record "envoy" "envoy $ver" "$ver" "$bin" \
        "brotli decompressor referenced in /etc/envoy or /etc/istio — decompression is an entry point" "medium"
    else
      _brotli_record "envoy" "envoy $ver" "$ver" "$bin" \
        "no brotli decompressor found in /etc/envoy or /etc/istio (compressor-only is not an entry point)" "low"
    fi
  fi
  if [ -d /etc/istio ]; then
    _brotli_record "envoy" "istio (proxyv2)" "unknown" "/etc/istio" \
      "Istio data plane present; carrier version follows the injected proxy image — check 'istioctl version'" "low"
  fi
}

detect_brotli_dotnet() {
  have_cmd dotnet || return 0
  local out ver
  out="$(dotnet --list-runtimes 2>/dev/null | awk '$1=="Microsoft.NETCore.App"{print $2}')"
  [ -n "$out" ] || return 0
  while IFS= read -r ver; do
    [ -n "$ver" ] || continue
    _brotli_record "dotnet" "Microsoft.NETCore.App $ver" "$ver" "$(command -v dotnet)" \
      "Brotli decompression is opt-in in HttpClient/ASP.NET Core; .NET Framework is unaffected" "medium"
  done <<EOF
$out
EOF
}

detect_brotli_curl() {
  have_cmd curl || return 0
  local v libs marker cert
  v="$(curl -V 2>/dev/null | head -1)"
  case "$v" in
    *brotli*) : ;;
    *) return 0 ;;
  esac
  libs="$(brotli_lib_for_binary "$(command -v curl)")"
  marker="$(brotli_marker_probe "$(command -v curl)")"
  cert="$(brotli_certainty "" "$marker")"
  _brotli_record "curl" "curl (brotli-enabled)" "unknown" "$(command -v curl)" \
    "curl -V advertises brotli; linked libs: ${libs:-statically linked}; marker $marker" "$cert"
}

detect_brotli_php() {
  [ "${#PHP_RECS[@]}" -gt 0 ] || return 0
  local rec bin mods libs marker cert ev
  for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
    bin="$(rec_bin "$rec")"
    mods="$("$bin" -m 2>/dev/null | grep -i 'brotli' || true)"
    libs="$(brotli_lib_for_binary "$bin")"
    [ -n "$mods$libs" ] || continue
    marker="$(brotli_marker_probe "$bin")"
    cert="$(brotli_certainty "" "$marker")"
    ev="php module(s): ${mods:-none}; linked: ${libs:-none}; marker $marker"
    _brotli_record "php" "php $(rec_version "$rec") brotli" "$(rec_version "$rec")" "$bin" "$ev" "$cert"
  done
}

# ------------------------------------------------------------------------------
# 5. vendored source trees (the case that version scanners miss entirely)
# ------------------------------------------------------------------------------
detect_brotli_vendor() {
  local root f maj min pat ver found=0
  local max_records="${P2S_BROTLI_VENDOR_MAX:-25}"
  local roots=""
  for root in ${P2S_BROTLI_SCAN_ROOTS[@]+"${P2S_BROTLI_SCAN_ROOTS[@]}"}; do
    [ -d "$root" ] && roots="$roots $root"
  done
  for root in /usr/src /usr/local/src /opt /srv /var/www /home; do
    [ -d "$root" ] && roots="$roots $root"
  done
  [ -n "$roots" ] || return 0

  for root in $roots; do
    for f in $(find "$root" -maxdepth 7 -type f \
                 \( -path '*brotli*/c/common/version.h' -o -path '*brotli/c/common/version.h' \) \
                 2>/dev/null | head -20); do
      maj="$(sed -n 's/^#define BROTLI_VERSION_MAJOR \([0-9]*\).*/\1/p' "$f" 2>/dev/null | head -1)"
      min="$(sed -n 's/^#define BROTLI_VERSION_MINOR \([0-9]*\).*/\1/p' "$f" 2>/dev/null | head -1)"
      pat="$(sed -n 's/^#define BROTLI_VERSION_PATCH \([0-9]*\).*/\1/p' "$f" 2>/dev/null | head -1)"
      [ -n "$maj" ] || continue
      [ "$found" -ge "$max_records" ] && continue
      ver="$maj.${min:-0}.${pat:-0}"
      _brotli_record "vendor" "vendored brotli $ver" "$ver" "$(dirname "$(dirname "$(dirname "$f")")")" \
        "source tree at $f (bundled copy — invisible to OS package management)" "medium"
      found=$((found+1))
    done
  done
  if [ "$found" -gt 0 ]; then
    info "found $found vendored Brotli source tree(s) — patch with patches/brotli/"
    [ "$found" -ge "${P2S_BROTLI_VENDOR_MAX:-25}" ] && \
      info "  (list capped; set P2S_BROTLI_VENDOR_MAX to raise it)"
  fi
  return 0
}

# ------------------------------------------------------------------------------
# entry point
# ------------------------------------------------------------------------------
detect_brotli_all() {
  BROTLI_RECS=()
  local scan
  for scan in ${P2S_SCAN_PATHS:-}; do
    P2S_BROTLI_SCAN_ROOTS[${#P2S_BROTLI_SCAN_ROOTS[@]}]="$scan"
  done

  detect_brotli_lib
  detect_brotli_node
  detect_brotli_bun
  detect_brotli_python
  detect_brotli_envoy
  detect_brotli_dotnet
  detect_brotli_curl
  detect_brotli_php
  detect_brotli_vendor
  detect_node_services

  if [ "${#BROTLI_RECS[@]}" -eq 0 ]; then
    info "no Brotli decoder carrier found on this host (containers/vendored builds are not visible here)"
  else
    ok "found ${#BROTLI_RECS[@]} Brotli decoder carrier(s)"
    local r
    for r in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
      log "     - $(printf '%s' "$r" | cut -d'|' -f1) $(printf '%s' "$r" | cut -d'|' -f3) ($(printf '%s' "$r" | cut -d'|' -f4))"
    done
  fi
}
