#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/brotli_db.sh
# HTTP2Shell (CVE-2026-111497) knowledge base and verdict engine.
#
# One CVE, four marketing names: Node2Shell / HTTP2Shell / Broccoli2Shell /
# Brotli2Shell.  All of them are a heap out-of-bounds write in Google Brotli's
# C decoder (CWE-787, caused by CWE-252) reached through `Content-Encoding: br`
# in *either* direction.  The root defect is not the missing bounds check: it is
# `DecodeBlockTypeAndLength()` returning a single BROTLI_BOOL for two mutually
# exclusive outcomes ("needs more input" vs "permanent format error"), so the
# caller cannot tell a resumable stream from a broken one.
#
# Design rules for this file (deliberate, they matter):
#   * Verdicts are per *carrier*, never per host.  "Is brotli patched?" is not a
#     question about an OS package: Node vendors it, Bun vendors it, Python
#     wheels vendor it, ClickHouse forks it.
#   * A version string is evidence, not proof.  Patched Node still reports
#     process.versions.brotli === "1.2.0"; Debian keeps the upstream version and
#     appends a revision.  Hence `brotli_marker_*` capability probes and the
#     CERTAINTY column carried on every record.
#   * Severity is stated honestly: DoS is universal, RCE is per-build.  A tool
#     that shouts "RCE everywhere" gets ignored, and one that whispers "DoS
#     only" gets hosts owned.  Both facts go in the report.
#
# Populates (see lib/detect_brotli.sh):
#   BROTLI_RECS[]      carrier|name|version|path|evidence|certainty
#   BROTLI_FINDINGS[]  id|severity|target|message|fix
# ==============================================================================

[ -n "${P2S_BROTLI_DB_LOADED:-}" ] && return 0
P2S_BROTLI_DB_LOADED=1

export BROTLI_CVE="CVE-2026-111497"
export BROTLI_ADVISORIES="GHSA-9v8h-qqgm-4m35 / PYSEC-2026-4322 / PYSEC-2026-4323 / GHSA-663w-cv8g-jj2p / GHSA-3wvj-j6qm-62mr / CVE-2026-115936"

# Affected upstream range: 1.0.3 .. 1.2.0.  Fixed: 1.0.10 / 1.1.1 / 1.2.1.
BROTLI_MIN_AFFECTED="1.0.3"
FIX_BROTLI_10="1.0.10"
FIX_BROTLI_11="1.1.1"
FIX_BROTLI_12="1.2.1"
FIX_BROTLI="$FIX_BROTLI_12"

FIX_NODE_22="22.23.4"
FIX_NODE_24="24.22.1"
FIX_NODE_26="26.12.1"
FIX_BUN="1.4.4"
FIX_PY_BROTLI="1.2.1"
FIX_PY_BROTLICFFI="1.2.1.0"
FIX_ENVOY_40="1.40.0"
FIX_ENVOY_39="1.39.3"
FIX_ENVOY_38="1.38.6"
FIX_ENVOY_37="1.37.8"
FIX_DOTNET_8="8.0.33"
FIX_DOTNET_9="9.0.22"
FIX_DOTNET_10="10.0.14"

# The error code introduced by the fix.  Positive evidence of the fix in a
# binary; see brotli_marker_probe().
BROTLI_FIX_MARKER="BLOCK_SWITCH"
export BROTLI_FIX_ERROR="-17"

BROTLI_RECS=()
BROTLI_FINDINGS=()

_brotli_rec()     { BROTLI_RECS[${#BROTLI_RECS[@]}]="$1|$2|$3|$4|$5|$6"; }
_brotli_finding() { BROTLI_FINDINGS[${#BROTLI_FINDINGS[@]}]="$1|$2|$3|$4|$5"; }

# ------------------------------------------------------------------------------
# version helpers
# ------------------------------------------------------------------------------

# brotli_norm_version <string> -> leading dotted-numeric component
#   "1.0.9-2+deb12u1" -> 1.0.9      "v1.2.1" -> 1.2.1       "1.2.1.0" -> 1.2.1.0
brotli_norm_version() {
  printf '%s\n' "$1" \
    | sed -n 's/^[^0-9]*\([0-9][0-9.]*\).*/\1/p' \
    | sed 's/\.*$//'
}

# brotli_certainty <version-string> <marker-state> -> high|medium|low
#   A clean version + a positive marker is high confidence.  A version that
#   looks patched with no marker is still medium (the marker can be optimised
#   away or the build stripped), a bare distro version with no probe is low.
brotli_certainty() {
  local v="$1" marker="$2"
  case "$marker" in
    present) printf '%s' high ;;
    absent)  [ -n "$v" ] && printf '%s' medium || printf '%s' low ;;
    *)       [ -n "$v" ] && printf '%s' low || printf '%s' low ;;
  esac
}

# ------------------------------------------------------------------------------
# per-carrier verdicts: FIXED | VULNERABLE | VULNERABLE-EOL |
#                      VULNERABLE-NO-UPSTREAM-FIX | NOT-AFFECTED | UNKNOWN
# ------------------------------------------------------------------------------

brotli_lib_status() { # <upstream libbrotli version>
  # Fixed releases are per line: 1.0.10, 1.1.1, 1.2.1. Comparing against 1.2.1
  # alone would call the fixed 1.0.10 and 1.1.1 "vulnerable" and send people on a
  # pointless major upgrade (or worse, an unmaintained rebuild).
  local v mm
  v="$(brotli_norm_version "$1")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  mm="$(version_major_minor "$v")"
  case "$mm" in
    1.0) version_ge "$v" "$FIX_BROTLI_10" && { printf '%s' FIXED; return; } ;;
    1.1) version_ge "$v" "$FIX_BROTLI_11" && { printf '%s' FIXED; return; } ;;
    1.2) version_ge "$v" "$FIX_BROTLI_12" && { printf '%s' FIXED; return; } ;;
    0.*) printf '%s' NOT-AFFECTED; return ;;
    1.*|2.*|3.*) printf '%s' FIXED; return ;;   # 1.3+/2.x ship the fix
  esac
  if version_ge "$v" "$BROTLI_MIN_AFFECTED"; then printf '%s' VULNERABLE; return; fi
  printf '%s' NOT-AFFECTED
}

node_brotli_status() { # <node version>
  local v major
  v="$(brotli_norm_version "$1")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  # Node fixes ship per MAJOR line (22.x, 24.x, 26.x). Note 22.23.4 is a higher
  # patch than 22.22.3 — that is the whole point of the per-line check.
  major="$(printf '%s' "$v" | cut -d. -f1)"
  case "$major" in
    22) version_ge "$v" "$FIX_NODE_22" && { printf '%s' FIXED; return; }
        printf '%s' VULNERABLE; return ;;
    24) version_ge "$v" "$FIX_NODE_24" && { printf '%s' FIXED; return; }
        printf '%s' VULNERABLE; return ;;
    26) version_ge "$v" "$FIX_NODE_26" && { printf '%s' FIXED; return; }
        printf '%s' VULNERABLE; return ;;
    20|21|23|25) printf '%s' VULNERABLE-EOL; return ;;
    1[0-9])      printf '%s' VULNERABLE-NO-UPSTREAM-FIX; return ;;
    27|28|29|[3-9][0-9]) printf '%s' UNKNOWN; return ;;   # released later than this DB
  esac
  if [ "$major" -ge 10 ] 2>/dev/null; then
    printf '%s' VULNERABLE-NO-UPSTREAM-FIX
    return
  fi
  printf '%s' UNKNOWN
}

bun_brotli_status() { # <bun version>
  local v
  v="$(brotli_norm_version "$1")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  version_ge "$v" "$FIX_BUN" && { printf '%s' FIXED; return; }
  printf '%s' VULNERABLE
}

python_brotli_status() { # <package> <version>
  local pkg="$1" v
  v="$(brotli_norm_version "$2")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  case "$pkg" in
    brotli)     version_ge "$v" "$FIX_PY_BROTLI"      && printf '%s' FIXED || printf '%s' VULNERABLE ;;
    brotlicffi) version_ge "$v" "$FIX_PY_BROTLICFFI"  && printf '%s' FIXED || printf '%s' VULNERABLE ;;
    *)          printf '%s' UNKNOWN ;;
  esac
}

envoy_brotli_status() { # <envoy version>
  local v mm
  v="$(brotli_norm_version "$1")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  mm="$(version_major_minor "$v")"
  case "$mm" in
    1.40) version_ge "$v" "$FIX_ENVOY_40" && { printf '%s' FIXED; return; } ;;
    1.39) version_ge "$v" "$FIX_ENVOY_39" && { printf '%s' FIXED; return; } ;;
    1.38) version_ge "$v" "$FIX_ENVOY_38" && { printf '%s' FIXED; return; } ;;
    1.37) version_ge "$v" "$FIX_ENVOY_37" && { printf '%s' FIXED; return; } ;;
    1.2[0-9]|1.3[0-6]) printf '%s' VULNERABLE-EOL; return ;;
    1.4[1-9]|1.[5-9]*) version_ge "$v" "$FIX_ENVOY_40" && { printf '%s' FIXED; return; } ;;
  esac
  printf '%s' VULNERABLE
}

dotnet_brotli_status() { # <Microsoft.NETCore.App version>
  local v mm
  v="$(brotli_norm_version "$1")"
  [ -n "$v" ] || { printf '%s' UNKNOWN; return; }
  mm="$(version_major_minor "$v")"
  case "$mm" in
    8.0)  version_ge "$v" "$FIX_DOTNET_8"  && printf '%s' FIXED || printf '%s' VULNERABLE ;;
    9.0)  version_ge "$v" "$FIX_DOTNET_9"  && printf '%s' FIXED || printf '%s' VULNERABLE ;;
    10.0) version_ge "$v" "$FIX_DOTNET_10" && printf '%s' FIXED || printf '%s' VULNERABLE ;;
    11.0) printf '%s' FIXED ;;        # RC3 and later ship the fixed decoder
    *)    printf '%s' UNKNOWN ;;
  esac
}

# ------------------------------------------------------------------------------
# fix guidance per carrier
# ------------------------------------------------------------------------------
brotli_fixed_for() { # <carrier> <version> -> human sentence
  case "$1" in
    libbrotli)
      case "$(version_major_minor "$(brotli_norm_version "$2")")" in
        1.0) printf '%s' "$FIX_BROTLI_10 (or vendor backport; any 1.2.1+ build)" ;;
        1.1) printf '%s' "$FIX_BROTLI_11 (or 1.2.1+)" ;;
        *)   printf '%s' "$FIX_BROTLI_12" ;;
      esac ;;
    node)
      case "$(version_major_minor "$(brotli_norm_version "$2")")" in
        22) printf '%s' "$FIX_NODE_22" ;;
        24) printf '%s' "$FIX_NODE_24" ;;
        26) printf '%s' "$FIX_NODE_26" ;;
        20|21|23|25) printf '%s' "nothing — branch is EOL; migrate to a supported line" ;;
        *) printf '%s' "a supported Node line (22.23.4+ / 24.22.1+ / 26.12.1+)" ;;
      esac ;;
    bun)        printf '%s' "$FIX_BUN" ;;
    brotli)     printf '%s' "$FIX_PY_BROTLI" ;;
    brotlicffi) printf '%s' "$FIX_PY_BROTLICFFI" ;;
    envoy)      printf '%s' "1.40.0 / 1.39.3 / 1.38.6 / 1.37.8 (or newer)" ;;
    dotnet)     printf '%s' "8.0.33 / 9.0.22 / 10.0.14 / 11 RC3+" ;;
    curl)       printf '%s' "rebuild curl against libbrotli >= 1.2.1 (or a vendor build that already links it)" ;;
    php)        printf '%s' "rebuild the PHP brotli extension/bundled libbrotli against >= 1.2.1" ;;
    vendor)     printf '%s' "update the vendored copy to 1.2.1, or apply patches/brotli/" ;;
    *)          printf '%s' "$FIX_BROTLI" ;;
  esac
}

# ------------------------------------------------------------------------------
# carrier context — used verbatim in reports, so it has to be true
# ------------------------------------------------------------------------------

# brotli_carrier_reach <carrier> -> "inbound|outbound|both|file-format"
#
# Direction matters more than anything else in this CVE: an inbound decoder is
# reachable by anyone who can POST; an outbound decoder is reachable by anyone
# who can make *your* service fetch *their* URL.
brotli_carrier_reach() {
  case "$1" in
    node|bun)   printf '%s' "both (inbound only if the app decodes br bodies; outbound whenever fetch() gets an attacker-influenced URL)" ;;
    brotli|brotlicffi) printf '%s' "both (urllib3/requests/httpx/aiohttp/Scrapy auto-decode br responses once the package is installed)" ;;
    envoy)      printf '%s' "inbound (only with a Brotli *decompressor* configured; compressor-only is not an entry point)" ;;
    libbrotli)  printf '%s' "depends on the consumer: proxy, interpreter, media pipeline or CLI tool" ;;
    curl)       printf '%s' "outbound (--compressed / libcurl auto-decode)" ;;
    dotnet)     printf '%s' "inbound/outbound, opt-in only (BrotliStream / handler decompression; .NET Framework unaffected)" ;;
    php)        printf '%s' "inbound (request bodies via the brotli extension)" ;;
    vendor)     printf '%s' "file-format / data pipeline (JPEG XL, Parquet, archives, firmware, PDF, Office files)" ;;
    *)          printf '%s' "unknown" ;;
  esac
}

# brotli_status_note -> the severity paragraph.  Printed once per run.
#
# The honest position: remote DoS is universal, RCE is per-build.  Public
# reproduction on linux/x86-64 measured the overflow topping out at struct
# offset 98 while the pointer that would have to be overwritten sits at 136;
# the one demonstrated RCE was on linux/arm64 against a single official Node
# build (24.22.0) with multiple attempts.  Triage must plan for DoS and must
# not assume RCE is impossible.
brotli_status_note() {
  cat <<'EOF'
HTTP2Shell (CVE-2026-111497) — how to read the verdicts
  * Remote denial of service is universal: a few hundred bytes of crafted
    Brotli can spin a decoder at 100% CPU or crash the process.
  * Remote code execution is per-build. It has been demonstrated on linux/arm64
    against one official Node build; on linux/x86-64 a measured reproduction
    reached only struct offset 98 of the 136 needed for pointer control. Treat
    "no working exploit yet" as a statement about one architecture on one day.
  * Weaponised RCE payloads are ~23 MB (2^24 commands). A request-body cap below
    that blocks the known RCE path but NOT the tiny DoS payload — so a small
    body limit is not a fix, and "we never saw a 23 MB body" is not a clean bill.
  * Version strings lie. Patched Node still reports process.versions.brotli
    "1.2.0"; Debian keeps upstream versions with a +deb revision. The toolkit
    therefore probes for the fix marker (BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH)
    in binaries and reports a CERTAINTY alongside every version.
EOF
}

# ------------------------------------------------------------------------------
# capability probe — "is the fix actually in this binary?"
# ------------------------------------------------------------------------------
#
# The fix introduced a *new error string* (BLOCK_SWITCH) that did not exist in
# any vulnerable build. Its presence is positive proof of the fix; its absence
# proves nothing (stripped symbol tables, dead-code elimination, a different
# build of the same source). That asymmetry is exactly what a probe should be:
# useful when it fires, honest when it does not.
#
# brotli_marker_probe <file> -> present|absent|skipped
brotli_marker_probe() {
  local f="$1"
  [ -e "$f" ] || { printf '%s' skipped; return; }
  [ -r "$f" ] || { printf '%s' skipped; return; }
  if have_cmd strings; then
    if strings -a "$f" 2>/dev/null | grep -q "$BROTLI_FIX_MARKER"; then
      printf '%s' present; return
    fi
    printf '%s' absent; return
  fi
  # No `strings`: grep -a is the portable fallback (matches binary content).
  if grep -qa "$BROTLI_FIX_MARKER" "$f" 2>/dev/null; then
    printf '%s' present
  else
    printf '%s' absent
  fi
}

# brotli_marker_from_proc <process-name-or-path> -> resolves a running binary
brotli_marker_for_cmd() {
  local bin
  bin="$(command -v "$1" 2>/dev/null)" || { printf '%s' skipped; return; }
  brotli_marker_probe "$bin"
}

# resolve the shared library a binary actually links (not what the distro says)
brotli_lib_for_binary() { # -> prints path(s) of libbrotli*decomp linked by $1
  local bin="$1"
  [ -n "$bin" ] || return 1
  if have_cmd ldd; then
    ldd "$bin" 2>/dev/null | awk '/libbrotli/ {print $3}' | grep -v '^$'
  fi
}

# ------------------------------------------------------------------------------
# audit — called from audit_all(); never fatal
# ------------------------------------------------------------------------------
audit_brotli() {
  BROTLI_FINDINGS=()
  local rec carrier name ver path evidence certainty status fix
  local vulnerable=0 unknown=0 fixed=0

  if [ "${#BROTLI_RECS[@]}" -eq 0 ]; then
    _brotli_finding "H2S-000" "info" "host" \
      "no Brotli decoder carrier detected on this host (Brotli may still be present inside containers, packaged binaries or vendored sources — use --scan-path)" \
      "-"
    return 0
  fi

  for rec in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    carrier="$(printf '%s' "$rec" | cut -d'|' -f1)"
    name="$(printf '%s' "$rec" | cut -d'|' -f2)"
    ver="$(printf '%s' "$rec" | cut -d'|' -f3)"
    path="$(printf '%s' "$rec" | cut -d'|' -f4)"
    evidence="$(printf '%s' "$rec" | cut -d'|' -f5)"
    certainty="$(printf '%s' "$rec" | cut -d'|' -f6)"

    case "$carrier" in
      libbrotli)  status="$(brotli_lib_status "$ver")" ;;
      node)       status="$(node_brotli_status "$ver")" ;;
      bun)        status="$(bun_brotli_status "$ver")" ;;
      brotli|brotlicffi) status="$(python_brotli_status "$carrier" "$ver")" ;;
      envoy)      status="$(envoy_brotli_status "$ver")" ;;
      dotnet)     status="$(dotnet_brotli_status "$ver")" ;;
      *)          status="UNKNOWN" ;;
    esac

    fix="$(brotli_fixed_for "$carrier" "$ver")"
    case "$status" in
      FIXED|NOT-AFFECTED) fixed=$((fixed+1)) ;;
      UNKNOWN)            unknown=$((unknown+1)) ;;
      *)                  vulnerable=$((vulnerable+1)) ;;
    esac

    case "$status" in
      FIXED)
        _brotli_finding "H2S-100" "info" "$name ($path)" \
          "$carrier $ver — fixed; capability probe: $evidence (certainty: $certainty)" "-" ;;
      NOT-AFFECTED)
        _brotli_finding "H2S-101" "info" "$name ($path)" \
          "$carrier $ver predates the vulnerable range ($BROTLI_MIN_AFFECTED+)" \
          "no action; confirm the copy is not vendored elsewhere" ;;
      VULNERABLE)
        _brotli_finding "H2S-200" "critical" "$name ($path)" \
          "$carrier $ver is in the affected range — reach: $(brotli_carrier_reach "$carrier"); probe: $evidence (certainty: $certainty)" \
          "upgrade to $fix, then REBUILD artifacts and RESTART processes (see README 'HTTP2Shell')" ;;
      VULNERABLE-EOL)
        _brotli_finding "H2S-201" "critical" "$name ($path)" \
          "$carrier $ver is end-of-life — no upstream fix will ship for this branch" \
          "migrate to a supported release ($fix) or buy vendor EOL support; contain the decoder meanwhile (--contain)" ;;
      VULNERABLE-NO-UPSTREAM-FIX)
        _brotli_finding "H2S-202" "critical" "$name ($path)" \
          "$carrier $ver has no upstream fix — check your vendor/LTS channel before assuming it is unfixable" \
          "vendor backport, or migrate; contain the decoder meanwhile (--contain)" ;;
      *)
        _brotli_finding "H2S-203" "medium" "$name ($path)" \
          "$carrier $ver cannot be verdict-ed from the version alone (probe: $evidence, certainty: $certainty)" \
          "verify by capability: apply patches/brotli/ to a source tree, or test a built binary for the BLOCK_SWITCH marker" ;;
    esac
  done

  if [ "$vulnerable" -gt 0 ]; then
    _brotli_finding "H2S-001" "critical" "host" \
      "$vulnerable Brotli carrier(s) at risk of CVE-2026-111497 (DoS universal; RCE per-build)" \
      "run './setup.sh --contain' to cut the input channel now, then './setup.sh --fix'"
  fi
  if [ "$unknown" -gt 0 ]; then
    _brotli_finding "H2S-002" "medium" "host" \
      "$unknown carrier(s) could not be verdict-ed from version evidence" \
      "confirm with capability probes or vendor advisories; do not record as clean"
  fi
  debug "brotli audit: fixed=$fixed vulnerable=$vulnerable unknown=$unknown"
}

# true when any detected Brotli carrier is not provably fixed
p2s_any_vulnerable_brotli() {
  local r carrier ver
  for r in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    carrier="$(printf '%s' "$r" | cut -d'|' -f1)"
    ver="$(printf '%s' "$r" | cut -d'|' -f3)"
    case "$carrier" in
      libbrotli)  case "$(brotli_lib_status "$ver")" in FIXED|NOT-AFFECTED) ;; *) return 0 ;; esac ;;
      node)       case "$(node_brotli_status "$ver")" in FIXED|NOT-AFFECTED) ;; *) return 0 ;; esac ;;
      bun)        case "$(bun_brotli_status "$ver")" in FIXED) ;; *) return 0 ;; esac ;;
      brotli|brotlicffi) case "$(python_brotli_status "$carrier" "$ver")" in FIXED) ;; *) return 0 ;; esac ;;
      envoy)      case "$(envoy_brotli_status "$ver")" in FIXED) ;; *) return 0 ;; esac ;;
      dotnet)     case "$(dotnet_brotli_status "$ver")" in FIXED) ;; *) return 0 ;; esac ;;
      *)          return 0 ;;
    esac
  done
  return 1
}

# assert_marker_fixed <record>
# A carrier whose version means nothing (curl, PHP extension, a statically
# linked binary) but whose binary positively contains the fix marker is FIXED.
# The reverse is NEVER true: a missing marker is not evidence of vulnerability.
assert_marker_fixed() {
  local rec="$1" cert ev
  cert="$(printf '%s' "$rec" | cut -d'|' -f6)"
  ev="$(printf '%s' "$rec" | cut -d'|' -f5)"
  if [ "$cert" = "high" ] && printf '%s' "$ev" | grep -q 'marker present'; then
    printf '%s' FIXED
  else
    printf '%s' UNKNOWN
  fi
}

# verdict for one carrier record (single source of truth for report + verify)
brotli_record_status() { # <carrier|name|version|...>
  local carrier ver
  carrier="$(printf '%s' "$1" | cut -d'|' -f1)"
  ver="$(printf '%s' "$1" | cut -d'|' -f3)"
  case "$carrier" in
    libbrotli)          brotli_lib_status "$ver" ;;
    node)               node_brotli_status "$ver" ;;
    bun)                bun_brotli_status "$ver" ;;
    brotli|brotlicffi)  python_brotli_status "$carrier" "$ver" ;;
    envoy)              envoy_brotli_status "$ver" ;;
    dotnet)             dotnet_brotli_status "$ver" ;;
    vendor)             brotli_lib_status "$ver" ;;
    *)                  assert_marker_fixed "$1" ;;
  esac
}

# number of *actionable* HTTP2Shell findings (used for exit codes + summary)
brotli_critical_count() {
  local r n=0
  for r in ${BROTLI_FINDINGS[@]+"${BROTLI_FINDINGS[@]}"}; do
    case "$(printf '%s' "$r" | cut -d'|' -f1)" in
      H2S-200|H2S-201|H2S-202|H2S-001) n=$((n+1)) ;;
    esac
  done
  printf '%s' "$n"
}
