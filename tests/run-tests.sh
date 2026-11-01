#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: tests/run-tests.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Self-test suite: version logic, CVE verdicts, project detection fixtures,
# end-to-end audit + fix dry-run, patch integrity.  No root needed.
#   ./tests/run-tests.sh
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
P2S_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
. "$P2S_ROOT/lib/common.sh"
. "$P2S_ROOT/lib/detect.sh"
. "$P2S_ROOT/lib/cve_db.sh"
. "$P2S_ROOT/lib/brotli_db.sh"
. "$P2S_ROOT/lib/detect_brotli.sh"
. "$P2S_ROOT/lib/fix.sh"
. "$P2S_ROOT/lib/contain.sh"
. "$P2S_ROOT/lib/verify.sh"
. "$P2S_ROOT/lib/report.sh"

PASS=0; FAIL=0; TMP="$(mktemp -d "${TMPDIR:-/tmp}/p2s-tests.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

assert_eq() { # assert_eq <desc> <expected> <actual>
  if [ "$2" = "$3" ]; then
    PASS=$((PASS+1)); ok "PASS: $1"
  else
    FAIL=$((FAIL+1)); err "FAIL: $1 — expected [$2] got [$3]"
  fi
}
assert_contains() { # assert_contains <desc> <needle> <haystack>
  case "$3" in
    *"$2"*) PASS=$((PASS+1)); ok "PASS: $1" ;;
    *) FAIL=$((FAIL+1)); err "FAIL: $1 — [$2] not found in output" ;;
  esac
}
assert_rc() { # assert_rc <desc> <expected-rc> <actual-rc>
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); ok "PASS: $1"
  else FAIL=$((FAIL+1)); err "FAIL: $1 — expected rc=$2 got rc=$3"; fi
}

step "1. version comparison"
assert_eq "1.0 >= 1.0" 0 "$(version_ge 1.0 1.0; echo $?)"
assert_eq "8.4.27 >= 8.4.27" 0 "$(version_ge 8.4.27 8.4.27; echo $?)"
assert_eq "8.5.12 >= 8.4.27" 0 "$(version_ge 8.5.12 8.4.27; echo $?)"
assert_eq "8.3.35 >= 8.3.36 (false)" 1 "$(version_ge 8.3.35 8.3.36; echo $?)"
assert_eq "7.4.33 >= 8.0 (false)" 1 "$(version_ge 7.4.33 8.0; echo $?)"
assert_eq "10.0.0 >= 9.9.9" 0 "$(version_ge 10.0.0 9.9.9; echo $?)"

step "2. PHP2Shell verdicts"
assert_eq "8.5.12 is FIXED"         FIXED "$(php2shell_status 8.5.12)"
assert_eq "8.5.11 is VULNERABLE"    VULNERABLE "$(php2shell_status 8.5.11)"
assert_eq "8.4.27 is FIXED"         FIXED "$(php2shell_status 8.4.27)"
assert_eq "8.4.26 is VULNERABLE"    VULNERABLE "$(php2shell_status 8.4.26)"
assert_eq "8.3.36 is FIXED"         FIXED "$(php2shell_status 8.3.36)"
assert_eq "8.2.35 is FIXED"         FIXED "$(php2shell_status 8.2.35)"
assert_eq "8.2.34 is VULNERABLE"    VULNERABLE "$(php2shell_status 8.2.34)"
assert_eq "8.1.29 is VULNERABLE-EOL" "VULNERABLE-EOL" "$(php2shell_status 8.1.29)"
assert_eq "7.4.33 is VULNERABLE-EOL" "VULNERABLE-EOL" "$(php2shell_status 7.4.33)"
assert_eq "7.3.11 has no upstream fix" "VULNERABLE-NO-UPSTREAM-FIX" "$(php2shell_status 7.3.11)"
assert_eq "5.6.40 has no upstream fix" "VULNERABLE-NO-UPSTREAM-FIX" "$(php2shell_status 5.6.40)"

step "3. support channels (EOL is not 'unfixable')"
assert_contains "8.3 is upstream-supported" "upstream-supported branch" "$(php2shell_support_note 8.3.36)"
assert_contains "7.4 name-checks the source backport" "minimal source backport" "$(php2shell_support_note 7.4.33)"
assert_contains "5.6 name-checks the vendor channel" "vendor/LTS backport" "$(php2shell_support_note 5.6.40)"
assert_contains "5.6 does not claim unfixable" "migration is the only fix" "$(php2shell_support_note 5.6.40)"
assert_eq "fixed_for 7.3 says vendor backport or migration" "no upstream release or backport — vendor backport or migration" "$(php2shell_fixed_for 7.3.11)"

step "4. CVE-2024-4577 verdicts"
assert_eq "8.3.8 FIXED"        FIXED "$(cve_2024_4577_status 8.3.8)"
assert_eq "8.3.7 VULNERABLE"   VULNERABLE "$(cve_2024_4577_status 8.3.7)"
assert_eq "8.1.28 VULNERABLE"  VULNERABLE "$(cve_2024_4577_status 8.1.28)"
assert_eq "8.1.29 FIXED"       FIXED "$(cve_2024_4577_status 8.1.29)"
assert_eq "8.4.0 NOT-AFFECTED" NOT-AFFECTED "$(cve_2024_4577_status 8.4.0)"

step "5. CVE-2019-11043 verdicts"
assert_eq "7.3.11 FIXED"      FIXED "$(cve_2019_11043_status 7.3.11)"
assert_eq "7.3.10 VULNERABLE" VULNERABLE "$(cve_2019_11043_status 7.3.10)"
assert_eq "7.1.33 FIXED"      FIXED "$(cve_2019_11043_status 7.1.33)"
assert_eq "8.4.27 NOT-AFFECTED" NOT-AFFECTED "$(cve_2019_11043_status 8.4.27)"

step "6. json escaping"
assert_eq "quote escaping" 'a\"b' "$(json_escape 'a"b')"
assert_eq "backslash escaping" 'a\\\\b' "$(json_escape 'a\\b')"

step "7. project detection (fixtures)"
mkdir -p "$TMP/wp/wp-includes" "$TMP/laravel"
cat > "$TMP/wp/wp-load.php" <<'EOF'
<?php // marker
EOF
cat > "$TMP/wp/wp-includes/version.php" <<'EOF'
<?php $wp_version = '6.7.1';
EOF
cat > "$TMP/laravel/composer.json" <<'EOF'
{"require": {"php": "^8.2", "laravel/framework": "^11.0"}}
EOF
cat > "$TMP/laravel/composer.lock" <<'EOF'
{"packages": [{"name": "laravel/framework", "version": "v11.3.0"}]}
EOF
detect_projects "$TMP"
wp_rec=""; lv_rec=""
for r in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
  case "$r" in
    *"|wordpress|"*) wp_rec="$r" ;;
    *"|laravel|"*)   lv_rec="$r" ;;
  esac
done
assert_contains "wordpress detected" "wordpress" "$wp_rec"
assert_contains "wordpress version" "6.7.1" "$wp_rec"
assert_contains "laravel detected" "laravel" "$lv_rec"
assert_contains "laravel version from lock" "v11.3.0" "$lv_rec"
assert_contains "php constraint parsed" "8.2" "$lv_rec"

step "7b. project detection with nothing to find"
# "Scan found nothing" is the normal case on a clean host — and it is exactly
# where an empty-array expansion aborted the run under `set -u` on bash 3.2
# (macOS). The empty result must be a clean zero, not a failure.
mkdir -p "$TMP/nothing-here"
detect_projects "$TMP/nothing-here" >/dev/null 2>&1
assert_rc "detect_projects on a tree with no projects exits 0" 0 "$?"
assert_eq "no project records for a tree with no projects" 0 "${#PROJECT_RECS[@]}"

step "8. patch files present and non-empty"
for p in upstream-php2shell-CVE-2026-109618-109619.patch \
         CVE-2019-11043-env-path-info-underflow.patch \
         CVE-2024-4577-php-cgi-argument-injection.patch \
         legacy/php2shell-minimal-backport-7.4-8.1.patch; do
  if [ -s "$P2S_ROOT/patches/$p" ]; then
    PASS=$((PASS+1)); ok "PASS: patches/$p exists"
  else
    FAIL=$((FAIL+1)); err "FAIL: patches/$p missing or empty"
  fi
done
assert_contains "php2shell patch has real hunks" "@@ -" "$(head -100 "$P2S_ROOT/patches/upstream-php2shell-CVE-2026-109618-109619.patch")"

step "9. end-to-end audit (setup.sh, read-only)"
out="$TMP/report.json"
"$P2S_ROOT/setup.sh" --json "$out" --scan-path "$TMP" >/dev/null 2>&1
rc=$?
assert_rc "audit exit code is 0 or 2" "0or2" "$([ "$rc" = 0 ] || [ "$rc" = 2 ] && echo 0or2 || echo "$rc")"
if have_cmd python3 && [ -f "$out" ]; then
  python3 -m json.tool "$out" >/dev/null 2>&1
  assert_rc "report JSON is valid" 0 "$?"
  assert_contains "report has cves" '"cves"' "$(cat "$out")"
  assert_contains "report has php_installs" '"php_installs"' "$(cat "$out")"
  assert_contains "report lists fixture project" 'wordpress' "$(cat "$out")"
else
  warn "python3 or report missing — skipping JSON validation"
fi

step "10. fix dry-run (must change nothing, exit 0 or 2)"
"$P2S_ROOT/setup.sh" --fix --yes --dry-run --scan-path "$TMP" >/dev/null 2>&1
rc=$?
assert_rc "fix --dry-run exits 0 or 2" "0or2" "$([ "$rc" = 0 ] || [ "$rc" = 2 ] && echo 0or2 || echo "$rc")"

step "11. php project-scanner (optional)"
if have_cmd php; then
  php "$P2S_ROOT/scanner/project-scanner.php" --path "$TMP" --json "$TMP/scan.json" >/dev/null 2>&1
  assert_rc "project-scanner runs" 0 "$?"
  assert_contains "scanner found wordpress" 'wordpress' "$(cat "$TMP/scan.json" 2>/dev/null)"
else
  info "php not installed — skipping scanner test"
fi

step "12. rollback flag parsing"
out="$("$P2S_ROOT/setup.sh" --rollback /nonexistent-backup-set 2>&1)"
rc=$?
assert_rc "setup.sh --rollback <bad dir> exits 1" 1 "$rc"
assert_contains "bad rollback path is reported" "backup set not found" "$out"
"$P2S_ROOT/rollback.sh" --list >/dev/null 2>&1
assert_rc "rollback.sh --list exits 0" 0 "$?"

step "13. hunt.sh indicator detection"
mkdir -p "$TMP/webroot/uploads"
cat > "$TMP/access.log" <<'EOF'
1.2.3.4 - - [31/Oct/2026:10:00:00 +0000] "GET /index.php?%ad-d+allow_url_include%3d1 HTTP/1.1" 404 210 "-" "curl/8"
1.2.3.4 - - [31/Oct/2026:10:00:01 +0000] "POST /index.php?PHP_SESSION_UPLOAD_PROGRESS=x HTTP/1.1" 200 245 "-" "python"
1.2.3.4 - - [31/Oct/2026:10:00:02 +0000] "POST /upload.php HTTP/1.1" 200 9999999 "-" "python"
EOF
echo '<?php eval($_POST[1]);' > "$TMP/webroot/uploads/shell.php"
echo '<?php // legit' > "$TMP/webroot/.hidden.php"
hout="$("$P2S_ROOT/hunt/hunt.sh" --log "$TMP/access.log" --webroot "$TMP/webroot" 2>&1)"
assert_contains "hunt sees %ad cgi-arg probe" "argument-injection probes" "$hout"
assert_contains "hunt sees upload_progress probe" "upload_progress probes" "$hout"
assert_contains "hunt sees oversized POST" "large POST bodies" "$hout"
assert_contains "hunt sees php in upload dir" "upload directories" "$hout"
assert_contains "hunt sees hidden php" "hidden/double-extension" "$hout"
"$P2S_ROOT/hunt/hunt.sh" --log "$TMP/access.log" --webroot "$TMP/none" --fail-on-findings >/dev/null 2>&1
rc=$?
assert_rc "hunt --fail-on-findings exits 1 on hits" 1 "$rc"

step "14. generated ini: memory mitigation direction"
# Vulnerable runtime, mitigation NOT requested: no active directive is written,
# only guidance — a tightened memory_limit is the wrong direction.
P2S_OOM_MITIGATION=0
ini_vuln="$(ini_hardening_content 8.1.29)"
mem_active="$(printf '%s\n' "$ini_vuln" | grep -E '^memory_limit' || true)"
assert_eq "no active memory_limit directive on a vulnerable runtime" "" "$mem_active"
assert_contains "vulnerable runtime is told the mitigation is opt-in" "NOT applied" "$ini_vuln"
assert_contains "vulnerable runtime is told the cap goes outside PHP" "cgroup v2 memory.max" "$ini_vuln"
assert_contains "vulnerable runtime is warned off RLIMIT" "RLIMIT_AS" "$ini_vuln"
assert_contains "input bounds are still written" "max_multipart_body_parts" "$ini_vuln"
# Vulnerable runtime, mitigation requested: exactly one directive, -1, with caveat
P2S_OOM_MITIGATION=1
ini_oom="$(ini_hardening_content 8.1.29)"
mem_active="$(printf '%s\n' "$ini_oom" | grep -E '^memory_limit' || true)"
assert_eq "opt-in writes exactly memory_limit = -1" "memory_limit = -1" "$mem_active"
assert_contains "opt-in demands an external cap" "systemd MemoryMax" "$ini_oom"
# Patched runtime: no active memory_limit directive is forced (site's existing setting stands)
P2S_OOM_MITIGATION=0
ini_fixed="$(ini_hardening_content 8.3.36)"
mem_active="$(printf '%s\n' "$ini_fixed" | grep -E '^memory_limit' || true)"
assert_eq "no active memory_limit directive forced on a patched runtime" "" "$mem_active"
assert_contains "patched runtime is told to keep its own setting" "NOT overridden" "$ini_fixed"

step "15. install.sh help"
"$P2S_ROOT/install.sh" --help >/dev/null 2>&1
assert_rc "install.sh --help exits 0" 0 "$?"


step "16. HTTP2Shell (CVE-2026-111497) verdicts"
# libbrotli: fixed releases are per line — 1.0.10 and 1.1.1 are fixed even
# though they are numerically below 1.2.1.
assert_eq "libbrotli 1.0.2 NOT-AFFECTED"     NOT-AFFECTED "$(brotli_lib_status 1.0.2)"
assert_eq "libbrotli 1.0.3 VULNERABLE"       VULNERABLE   "$(brotli_lib_status 1.0.3)"
assert_eq "libbrotli 1.0.9 VULNERABLE"       VULNERABLE   "$(brotli_lib_status 1.0.9)"
assert_eq "libbrotli 1.0.10 FIXED"           FIXED        "$(brotli_lib_status 1.0.10)"
assert_eq "libbrotli 1.1.0 VULNERABLE"       VULNERABLE   "$(brotli_lib_status 1.1.0)"
assert_eq "libbrotli 1.1.1 FIXED"            FIXED        "$(brotli_lib_status 1.1.1)"
assert_eq "libbrotli 1.2.0 VULNERABLE"       VULNERABLE   "$(brotli_lib_status 1.2.0)"
assert_eq "libbrotli 1.2.1 FIXED"            FIXED        "$(brotli_lib_status 1.2.1)"
assert_eq "libbrotli 1.3.0 FIXED"            FIXED        "$(brotli_lib_status 1.3.0)"

# Node fixes ship per MAJOR line: 22.22.3 is older than 22.23.4
assert_eq "node 22.22.3 VULNERABLE"          VULNERABLE   "$(node_brotli_status 22.22.3)"
assert_eq "node 22.23.4 FIXED"               FIXED        "$(node_brotli_status 22.23.4)"
assert_eq "node 24.22.0 VULNERABLE"          VULNERABLE   "$(node_brotli_status 24.22.0)"
assert_eq "node 24.22.1 FIXED"               FIXED        "$(node_brotli_status 24.22.1)"
assert_eq "node 26.12.0 VULNERABLE"          VULNERABLE   "$(node_brotli_status 26.12.0)"
assert_eq "node 26.12.1 FIXED"               FIXED        "$(node_brotli_status 26.12.1)"
assert_eq "node 20.x is EOL"                 VULNERABLE-EOL "$(node_brotli_status 20.19.0)"
assert_eq "node 18.x has no upstream fix"    VULNERABLE-NO-UPSTREAM-FIX "$(node_brotli_status 18.20.0)"
assert_eq "node 27 is unknown, not guessed"  UNKNOWN      "$(node_brotli_status 27.1.0)"

assert_eq "bun 1.4.3 VULNERABLE"             VULNERABLE   "$(bun_brotli_status 1.4.3)"
assert_eq "bun 1.4.4 FIXED"                  FIXED        "$(bun_brotli_status 1.4.4)"
assert_eq "python brotli 1.2.0 VULNERABLE"   VULNERABLE   "$(python_brotli_status brotli 1.2.0)"
assert_eq "python brotli 1.2.1 FIXED"        FIXED        "$(python_brotli_status brotli 1.2.1)"
assert_eq "brotlicffi 1.2.1.0 FIXED"         FIXED        "$(python_brotli_status brotlicffi 1.2.1.0)"
assert_eq "envoy 1.39.2 VULNERABLE"          VULNERABLE   "$(envoy_brotli_status 1.39.2)"
assert_eq "envoy 1.39.3 FIXED"               FIXED        "$(envoy_brotli_status 1.39.3)"
assert_eq "envoy 1.40.0 FIXED"               FIXED        "$(envoy_brotli_status 1.40.0)"
assert_eq "dotnet 8.0.32 VULNERABLE"         VULNERABLE   "$(dotnet_brotli_status 8.0.32)"
assert_eq "dotnet 8.0.33 FIXED"              FIXED        "$(dotnet_brotli_status 8.0.33)"

step "17. version normalisation (distro lies)"
assert_eq 'apt suffix "1.0.9-2+deb12u1"'  1.0.9     "$(brotli_norm_version 1.0.9-2+deb12u1)"
assert_eq 'leading v "v1.2.1"'            1.2.1     "$(brotli_norm_version v1.2.1)"
assert_eq 'apk form "brotli-1.2.1-r0"'    1.2.1     "$(brotli_norm_version brotli-1.2.1-r0)"
assert_eq 'rpm form "1.2.1-1.el9"'        1.2.1     "$(brotli_norm_version 1.2.1-1.el9)"
assert_eq 'fourth component kept'         1.2.1.0   "$(brotli_norm_version 1.2.1.0)"
assert_eq 'distro 1.0.9 is still VULNERABLE' VULNERABLE "$(brotli_lib_status 1.0.9-2+b6)"

step "18. capability probe: positive evidence only"
printf 'blob ... _ERROR_FORMAT_BLOCK_SWITCH ...' > "$TMP/patched.bin"
printf 'blob ... INVALID ...' > "$TMP/unpatched.bin"
assert_eq "marker found in a patched binary" present "$(brotli_marker_probe "$TMP/patched.bin")"
assert_eq "marker absent in an unpatched binary" absent "$(brotli_marker_probe "$TMP/unpatched.bin")"
assert_eq "probe on a missing file is skipped" skipped "$(brotli_marker_probe "$TMP/nope.bin")"
# a high-certainty marker outranks an unknown version (curl/php/vendored builds)
assert_eq "marker present -> FIXED even with no version" FIXED \
  "$(brotli_record_status "curl|curl|unknown|/usr/bin/curl|curl -V advertises brotli; marker present|high")"
assert_eq "marker absent + no version -> UNKNOWN, never vulnerable" UNKNOWN \
  "$(brotli_record_status "curl|curl|unknown|/usr/bin/curl|curl -V advertises brotli; marker absent|low")"
assert_eq "vendored tree verdicts by its version" VULNERABLE \
  "$(brotli_record_status "vendor|vendored brotli 1.2.0|1.2.0|/src/brotli|x|medium")"

step "19. Brotli patch set integrity"
for pf in patches/brotli/upstream-brotli-CVE-2026-111497-1.2.0-to-1.2.1.patch \
          patches/brotli/backport-brotli-CVE-2026-111497-1.0.x.patch; do
  if [ -s "$P2S_ROOT/$pf" ]; then
    PASS=$((PASS+1)); ok "PASS: $pf exists"
  else
    FAIL=$((FAIL+1)); err "FAIL: $pf missing or empty"
  fi
done
up_patch="$(cat "$P2S_ROOT/patches/brotli/upstream-brotli-CVE-2026-111497-1.2.0-to-1.2.1.patch")"
assert_contains "upstream patch adds BROTLI_SAFE_WITH_STATUS" "BROTLI_SAFE_WITH_STATUS" "$up_patch"
assert_contains "upstream patch returns FORMAT_BLOCK_SWITCH" "BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH" "$up_patch"
assert_contains "upstream patch defines error -17" "_ERROR_FORMAT_, BLOCK_SWITCH, -17" "$up_patch"
assert_contains "upstream patch touches decode.c" "c/dec/decode.c" "$up_patch"
assert_contains "backport touches decode.c" "c/dec/decode.c" \
  "$(cat "$P2S_ROOT/patches/brotli/backport-brotli-CVE-2026-111497-1.0.x.patch")"
# applier: a tree that already carries the fix must be recognised and skipped
mkdir -p "$TMP/fixed-brotli/c/common" "$TMP/fixed-brotli/c/dec" "$TMP/fixed-brotli/c/include/brotli"
printf '#define BROTLI_VERSION_MAJOR 1\n#define BROTLI_VERSION_MINOR 2\n#define BROTLI_VERSION_PATCH 1\n' \
  > "$TMP/fixed-brotli/c/common/version.h"
printf 'BROTLI_SAFE_WITH_STATUS\n' > "$TMP/fixed-brotli/c/dec/decode.c"
printf '_ERROR_FORMAT_, BLOCK_SWITCH, -17\n' > "$TMP/fixed-brotli/c/include/brotli/decode.h"
out="$("$P2S_ROOT/patches/apply-brotli-patch.sh" --find-under "$TMP/fixed-brotli" --dry-run 2>&1)"
assert_rc "applier exits 0 on an already-fixed tree" 0 "$?"
assert_contains "applier reports already fixed" "already fixed" "$out"
# legacy hex version macro (1.0.x) must be understood too
mkdir -p "$TMP/old-brotli/c/common" "$TMP/old-brotli/c/dec"
printf '#define BROTLI_VERSION 0x1000009\n' > "$TMP/old-brotli/c/common/version.h"
printf '/* old decoder */\n' > "$TMP/old-brotli/c/dec/decode.c"
out="$("$P2S_ROOT/patches/apply-brotli-patch.sh" "$TMP/old-brotli" --dry-run 2>&1)"
assert_contains "1.0.9 hex version is parsed" "Brotli 1.0.9" "$out"
assert_contains "1.0.x selects the backport" "backport-brotli" "$out"

step "20. containment artifacts"
assert_contains "nginx guard denies br request bodies" 'http_content_encoding ~* "br"' \
  "$(cat "$P2S_ROOT/contain/snippets/nginx-deny-br.conf")"
assert_contains "nginx guard returns 415" "return 415" "$(cat "$P2S_ROOT/contain/snippets/nginx-deny-br.conf")"
assert_contains "apache guard rewrites to 415" "R=415" "$(cat "$P2S_ROOT/contain/snippets/apache-deny-br.conf")"
assert_contains "IIS guard uses CustomResponse 415" "SetAttribute('statusCode', '415')" \
  "$(cat "$P2S_ROOT/contain/windows-iis-http2shell.ps1")"
assert_contains "node guard inspects content-encoding" "content-encoding" \
  "$(cat "$P2S_ROOT/contain/guards/node-p2s-guard.cjs")"
assert_contains "python guard patches urllib3" "_init_decoder" \
  "$(cat "$P2S_ROOT/contain/guards/python-p2s-guard.py")"
if have_cmd python3; then
  py_out="$(P2S_DENY_BR=0 python3 - "$P2S_ROOT/contain/guards/python-p2s-guard.py" <<'PYEOF' 2>&1
import importlib.util, sys
spec = importlib.util.spec_from_file_location("p2s_guard", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
print("br-list", m._is_brotli("gzip, br"))
print("plain", m._is_brotli("gzip"))
print("upper", m._is_brotli("BR"))
PYEOF
)"
  assert_contains "python guard recognises a br list value" "br-list True" "$py_out"
  assert_contains "python guard ignores gzip" "plain False" "$py_out"
  assert_contains "python guard is case-insensitive" "upper True" "$py_out"
fi
if have_cmd node; then
  node --check "$P2S_ROOT/contain/guards/node-p2s-guard.cjs" >/dev/null 2>&1
  assert_rc "node guard parses" 0 "$?"
  # functional: the preload must answer 415 to a brotli request body
  port=18877
  cat > "$TMP/guard-app.js" <<'JSEOF'
const http = require('http');
const s = http.createServer((req, res) => {
  let n = 0;
  req.on('data', (c) => { n += c.length; });
  req.on('end', () => { res.writeHead(200); res.end('handled:' + n); });
});
s.listen(process.env.PORT);
JSEOF
  cat > "$TMP/guard-client.js" <<'JSEOF'
const http = require('http');
function once(headers) {
  return new Promise((resolve) => {
    const req = http.request({ port: process.env.PORT, method: 'POST', headers: headers }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve(res.statusCode + ' ' + body.trim().slice(0, 3)));
    });
    req.end(Buffer.from([0xff, 0x00]));
  });
}
(async () => {
  console.log('br:', await once({ 'Content-Encoding': 'br' }));
  console.log('plain:', await once({ 'Content-Type': 'text/plain' }));
  process.exit(0);
})();
JSEOF
  PORT=$port node -r "$P2S_ROOT/contain/guards/node-p2s-guard.cjs" "$TMP/guard-app.js" &
  guard_pid=$!
  sleep 1
  g_out="$(PORT=$port node "$TMP/guard-client.js" 2>&1)"
  kill "$guard_pid" 2>/dev/null
  wait "$guard_pid" 2>/dev/null
  assert_contains "node guard answers 415 to a br body" "br: 415" "$g_out"
  assert_contains "node guard leaves plain bodies alone" "plain: 200" "$g_out"
else
  info "node not installed — skipping the node guard functional test"
fi

step "21. containment dry-run (end to end)"
out="$("$P2S_ROOT/setup.sh" --contain --yes --dry-run --scan-path "$TMP" 2>&1)"
rc=$?
assert_rc "contain dry-run exits 0 or 2" "0or2" "$([ "$rc" = 0 ] || [ "$rc" = 2 ] && echo 0or2 || echo "$rc")"
assert_contains "contain phase runs" "Containment" "$out"
assert_contains "guards are emitted or planned" "node-p2s-guard.cjs" "$out"
assert_contains "verification runs after containment" "Verification" "$out"

step "22. JSON report carries the HTTP2Shell section"
"$P2S_ROOT/setup.sh" --json "$TMP/h2s.json" --scan-path "$TMP" >/dev/null 2>&1
if have_cmd python3 && [ -f "$TMP/h2s.json" ]; then
  python3 -m json.tool "$TMP/h2s.json" >/dev/null 2>&1
  assert_rc "HTTP2Shell report JSON is valid" 0 "$?"
  check="$(python3 - "$TMP/h2s.json" <<'PYEOF'
import json, sys
d = json.load(open(sys.argv[1]))
print("tool", d.get("tool", {}).get("name"))
print("cve", d.get("http2shell", {}).get("cve"))
print("carriers", "list" if isinstance(d.get("http2shell", {}).get("carriers"), list) else "missing")
print("findings", "list" if isinstance(d.get("http2shell", {}).get("findings"), list) else "missing")
print("verification", "object" if isinstance(d.get("verification"), dict) else "missing")
print("legacy_keys", "ok" if "cves" in d and "php_installs" in d else "missing")
PYEOF
)"
  assert_contains "report names the tool" "tool protection2shell" "$check"
  assert_contains "report names the CVE" "cve CVE-2026-111497" "$check"
  assert_contains "report has carriers" "carriers list" "$check"
  assert_contains "report has http2shell findings" "findings list" "$check"
  assert_contains "report has verification counts" "verification object" "$check"
  assert_contains "report keeps v1 keys (backwards compatible)" "legacy_keys ok" "$check"
else
  warn "python3 or report missing — skipping HTTP2Shell JSON test"
fi

step "23. legacy v1.x compatibility"
# the old ini drop-in must be removed (after backup) so directives are not duplicated
mkdir -p "$TMP/legacy-scan" "$TMP/legacy-backup"
printf 'session.upload_progress.enabled = On\n' > "$TMP/legacy-scan/99-pSP-hardening.ini"
P2S_BACKUP_DIR="$TMP/legacy-backup"; : > "$P2S_BACKUP_DIR/MANIFEST.txt"
P2S_DRY_RUN=0
cleanup_legacy_ini_dropins "$TMP/legacy-scan" >/dev/null 2>&1
assert_rc "legacy drop-in no longer exists" 1 "$([ -f "$TMP/legacy-scan/99-pSP-hardening.ini" ] && echo 0 || echo 1)"
assert_contains "legacy drop-in was backed up" "$TMP/legacy-scan/99-pSP-hardening.ini" \
  "$(cat "$P2S_BACKUP_DIR/MANIFEST.txt" 2>/dev/null)"
assert_eq "backup copy of the legacy drop-in exists" 1 \
  "$([ -f "$P2S_BACKUP_DIR/files/${TMP#/}/legacy-scan/99-pSP-hardening.ini" ] && echo 1 || echo 0)"
# old backup tree must still be discoverable (rename must not strand rollbacks)
base="$(p2s_backup_base)"
assert_eq "backup base resolves to a path" 1 "$(case "$base" in /*) echo 1 ;; *) echo 0 ;; esac)"

step "24. rename hygiene"
# No tracked path still carries the v1 name, no executable identifier does, and
# the documented compatibility shims are the only place the old name survives.
stale_paths="$(cd "$P2S_ROOT" && git ls-files 2>/dev/null | grep -i 'php-secure-patch' || true)"
assert_eq "no tracked file name carries the v1 name" "" "$stale_paths"
stale_ids="$(grep -rInE '(^|[^A-Za-z0-9_])(PSP_|psp_)|\bPSP_ROOT\b' \
  "$P2S_ROOT/lib" "$P2S_ROOT/setup.sh" "$P2S_ROOT/rollback.sh" \
  "$P2S_ROOT/install.sh" "$P2S_ROOT/hunt" "$P2S_ROOT/contain" 2>/dev/null || true)"
assert_eq "no stale PSP_/psp_ identifiers in code" "" "$stale_ids"
assert_contains "setup --help uses the new name" "protection2shell" "$("$P2S_ROOT/setup.sh" --help 2>&1)"
assert_contains "setup --help documents --auto" "--auto" "$("$P2S_ROOT/setup.sh" --help 2>&1)"
assert_contains "setup --help documents --contain" "--contain" "$("$P2S_ROOT/setup.sh" --help 2>&1)"
assert_contains "install --help uses the new name" "protection2shell" "$("$P2S_ROOT/install.sh" --help 2>&1)"
assert_eq "tool version is 2.x" 2 "$(printf '%s' "$P2S_TOOL_VERSION" | cut -d. -f1)"

step "25. install ergonomics (the \"it will not install\" cases)"
# `sh setup.sh` was a syntax error before 2.0.1; the scripts re-exec under bash.
assert_rc "sh setup.sh --help exits 0" 0 "$(sh "$P2S_ROOT/setup.sh" --help >/dev/null 2>&1; echo $?)"
assert_contains "sh setup.sh produces help, not a syntax error" "protection2shell" \
  "$(sh "$P2S_ROOT/setup.sh" --help 2>&1)"
assert_rc "sh install.sh --help exits 0" 0 "$(sh "$P2S_ROOT/install.sh" --help >/dev/null 2>&1; echo $?)"
assert_contains "install --help documents --bin" "--bin" "$("$P2S_ROOT/install.sh" --help 2>&1)"
assert_contains "setup.sh carries the bash re-exec guard" "BASH_VERSION" "$(cat "$P2S_ROOT/setup.sh")"

# a user-level install needs no root and no /usr/local/bin
PREFIX_DIR="$TMP/user-install/opt"
BIN_DIR="$TMP/user-install/bin"
out="$("$P2S_ROOT/install.sh" --prefix "$PREFIX_DIR" --bin "$BIN_DIR" 2>&1)"
assert_rc "install.sh --prefix/--bin exits 0" 0 "$?"
assert_contains "install.sh reports the destination" "$PREFIX_DIR/protection2shell" "$out"
assert_eq "wrapper installed" 1 "$([ -x "$BIN_DIR/protection2shell" ] && echo 1 || echo 0)"
assert_eq "payload installed" 1 "$([ -f "$PREFIX_DIR/protection2shell/setup.sh" ] && echo 1 || echo 0)"
assert_eq "docs installed with the payload" 1 "$([ -f "$PREFIX_DIR/protection2shell/INSTALL.md" ] && echo 1 || echo 0)"
# the wrapper must not depend on the exec bit of the payload (zip extractions)
chmod -x "$PREFIX_DIR/protection2shell/setup.sh"
assert_rc "wrapper runs a non-executable payload" 0 "$("$BIN_DIR/protection2shell" --help >/dev/null 2>&1; echo $?)"
assert_contains "wrapper survives a lost exec bit" "exec bash" "$(cat "$BIN_DIR/protection2shell")"

if [ "$(id -u)" != 0 ]; then
  out="$("$P2S_ROOT/install.sh" --prefix "$TMP/timer-opt" --bin "$TMP/timer-bin" --timer 2>&1)"
  assert_rc "--timer without root fails" 1 "$?"
  assert_contains "--timer failure names sudo" "sudo" "$out"
fi

assert_eq "INSTALL.md shipped" 1 "$([ -f "$P2S_ROOT/INSTALL.md" ] && echo 1 || echo 0)"
assert_contains "INSTALL.md tells people to run bash setup.sh" "bash setup.sh" "$(cat "$P2S_ROOT/INSTALL.md")"
assert_contains "INSTALL.md maps the exec-bit failure" "Permission denied" "$(cat "$P2S_ROOT/INSTALL.md")"
assert_contains "README points at INSTALL.md" "INSTALL.md" "$(cat "$P2S_ROOT/README.md")"

step "Results"
log "passed: $PASS   failed: $FAIL"
[ "$FAIL" = 0 ] || exit 1
exit 0
