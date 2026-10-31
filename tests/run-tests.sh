#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: tests/run-tests.sh
# Author: ESS KS Life Tech — MIT licensed, see LICENSE
# Self-test suite: version logic, CVE verdicts, project detection fixtures,
# end-to-end audit + fix dry-run, patch integrity.  No root needed.
#   ./tests/run-tests.sh
# ==============================================================================
set -u
PSP_ROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
. "$PSP_ROOT/lib/common.sh"
. "$PSP_ROOT/lib/detect.sh"
. "$PSP_ROOT/lib/cve_db.sh"
. "$PSP_ROOT/lib/fix.sh"

PASS=0; FAIL=0; TMP="$(mktemp -d "${TMPDIR:-/tmp}/psp-tests.XXXXXX")"
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

step "8. patch files present and non-empty"
for p in upstream-php2shell-CVE-2026-109618-109619.patch \
         CVE-2019-11043-env-path-info-underflow.patch \
         CVE-2024-4577-php-cgi-argument-injection.patch \
         legacy/php2shell-minimal-backport-7.4-8.1.patch; do
  if [ -s "$PSP_ROOT/patches/$p" ]; then
    PASS=$((PASS+1)); ok "PASS: patches/$p exists"
  else
    FAIL=$((FAIL+1)); err "FAIL: patches/$p missing or empty"
  fi
done
assert_contains "php2shell patch has real hunks" "@@ -" "$(head -100 "$PSP_ROOT/patches/upstream-php2shell-CVE-2026-109618-109619.patch")"

step "9. end-to-end audit (setup.sh, read-only)"
out="$TMP/report.json"
"$PSP_ROOT/setup.sh" --json "$out" --scan-path "$TMP" >/dev/null 2>&1
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
"$PSP_ROOT/setup.sh" --fix --yes --dry-run --scan-path "$TMP" >/dev/null 2>&1
rc=$?
assert_rc "fix --dry-run exits 0 or 2" "0or2" "$([ "$rc" = 0 ] || [ "$rc" = 2 ] && echo 0or2 || echo "$rc")"

step "11. php project-scanner (optional)"
if have_cmd php; then
  php "$PSP_ROOT/scanner/project-scanner.php" --path "$TMP" --json "$TMP/scan.json" >/dev/null 2>&1
  assert_rc "project-scanner runs" 0 "$?"
  assert_contains "scanner found wordpress" 'wordpress' "$(cat "$TMP/scan.json" 2>/dev/null)"
else
  info "php not installed — skipping scanner test"
fi

step "12. rollback flag parsing"
out="$("$PSP_ROOT/setup.sh" --rollback /nonexistent-backup-set 2>&1)"
rc=$?
assert_rc "setup.sh --rollback <bad dir> exits 1" 1 "$rc"
assert_contains "bad rollback path is reported" "backup set not found" "$out"
"$PSP_ROOT/rollback.sh" --list >/dev/null 2>&1
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
hout="$("$PSP_ROOT/hunt/hunt.sh" --log "$TMP/access.log" --webroot "$TMP/webroot" 2>&1)"
assert_contains "hunt sees %ad cgi-arg probe" "argument-injection probes" "$hout"
assert_contains "hunt sees upload_progress probe" "upload_progress probes" "$hout"
assert_contains "hunt sees oversized POST" "large POST bodies" "$hout"
assert_contains "hunt sees php in upload dir" "upload directories" "$hout"
assert_contains "hunt sees hidden php" "hidden/double-extension" "$hout"
"$PSP_ROOT/hunt/hunt.sh" --log "$TMP/access.log" --webroot "$TMP/none" --fail-on-findings >/dev/null 2>&1
rc=$?
assert_rc "hunt --fail-on-findings exits 1 on hits" 1 "$rc"

step "14. generated ini: memory mitigation direction"
# Vulnerable runtime, mitigation NOT requested: no active directive is written,
# only guidance — a tightened memory_limit is the wrong direction.
PSP_OOM_MITIGATION=0
ini_vuln="$(ini_hardening_content 8.1.29)"
mem_active="$(printf '%s\n' "$ini_vuln" | grep -E '^memory_limit' || true)"
assert_eq "no active memory_limit directive on a vulnerable runtime" "" "$mem_active"
assert_contains "vulnerable runtime is told the mitigation is opt-in" "NOT applied" "$ini_vuln"
assert_contains "vulnerable runtime is told the cap goes outside PHP" "cgroup v2 memory.max" "$ini_vuln"
assert_contains "vulnerable runtime is warned off RLIMIT" "RLIMIT_AS" "$ini_vuln"
assert_contains "input bounds are still written" "max_multipart_body_parts" "$ini_vuln"
# Vulnerable runtime, mitigation requested: exactly one directive, -1, with caveat
PSP_OOM_MITIGATION=1
ini_oom="$(ini_hardening_content 8.1.29)"
mem_active="$(printf '%s\n' "$ini_oom" | grep -E '^memory_limit' || true)"
assert_eq "opt-in writes exactly memory_limit = -1" "memory_limit = -1" "$mem_active"
assert_contains "opt-in demands an external cap" "systemd MemoryMax" "$ini_oom"
# Patched runtime: finite bound, never -1
PSP_OOM_MITIGATION=0
ini_fixed="$(ini_hardening_content 8.3.36)"
mem_active="$(printf '%s\n' "$ini_fixed" | grep -E '^memory_limit' || true)"
assert_eq "patched runtime keeps a finite bound" "memory_limit = 256M" "$mem_active"

step "15. install.sh help"
"$PSP_ROOT/install.sh" --help >/dev/null 2>&1
assert_rc "install.sh --help exits 0" 0 "$?"

step "Results"
log "passed: $PASS   failed: $FAIL"
[ "$FAIL" = 0 ] || exit 1
exit 0
