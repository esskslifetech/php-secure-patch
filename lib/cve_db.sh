#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: lib/cve_db.sh
# Vulnerability knowledge base and verdict engine.
#
# Covers:
#   CVE-2026-109618  PHP2Shell: RCE via OOM corruption        (CVSS 9.2)
#   CVE-2026-109619  PHP2Shell: RCE via stale global state     (CVSS 9.2)
#   CVE-2026-115560  session.serialize_handler RCE (info)      (pending advisory)
#   CVE-2024-4577    PHP-CGI argument injection (Windows)      (CVSS 9.8)
#   CVE-2019-11043   PHP-FPM env_path_info underflow RCE       (CVSS 9.8)
# plus general PHP hardening findings (H-xxx).
#
# Populates:
#   CVE_RECORDS[]        id|status|evidence|fix
#   HARDENING_RECORDS[]  id|severity|target|message|fix
# ==============================================================================

[ -n "${PSP_CVE_DB_LOADED:-}" ] && return 0
PSP_CVE_DB_LOADED=1

# ---- fixed versions ---------------------------------------------------------
FIX_PHP2SHELL_85="8.5.12"   # released 2026-10-21
FIX_PHP2SHELL_84="8.4.27"
FIX_PHP2SHELL_83="8.3.36"
FIX_PHP2SHELL_82="8.2.35"
FIX_4577_81="8.1.29"        # released 2024-06-06
FIX_4577_82="8.2.20"
FIX_4577_83="8.3.8"
FIX_11043_71="7.1.33"       # released 2019-10-24 (bug #78598)
FIX_11043_72="7.2.24"
FIX_11043_73="7.3.11"

# PHP release branch support status (as of 2026-10-31)
# 8.2 security until 2026-12-31; 8.3/8.4/8.5 active. <=8.1: EOL upstream.

CVE_RECORDS=()
HARDENING_RECORDS=()

_cve_add()        { CVE_RECORDS[${#CVE_RECORDS[@]}]="$1|$2|$3|$4"; }
_hardening_add()  { HARDENING_RECORDS[${#HARDENING_RECORDS[@]}]="$1|$2|$3|$4|$5"; }

# php2shell_status <version> -> FIXED|VULNERABLE|VULNERABLE-EOL|VULNERABLE-NO-UPSTREAM-FIX
#
# The two EOL verdicts answer different questions — keep them distinct:
#   VULNERABLE-EOL               branch is EOL upstream, but PHP publishes a
#                                minimal source backport (7.4 / 8.0 / 8.1).
#   VULNERABLE-NO-UPSTREAM-FIX   no supported branch AND no upstream source
#                                backport (<= 7.3, PHP 5).  A distribution or
#                                commercial vendor backport may still exist
#                                (ESM / ELS / LTSS / vendor build) — that is a
#                                separate question from upstream's.
# Neither verdict says "unfixable": see php2shell_support_note().
php2shell_status() {
  local v="$1" mm
  mm="$(version_major_minor "$v")"
  case "$mm" in
    8.5) version_ge "$v" "$FIX_PHP2SHELL_85" && { echo FIXED; return; } ;;
    8.4) version_ge "$v" "$FIX_PHP2SHELL_84" && { echo FIXED; return; } ;;
    8.3) version_ge "$v" "$FIX_PHP2SHELL_83" && { echo FIXED; return; } ;;
    8.2) version_ge "$v" "$FIX_PHP2SHELL_82" && { echo FIXED; return; } ;;
    8.1|8.0|7.4) echo "VULNERABLE-EOL"; return ;;
    *)           echo "VULNERABLE-NO-UPSTREAM-FIX"; return ;;
  esac
  echo "VULNERABLE"
}

# php2shell_support_note <version> -> one line naming which support channels
# exist, so nobody reads "EOL" as "nothing can be done".
#   1. upstream-supported release for the branch
#   2. upstream source backport
#   3. vendor / LTS backport
php2shell_support_note() {
  case "$(version_major_minor "$1")" in
    8.5|8.4|8.3|8.2)
      echo "upstream-supported branch (standard security release)" ;;
    8.1|8.0|7.4)
      echo "upstream: no supported release for this branch — PHP does publish a minimal source backport (patches/legacy/); vendor backport may also exist" ;;
    *)
      echo "upstream: no supported release and no upstream source backport — a vendor/LTS backport may still exist (Debian/Ubuntu ESM, RHEL ELS, SUSE LTSS, vendor PHP builds); if it does not, migration is the only fix" ;;
  esac
}

php2shell_fixed_for() { # prints the fixed release for a version's branch (or '-')
  case "$(version_major_minor "$1")" in
    8.5) echo "$FIX_PHP2SHELL_85" ;;
    8.4) echo "$FIX_PHP2SHELL_84" ;;
    8.3) echo "$FIX_PHP2SHELL_83" ;;
    8.2) echo "$FIX_PHP2SHELL_82" ;;
    7.4|8.0|8.1) echo "no standard release — minimal source backport or vendor backport" ;;
    *) echo "no upstream release or backport — vendor backport or migration" ;;
  esac
}

cve_2024_4577_status() { # <version> -> FIXED|VULNERABLE|NOT-AFFECTED(version)|EOL-NO-FIX
  local v="$1" mm
  mm="$(version_major_minor "$v")"
  case "$mm" in
    8.3) version_ge "$v" "$FIX_4577_83" && { echo FIXED; return; } ;;
    8.2) version_ge "$v" "$FIX_4577_82" && { echo FIXED; return; } ;;
    8.1) version_ge "$v" "$FIX_4577_81" && { echo FIXED; return; } ;;
    8.4|8.5) echo "NOT-AFFECTED"; return ;;   # released after the fix
    *) echo "EOL-NO-FIX"; return ;;
  esac
  echo "VULNERABLE"
}

cve_2019_11043_status() { # <version> -> FIXED|VULNERABLE|NOT-AFFECTED
  local v="$1" mm
  mm="$(version_major_minor "$v")"
  case "$mm" in
    7.1) version_ge "$v" "$FIX_11043_71" && { echo FIXED; return; } ;;
    7.2) version_ge "$v" "$FIX_11043_72" && { echo FIXED; return; } ;;
    7.3) version_ge "$v" "$FIX_11043_73" && { echo FIXED; return; } ;;
    7.0|5.*|4.*) echo "VULNERABLE"; return ;;
    *) echo "NOT-AFFECTED"; return ;;        # 7.4+ shipped the fix from day one
  esac
  echo "VULNERABLE"
}

# ------------------------------------------------------------------------------
# Audit entry point — walks every detected installation and emits records.
# ------------------------------------------------------------------------------
audit_all() {
  CVE_RECORDS=(); HARDENING_RECORDS=()
  local rec ver st worst="FIXED"

  if [ "${#PHP_RECS[@]}" -eq 0 ]; then
    _cve_add "CVE-2026-109618" "NOT-FOUND" "no PHP installation detected" "-"
    _cve_add "CVE-2026-109619" "NOT-FOUND" "no PHP installation detected" "-"
    return 0
  fi

  for rec in "${PHP_RECS[@]}"; do
    ver="$(rec_version "$rec")"
    audit_php2shell_one "$rec" "$ver"
    audit_2024_4577_one "$rec" "$ver"
    audit_2019_11043_one "$rec" "$ver"
    audit_hardening_one "$rec" "$ver"
  done
  audit_fpm_hardening
  audit_nginx_cve_2019_11043
  audit_oldest_php
}

audit_php2shell_one() {
  local rec="$1" ver="$2" bin st fix evidence
  bin="$(rec_bin "$rec")"
  st="$(php2shell_status "$ver")"
  fix="upgrade to $(php2shell_fixed_for "$ver") and restart all workers"
  evidence="PHP $ver at $bin (SAPI $(rec_sapi "$rec"))"

  case "$st" in
    FIXED)
      _cve_add "CVE-2026-109618" "FIXED" "$evidence — >= $(php2shell_fixed_for "$ver")" \
        "keep session.upload_progress.enabled=Off until the next bugfix release (CVE-2026-115560)"
      _cve_add "CVE-2026-109619" "FIXED" "$evidence — >= $(php2shell_fixed_for "$ver")" \
        "keep session.upload_progress.enabled=Off until the next bugfix release (CVE-2026-115560)"
      ;;
    VULNERABLE)
      _cve_add "CVE-2026-109618" "VULNERABLE" "$evidence — below $(php2shell_fixed_for "$ver")" "$fix"
      _cve_add "CVE-2026-109619" "VULNERABLE" "$evidence — below $(php2shell_fixed_for "$ver")" "$fix"
      ;;
    VULNERABLE-EOL)
      _cve_add "CVE-2026-109618" "VULNERABLE" "$evidence — EOL branch: $(php2shell_support_note "$ver")" \
        "apply the PHP minimal source backport (patches/legacy/) or a vendor/LTS backport, then restart workers; otherwise migrate to 8.2.35+/8.3.36+/8.4.27+/8.5.12"
      _cve_add "CVE-2026-109619" "VULNERABLE" "$evidence — EOL branch: $(php2shell_support_note "$ver")" \
        "apply the PHP minimal source backport (patches/legacy/) or a vendor/LTS backport, then restart workers; otherwise migrate to 8.2.35+/8.3.36+/8.4.27+/8.5.12"
      ;;
    VULNERABLE-NO-UPSTREAM-FIX)
      _cve_add "CVE-2026-109618" "VULNERABLE" "$evidence — no upstream fix for this branch: $(php2shell_support_note "$ver")" \
        "check your vendor/LTS channel for a backport (Debian/Ubuntu ESM, RHEL ELS, SUSE LTSS); if none exists, migrate to a supported branch — do not assume the host is unfixable without asking the vendor"
      _cve_add "CVE-2026-109619" "VULNERABLE" "$evidence — no upstream fix for this branch: $(php2shell_support_note "$ver")" \
        "check your vendor/LTS channel for a backport (Debian/Ubuntu ESM, RHEL ELS, SUSE LTSS); if none exists, migrate to a supported branch — do not assume the host is unfixable without asking the vendor"
      ;;
  esac

  # CVE-2026-115560 (informational, advisory pending): session.upload_progress +
  # runtime session.serialize_handler switching. Mitigation is the same knob.
  local up
  up="$(rec_setting "$rec" "session.upload_progress.enabled")"
  if [ "$up" = "1" ] || [ "$up" = "On" ]; then
    _cve_add "CVE-2026-115560" "MITIGATE" "$evidence — session.upload_progress.enabled=$up" \
      "set session.upload_progress.enabled=Off (php.ini / FPM pool / server config) and restart workers"
  elif [ "$up" = "__unset__" ]; then
    _cve_add "CVE-2026-115560" "UNKNOWN" "$evidence — setting not reported by this SAPI" \
      "set session.upload_progress.enabled=Off explicitly"
  else
    _cve_add "CVE-2026-115560" "MITIGATED" "$evidence — session.upload_progress disabled" "-"
  fi
}

audit_2024_4577_one() {
  local rec="$1" ver="$2" bin st sapi
  bin="$(rec_bin "$rec")"; sapi="$(rec_sapi "$rec")"
  if [ "$IS_WINDOWS" != 1 ]; then
    _cve_add "CVE-2024-4577" "NOT-AFFECTED" "host OS is not Windows (bug is Windows Best-Fit specific)" "-"
    return 0
  fi
  st="$(cve_2024_4577_status "$ver")"
  case "$st" in
    FIXED)
      _cve_add "CVE-2024-4577" "FIXED" "PHP $ver at $bin — >= fixed release" "-" ;;
    NOT-AFFECTED)
      _cve_add "CVE-2024-4577" "NOT-AFFECTED" "PHP $ver at $bin released after the fix" "-" ;;
    EOL-NO-FIX)
      _cve_add "CVE-2024-4577" "VULNERABLE" "PHP $ver at $bin — EOL, no fix on Windows" \
        "migrate off php-cgi (use mod_php/PHP-FPM) or upgrade PHP" ;;
    *)
      _cve_add "CVE-2024-4577" "VULNERABLE" "PHP $ver at $bin on Windows (SAPI $sapi)" \
        "upgrade to 8.3.8+/8.2.20+/8.1.29+, move off php-cgi, or apply the %AD rewrite block" ;;
  esac
}

audit_2019_11043_one() {
  local rec="$1" ver="$2" bin st
  bin="$(rec_bin "$rec")"
  st="$(cve_2019_11043_status "$ver")"
  case "$st" in
    NOT-AFFECTED)
      _cve_add "CVE-2019-11043" "NOT-AFFECTED" "PHP $ver at $bin already contains the env_path_info fix" "-" ;;
    FIXED)
      _cve_add "CVE-2019-11043" "FIXED" "PHP $ver at $bin >= branch fix" "-" ;;
    *)
      _cve_add "CVE-2019-11043" "VULNERABLE" "PHP $ver at $bin — env_path_info underflow present" \
        "upgrade to 7.3.11+/7.2.24+/7.1.33+ and harden nginx fastcgi_split_path_info (guard snippet)" ;;
  esac
}

audit_nginx_cve_2019_11043() {
  [ "${#NGINX_SPLITPATH_CONFS[@]}" -gt 0 ] || return 0
  local f
  for f in "${NGINX_SPLITPATH_CONFS[@]}"; do
    if grep -qs 'php-secure-patch.*CVE-2019-11043' "$f"; then
      _hardening_add "H-100" "info" "$f" "nginx fastcgi_split_path_info present (guard already applied)" "-"
    else
      _hardening_add "H-100" "medium" "$f" \
        "nginx fastcgi_split_path_info without a script-file guard (classic CVE-2019-11043 setup)" \
        "insert 'if (!-f \$document_root\$fastcgi_script_name) { return 404; }' in the php location block"
    fi
  done
}

# true when any detected runtime still sits below its fixed release
psp_any_vulnerable_php() {
  local r
  for r in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
    case "$(php2shell_status "$(rec_version "$r")")" in
      FIXED|NOT-AFFECTED) ;;
      *) return 0 ;;
    esac
  done
  return 1
}

audit_fpm_hardening() {
  [ "${#FPM_POOLS[@]}" -gt 0 ] || return 0
  local p conf user pmmr mem lim hardened vuln=0
  psp_any_vulnerable_php && vuln=1
  for p in "${FPM_POOLS[@]}"; do
    conf="$(printf '%s' "$p" | cut -d'|' -f1)"
    pmmr="$(printf '%s' "$p" | cut -d'|' -f5)"
    mem="$(printf '%s' "$p" | cut -d'|' -f6)"
    lim="$(printf '%s' "$p" | cut -d'|' -f7)"
    hardened="$(printf '%s' "$p" | cut -d'|' -f8)"
    if [ "$pmmr" = "unset" ] || [ "$pmmr" = "0" ]; then
      _hardening_add "H-101" "medium" "$conf" \
        "pm.max_requests not set — workers live indefinitely, so CVE-2026-109619 can reach the same worker twice" \
        "set pm.max_requests=500 to shorten stale-state lifetime (reduced exposure, not isolation), or 1 to remove cross-request reuse entirely (--lockdown)"
    elif [ "$pmmr" != "1" ] && [ "$vuln" = 1 ]; then
      _hardening_add "H-101" "info" "$conf" \
        "pm.max_requests=$pmmr recycles workers but does not isolate requests — only 1 breaks the two-requests-on-one-worker requirement of CVE-2026-109619" \
        "use --lockdown (pm.max_requests=1) where the performance cost is acceptable; patching PHP is what actually closes this"
    fi
    if [ "$mem" = "unset" ]; then
      _hardening_add "H-102" "info" "$conf" \
        "pool sets no memory_limit — it inherits the php.ini value; check that value against the H-001 guidance" \
        "vulnerable runtime: memory_limit=-1 in php.ini plus an OS/container cap; patched runtime: an app-appropriate bound"
    elif [ "$vuln" = 1 ]; then
      _hardening_add "H-102" "high" "$conf" \
        "pool pins a PHP-level memory ceiling ($mem) on a vulnerable runtime — that is exactly the predictable OOM trigger CVE-2026-109618 steers" \
        "move the ceiling out of PHP: memory_limit=-1 (--oom-mitigation) plus a cgroup/systemd cap on the pool; never RLIMIT_AS/RLIMIT_DATA"
    fi
    if [ "$lim" = "unset" ]; then
      _hardening_add "H-103" "low" "$conf" \
        "security.limit_extensions not set" "set security.limit_extensions = .php"
    fi
  done
}

audit_oldest_php() {
  # Branch-level EOL advisory (only once)
  local rec ver mm
  for rec in "${PHP_RECS[@]}"; do
    ver="$(rec_version "$rec")"; mm="$(version_major_minor "$ver")"
    case "$mm" in
      8.2) _hardening_add "H-110" "info" "$ver" "PHP 8.2 is security-only until 2026-12-31 — plan upgrade to 8.3+" "plan migration" ;;
      8.1|8.0|7.4) _hardening_add "H-110" "high" "$ver" "PHP $mm is EOL upstream (no supported release); a PHP minimal source backport exists and a vendor backport may too" "apply patches/legacy/ or your vendor's backport, or migrate to 8.2.35+/8.3.36+/8.4.27+/8.5.12" ;;
      7.*|5.*|4.*) _hardening_add "H-110" "critical" "$ver" "PHP $mm has no upstream security branch and no upstream source backport — a vendor/LTS backport (ESM/ELS/LTSS) may still exist, check before assuming unfixable" "ask your vendor for a backport; if none exists, migrate immediately" ;;
    esac
    break  # one EOL note is enough
  done
}

audit_hardening_one() {
  local rec="$1" ver="$2" bin v st mvp
  bin="$(rec_bin "$rec")"
  st="$(php2shell_status "$ver")"

  # ---- CVE-2026-109618: memory ceiling ---------------------------------------
  # The steered out-of-memory path needs a *predictable per-request ceiling* to
  # aim at. On a vulnerable runtime the advisory's interim mitigation is
  # therefore memory_limit=-1 (no PHP ceiling) plus an OS/container cap — the
  # opposite of "tighten memory_limit". RLIMIT_AS / RLIMIT_DATA are explicitly
  # discouraged: they surface as fatal allocation errors, i.e. the bailout path
  # that is being exploited. Neither is a fix; updating PHP is.
  v="$(rec_setting "$rec" "memory_limit")"
  case "$st" in
    FIXED|NOT-AFFECTED)
      # Patched runtime: a finite ceiling is the normal, desirable setting.
      if [ "$v" = "-1" ]; then
        _hardening_add "H-001" "medium" "$bin" \
          "memory_limit=-1 on a patched runtime — PHP keeps no memory guard, so a runaway request is only stopped by the OS" \
          "set an app-appropriate memory_limit; the OOM-corruption path no longer exists on this release"
      fi
      ;;
    *)
      if [ "$v" = "-1" ]; then
        _hardening_add "H-001" "info" "$bin" \
          "interim mitigation in place: memory_limit=-1 removes the predictable ceiling CVE-2026-109618 steers" \
          "confirm an OS/container cap exists (systemd MemoryMax= / cgroup v2 memory.max) — do NOT use RLIMIT_AS/RLIMIT_DATA — and still patch PHP: this is containment, not a fix"
      elif [ "$v" = "__unset__" ]; then
        _hardening_add "H-001" "high" "$bin" \
          "vulnerable runtime reporting no memory_limit: if a PHP-level ceiling applies, CVE-2026-109618 gets a predictable OOM trigger" \
          "interim: memory_limit=-1 plus an OS/container memory cap (./setup.sh --fix --oom-mitigation); never RLIMIT_AS/RLIMIT_DATA; patch PHP for the real fix"
      else
        _hardening_add "H-001" "high" "$bin" \
          "memory_limit=$v gives CVE-2026-109618 a predictable OOM ceiling to steer — the advisory's interim mitigation is memory_limit=-1 plus an OS/container cap, not a tighter limit" \
          "interim: memory_limit=-1 with a cgroup/systemd cap (./setup.sh --fix --oom-mitigation); never RLIMIT_AS/RLIMIT_DATA; patch PHP for the real fix"
      fi
      ;;
  esac

  v="$(rec_setting "$rec" "post_max_size")"
  if [ "$v" = "-1" ] || [ "$v" = "0" ] || [ "$v" = "__unset__" ]; then
    _hardening_add "H-002" "medium" "$bin" \
      "post_max_size unbounded — oversized or deeply nested multipart bodies are the documented CVE-2026-109618 trigger" \
      "set post_max_size=64M (or app-appropriate) and enforce a request-body limit at the frontend proxy too"
  fi

  # third leg of the same advisory: keep attacker-shaped input bounded
  if [ "$st" != "FIXED" ] && [ "$st" != "NOT-AFFECTED" ]; then
    mvp="$(rec_setting "$rec" "max_multipart_body_parts")"
    if [ "$mvp" = "__unset__" ] || [ "$mvp" = "-1" ]; then
      _hardening_add "H-003" "medium" "$bin" \
        "max_multipart_body_parts unbounded — nested multipart bodies stay fully attacker-sized (honoured on PHP >= 8.3)" \
        "set max_multipart_body_parts=1000 and cap body/part counts at the frontend proxy"
    fi
  fi
  v="$(rec_setting "$rec" "allow_url_include")"
  if [ "$v" = "1" ] || [ "$v" = "On" ]; then
    _hardening_add "H-005" "critical" "$bin" "allow_url_include=On — remote file inclusion enabled" "set allow_url_include=Off"
  fi
  v="$(rec_setting "$rec" "expose_php")"
  if [ "$v" = "1" ] || [ "$v" = "On" ] || [ "$v" = "" ]; then
    _hardening_add "H-006" "low" "$bin" "expose_php=On — X-Powered-By fingerprinting" "set expose_php=Off"
  fi
  v="$(rec_setting "$rec" "cgi.fix_pathinfo")"
  if [ "$v" = "1" ] && [ "$(rec_sapi "$rec")" != "fpm-fcgi" ] && [ "$(rec_sapi "$rec")" != "fpm" ]; then
    _hardening_add "H-007" "medium" "$bin" "cgi.fix_pathinfo=1 on non-FPM SAPI — classic cgi hijack surface" "set cgi.fix_pathinfo=0"
  fi
  v="$(rec_setting "$rec" "display_errors")"
  if [ "$v" = "1" ] || [ "$v" = "On" ]; then
    _hardening_add "H-008" "low" "$bin" "display_errors=On — leaks paths/stack traces" "set display_errors=Off in production"
  fi
  v="$(rec_setting "$rec" "phar.readonly")"
  if [ "$v" = "0" ] || [ "$v" = "Off" ]; then
    _hardening_add "H-009" "medium" "$bin" "phar.readonly=Off — phar deserialization gadget surface" "set phar.readonly=On"
  fi
  v="$(rec_setting "$rec" "session.cookie_httponly")"
  if [ "$v" != "1" ] && [ "$v" != "On" ]; then
    _hardening_add "H-010" "medium" "$bin" "session.cookie_httponly off — session cookie readable from JS" "set session.cookie_httponly=On"
  fi
  v="$(rec_setting "$rec" "session.cookie_secure")"
  if [ "$v" != "1" ] && [ "$v" != "On" ]; then
    _hardening_add "H-011" "low" "$bin" "session.cookie_secure off" "set session.cookie_secure=On (HTTPS sites)"
  fi
  v="$(rec_setting "$rec" "session.cookie_samesite")"
  if [ -z "$v" ]; then
    _hardening_add "H-012" "low" "$bin" "session.cookie_samesite unset" "set session.cookie_samesite=Lax"
  fi
  v="$(rec_setting "$rec" "zend.assertions")"
  if [ "$v" = "1" ]; then
    _hardening_add "H-013" "low" "$bin" "zend.assertions=1 (dev mode) in a deployed runtime" "set zend.assertions=-1 in production"
  fi
  v="$(rec_setting "$rec" "session.use_strict_mode")"
  if [ "$v" != "1" ] && [ "$v" != "On" ]; then
    _hardening_add "H-014" "low" "$bin" "session.use_strict_mode off — session fixation surface" "set session.use_strict_mode=On"
  fi
  # PHP2Shell producer (CVE-2026-109619): session.upload_progress
  v="$(rec_setting "$rec" "session.upload_progress.enabled")"
  if [ "$v" = "1" ] || [ "$v" = "On" ] || [ "$v" = "" ]; then
    _hardening_add "H-003" "high" "$bin" \
      "session.upload_progress.enabled is active — confirmed CVE-2026-109619 exploit producer" \
      "set session.upload_progress.enabled=Off and restart all PHP workers"
  fi
  # PHP 8.5 producer: fatal_error_backtraces
  v="$(rec_setting "$rec" "fatal_error_backtraces")"
  if [ "$v" = "1" ] || [ "$v" = "On" ]; then
    _hardening_add "H-004" "high" "$bin" \
      "fatal_error_backtraces=On (PHP 8.5) — confirmed CVE-2026-109619 backtrace producer" \
      "set fatal_error_backtraces=Off and restart all PHP workers"
  fi
}
