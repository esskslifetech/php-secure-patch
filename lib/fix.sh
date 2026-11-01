#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/fix.sh
# Automatic remediation engine.  Every change is backed up first and recorded
# in $P2S_BACKUP_DIR/MANIFEST.txt so ./rollback.sh can undo it wholesale.
#
# Actions:
#   1. upgrade_php_packages   — vendor packages to fixed versions (opt-out: --no-upgrade)
#   2. fix_ini_hardening      — version-aware ini drop-ins (PHP2Shell mitigations first)
#   3. fix_fpm_pools          — php_admin_value so mitigations apply BEFORE request parsing
#   4. fix_nginx_2019_11043   — CVE-2019-11043 script-file guard in php location blocks
#   5. fix_windows_2024_4577  — emit %AD rewrite / PowerShell / htaccess mitigations
#   6. fix_projects           — per-project .htaccess snippet + composer audit hints
#   7. apply_source_patches   — optional: patches/ against a php-src tree (--source-dir)
#   8. fix_upgrade_brotli     — HTTP2Shell: OS Brotli/curl/.NET carriers
#   9. fix_brotli_sources     — HTTP2Shell: vendored/source trees (--brotli-src)
#  10. restart_workers        — REQUIRED: both bugs live in long-lived process state
# ==============================================================================

[ -n "${P2S_FIX_LOADED:-}" ] && return 0
P2S_FIX_LOADED=1

FIX_REPORT=()

_fix_log() {
  FIX_REPORT[${#FIX_REPORT[@]}]="$1"
  action_note "$1"
}

# ------------------------------------------------------------------------------
fix_all() {
  step "Remediation"
  p2s_backup_init

  local failed=0

  [ "$P2S_NO_UPGRADE" != 1 ] && fix_upgrade_packages || failed=$((failed+1))
  fix_ini_hardening || failed=$((failed+1))
  fix_fpm_pools || failed=$((failed+1))
  fix_nginx_2019_11043 || failed=$((failed+1))
  fix_windows_2024_4577 || failed=$((failed+1))
  fix_projects || failed=$((failed+1))
  [ -n "${P2S_SOURCE_DIR:-}" ] && fix_source_patches || failed=$((failed+1))
  fix_upgrade_brotli_packages || failed=$((failed+1))
  [ -n "${P2S_BROTLI_SRC:-}" ] && fix_brotli_sources || failed=$((failed+1))
  fix_restart_workers || failed=$((failed+1))

  if [ "$failed" -gt 0 ]; then
    err "remediation pass completed with $failed failed action(s)"
    return 1
  fi
  ok "remediation pass complete (${#FIX_REPORT[@]} action(s))"
}

# ------------------------------------------------------------------------------
# 1. package upgrades
# ------------------------------------------------------------------------------
fix_upgrade_packages() {
  step "Upgrading PHP packages to patched releases"
  if [ "$PKG_MGR" = "none" ]; then
    warn "no package manager detected — skipping automated upgrade"
    _fix_log "SKIP upgrade: no package manager"
    return 0
  fi
  require_root_for "package upgrade"

  local pkgs=""
  case "$PKG_MGR" in
    apt-get)
      pkgs="$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^php/ {print $2}' | tr '\n' ' ')"
      if [ -n "$pkgs" ]; then
        info "upgrading: $pkgs"
        run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade $pkgs
        _fix_log "UPGRADE apt: $pkgs"
      fi
      ;;
    dnf|yum)
      run "$PKG_MGR" -y update 'php*'
      _fix_log "UPGRADE $PKG_MGR: php*"
      ;;
    apk)
      run apk upgrade 'php8*'
      _fix_log "UPGRADE apk: php8*"
      ;;
    pacman)
      run pacman -Sy --noconfirm php
      _fix_log "UPGRADE pacman: php"
      ;;
    zypper)
      run zypper --non-interactive update 'php*'
      _fix_log "UPGRADE zypper: php*"
      ;;
    brew)
      run brew upgrade php
      _fix_log "UPGRADE brew: php"
      ;;
    *)
      warn "package manager '$PKG_MGR' not automated — upgrade PHP manually"
      _fix_log "SKIP upgrade: unsupported package manager $PKG_MGR"
      ;;
  esac

  # Guidance for EOL branches the distro won't move by itself
  info "NOTE: distro upgrades stay on the same PHP branch. If you are on <= 8.1,"
  info "      switch to a maintained branch (e.g. deb.sury.org packages on Debian/Ubuntu,"
  info "      remi on EL, or build from source with patches/). See README 'Upgrading PHP branches'."
}

# ------------------------------------------------------------------------------
# 2. ini hardening (per PHP install, version aware)
# ------------------------------------------------------------------------------
ini_hardening_content() { # ini_hardening_content <version>
  local ver="$1" mm st
  mm="$(version_major_minor "$ver")"
  st="$(php2shell_status "$ver")"
  cat <<'EOF'
; ==============================================================================
; protection2shell :: PHP2Shell + general hardening drop-in (auto-generated)
; Applied: session.upload_progress producer kill (CVE-2026-109619), request-size
; and input-complexity bounds, baseline php.ini hardening.  Memory is handled
; according to whether this runtime is patched (see below).
; Safe to delete — every line is documented in README.md.
; ==============================================================================

; --- PHP2Shell temporary mitigations (php.net guidance, 21-23 Oct 2026) -------
; Kill the confirmed exploit producer: fires on ANY POST before app code runs.
session.upload_progress.enabled = Off

EOF
  case "$st" in
    FIXED|NOT-AFFECTED)
      cat <<'EOF'
; --- CVE-2026-109618: patched runtime ----------------------------------------
; The OOM-corruption path is gone on this release.  memory_limit is deliberately
; NOT overridden here — keep the site's existing, application-specific setting.
; If you want a finite availability guard, set it yourself (e.g. memory_limit = 256M).
EOF
      ;;
    *)
      if [ "$P2S_OOM_MITIGATION" = 1 ]; then
        cat <<'EOF'
; --- CVE-2026-109618: interim mitigation — memory_limit = -1 ------------------
; The exploit steers a *controlled* OOM during request setup, which needs a
; predictable per-request ceiling to aim at; removing PHP's ceiling removes
; that lever.
;
; THIS IS NOT A FIX, and it also deletes PHP's own memory guard: you MUST cap
; memory outside PHP (systemd MemoryMax=, cgroup v2 memory.max, container
; limit).  Do NOT use RLIMIT_AS / RLIMIT_DATA (ulimit -v / -d) — they surface
; as fatal allocation errors, the very bailout being exploited.
memory_limit = -1
EOF
      else
        cat <<'EOF'
; --- CVE-2026-109618: interim mitigation NOT applied -------------------------
; On a vulnerable runtime the advisory's interim mitigation is
;     memory_limit = -1    plus    a cap OUTSIDE PHP
; (systemd MemoryMax= / cgroup v2 memory.max / container limit) — not a tighter
; limit.  Left unchanged here on purpose: removing PHP's ceiling trades
; exploitability for availability, so it is opt-in:
;     sudo ./setup.sh --fix --oom-mitigation
; Do NOT use RLIMIT_AS / RLIMIT_DATA (ulimit -v / -d): they surface as fatal
; allocation errors, the very bailout being exploited.
; Only the PHP upgrade is a complete fix.
EOF
      fi
      ;;
  esac
  cat <<'EOF'

; --- request-size and input-complexity bounds (both cases) -------------------
post_max_size = 64M
upload_max_filesize = 32M
max_multipart_body_parts = 1000   ; PHP >= 8.3 only

; --- baseline hardening ------------------------------------------------------
allow_url_include = Off
expose_php = Off
cgi.fix_pathinfo = 0
phar.readonly = On
session.use_strict_mode = On
session.use_only_cookies = On
session.cookie_httponly = On
session.cookie_samesite = Lax
mail.add_x_header = Off
EOF
  # PHP 8.5-only producer (fatal_error_backtraces) — leave on other branches
  if [ "$mm" = "8.5" ]; then
    echo "; CVE-2026-109619 confirmed backtrace producer (PHP 8.5 only)"
    echo "fatal_error_backtraces = Off"
  fi
  if [ "$P2S_STRICT" = 1 ]; then
    cat <<'EOF'
display_errors = Off
zend.assertions = -1
session.cookie_secure = On
EOF
  fi
  if [ "$P2S_LOCKDOWN" = 1 ]; then
    cat <<'EOF'
; lockdown: shrunken request budgets (review before production use!)
max_execution_time = 60
max_input_time = 60
max_input_vars = 1000
EOF
  fi
}

fix_ini_hardening() {
  step "Applying ini hardening (version-aware drop-ins)"
  local rec bin ver ini scan target legacy_dir
  for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
    bin="$(rec_bin "$rec")"; ver="$(rec_version "$rec")"
    ini="$(rec_ini "$rec")"; scan="$(rec_scandir "$rec")"

    # v1.x wrote 99-pSP-hardening.ini. Leaving it behind would keep stale
    # directives alongside the new drop-in, so it is backed up and removed
    # (rollback restores it) before the new file is written.
    legacy_dir=""
    [ -n "$ini" ] && legacy_dir="$(dirname "$ini")"
    cleanup_legacy_ini_dropins "$scan" "$legacy_dir"

    if [ -n "$scan" ] && [ -d "$scan" ] && [ -w "$scan" ]; then
      target="$scan/99-p2s-hardening.ini"
    elif [ -n "$ini" ] && [ -w "$(dirname "$ini")" ]; then
      target="$(dirname "$ini")/99-p2s-hardening.ini"
    elif [ -n "$ini" ] && [ -f "$ini" ]; then
      # last resort: append a marked block to the main ini
      if grep -q 'protection2shell' "$ini" 2>/dev/null; then
        info "$ini already hardened — skipping"
        continue
      fi
      backup_file "$ini" >/dev/null
      if [ "$P2S_DRY_RUN" = 1 ]; then
        info "[dry] would append hardening block to $ini"
      else
        { echo ""; echo "; protection2shell hardening block — begin"; \
          ini_hardening_content "$ver"; \
          echo "; protection2shell hardening block — end"; } >> "$ini"
        ok "appended hardening block to $ini"
      fi
      _fix_log "INI $ini: appended PHP2Shell + hardening block (PHP $ver)"
      continue
    else
      warn "cannot write ini for $bin (ini='$ini' scan='$scan') — run as root or fix permissions"
      _fix_log "SKIP ini: $bin not writable"
      continue
    fi

    if [ -f "$target" ]; then
      backup_file "$target" >/dev/null
    else
      record_created "$target"
    fi
    if [ "$P2S_DRY_RUN" = 1 ]; then
      info "[dry] would write $target"
    else
      ini_hardening_content "$ver" > "$target"
      ok "wrote $target"
    fi
    _fix_log "INI $target: PHP2Shell + hardening drop-in (PHP $ver)"
  done

  # The memory half of the CVE-2026-109618 mitigation cannot live in php.ini —
  # state it plainly once, so nobody "improves" it with a tighter limit or with
  # setrlimit.
  if p2s_any_vulnerable_php; then
    info "CVE-2026-109618 interim memory mitigation:"
    info "  vulnerable runtimes want memory_limit=-1 plus a cap OUTSIDE PHP."
    info "  cap the cgroup/systemd slice, e.g. systemd drop-in for php-fpm:"
    info "    [Service]"
    info "    MemoryMax=2G"
    info "    MemoryHigh=1500M"
    info "  or a container limit (docker --memory / k8s resources.limits.memory)."
    info "  Do NOT use RLIMIT_AS / RLIMIT_DATA (ulimit -v / -d) — they turn into"
    info "  fatal allocation errors, which is the bailout path being exploited."
    if [ "$P2S_OOM_MITIGATION" != 1 ]; then
      info "  Not applied: re-run with --oom-mitigation to write memory_limit=-1."
    fi
    info "  This is containment. Only upgrading PHP closes CVE-2026-109618."
  fi
}

# ------------------------------------------------------------------------------
# 3. PHP-FPM pool hardening
# ------------------------------------------------------------------------------
fix_fpm_pools() {
  [ "${#FPM_POOLS[@]}" -gt 0 ] || { debug "no FPM pools to harden"; return 0; }
  step "Hardening PHP-FPM pools"
  require_root_for "php-fpm pool edit"

  local p conf user pmmr mem lim hardened
  local -a _seen_confs=()
  for p in ${FPM_POOLS[@]+"${FPM_POOLS[@]}"}; do
    conf="$(printf '%s' "$p" | cut -d'|' -f1)"
    # skip duplicate conf files (multiple pools in one file)
    local already=0
    for s in "${_seen_confs[@]+${_seen_confs[@]}}"; do
      [ "$s" = "$conf" ] && already=1 && break
    done
    [ "$already" = 1 ] && continue
    _seen_confs[${#_seen_confs[@]}]="$conf"
    pmmr="$(printf '%s' "$p" | cut -d'|' -f5)"
    mem="$(printf '%s' "$p" | cut -d'|' -f6)"
    lim="$(printf '%s' "$p" | cut -d'|' -f7)"
    hardened="$(printf '%s' "$p" | cut -d'|' -f8)"

    if [ "$hardened" = "yes" ]; then
      if [ "$P2S_LOCKDOWN" = 1 ]; then
        # Already hardened by an earlier run — lockdown still needs pm.max_requests=1.
        # Replace any existing pm.max_requests line (in or outside the p2s block).
        if [ -w "$conf" ]; then
          backup_file "$conf" >/dev/null
          if [ "$P2S_DRY_RUN" = 1 ]; then
            info "[dry] would set pm.max_requests=1 in $conf (lockdown)"
          else
            sed_inplace 's/^pm\.max_requests[[:space:]]*=.*/pm.max_requests = 1/' "$conf"
            # ensure it exists at all
            if ! grep -q '^pm\.max_requests[[:space:]]*=' "$conf" 2>/dev/null; then
              echo "pm.max_requests = 1" >> "$conf"
            fi
            ok "lockdown: pm.max_requests=1 set in $conf"
          fi
        fi
        _fix_log "FPM $conf: lockdown pm.max_requests=1 (already hardened)"
      else
        info "$conf already contains protection2shell block — skipping"
      fi
      continue
    fi
    [ -f "$conf" ] && [ -w "$conf" ] || { warn "$conf not writable — skipping"; continue; }
    backup_file "$conf" >/dev/null

    if [ "$P2S_DRY_RUN" = 1 ]; then
      info "[dry] would append hardening block to $conf"
      _fix_log "FPM $conf: pool hardening (dry-run)"
      continue
    fi

    {
      echo ""
      echo "; protection2shell hardening — begin (safe to remove)"
      echo "; PHP2Shell: mitigations must apply BEFORE request parsing => php_admin_*"
      echo "php_admin_value[session.upload_progress.enabled] = 0"
      echo "php_admin_value[allow_url_include] = 0"
      echo "php_admin_flag[expose_php] = off"
      echo "php_admin_value[phar.readonly] = 1"
      echo "php_admin_value[cgi.fix_pathinfo] = 0"
      if [ "$mem" = "unset" ] || [ "$P2S_OOM_MITIGATION" = 1 ]; then
        if [ "$P2S_OOM_MITIGATION" = 1 ]; then
          echo "; CVE-2026-109618 interim: keep the ceiling OUTSIDE PHP — cap the"
          echo "; cgroup/systemd slice for this pool (memory.max / MemoryMax=) and size"
          echo "; pm.max_children against it.  Never RLIMIT_AS / RLIMIT_DATA."
          echo "php_admin_value[memory_limit] = -1"
        else
          echo "; CVE-2026-109618: memory_limit deliberately not set here — the"
          echo "; advisory's interim mitigation is -1 plus an OS/container cap, not a"
          echo "; tighter limit (see H-001 in the report; --oom-mitigation applies it)."
        fi
      fi
      if [ "$lim" = "unset" ]; then
        echo "security.limit_extensions = .php"
      fi
      if [ "$pmmr" = "unset" ] || [ "$pmmr" = "0" ] || [ "$P2S_LOCKDOWN" = 1 ]; then
        if [ "$P2S_LOCKDOWN" = 1 ]; then
          echo "; lockdown: pm.max_requests=1 — no worker ever serves a second request,"
          echo "; which removes the cross-request reuse CVE-2026-109619 depends on"
          echo "; (it does NOT close the 109618 OOM path — patching still required)."
          echo "pm.max_requests = 1"
        else
          echo "; CVE-2026-109619 reduced exposure: recycling shortens the lifetime of"
          echo "; stale worker state.  500 does NOT isolate requests — only"
          echo "; pm.max_requests=1 does that (--lockdown)."
          echo "pm.max_requests = 500"
        fi
      fi
      echo "request_terminate_timeout = 120s"
      echo "; protection2shell hardening — end"
    } >> "$conf"
    ok "hardened FPM pool $conf"
    _fix_log "FPM $conf: pool hardening applied"
  done

  # validate every fpm binary's config before we restart later
  local fbin
  for p in ${FPM_RECS[@]+"${FPM_RECS[@]}"}; do
    fbin="$(printf '%s' "$p" | cut -d'|' -f1)"
    if [ -x "$fbin" ]; then
      if [ "$P2S_DRY_RUN" = 1 ]; then
        info "[dry] would validate $fbin -t"
      else
        if "$fbin" -t >/dev/null 2>&1; then
          ok "$fbin config test passed"
        else
          err "$fbin config test failed — reverting pool backups"
          restore_backups
          return 1
        fi
      fi
    fi
  done
}

# ------------------------------------------------------------------------------
# 4. nginx guard for CVE-2019-11043
# ------------------------------------------------------------------------------
fix_nginx_2019_11043() {
  [ "$NGINX_PRESENT" = 1 ] || return 0
  [ "${#NGINX_SPLITPATH_CONFS[@]}" -gt 0 ] || return 0
  step "Inserting CVE-2019-11043 guards into nginx php location blocks"
  require_root_for "nginx config edit"

  local f
  for f in ${NGINX_SPLITPATH_CONFS[@]+"${NGINX_SPLITPATH_CONFS[@]}"}; do
    if grep -qs 'protection2shell.*CVE-2019-11043' "$f"; then
      info "$f already guarded"
      continue
    fi
    [ -w "$f" ] || { warn "$f not writable — skipping"; continue; }
    backup_file "$f" >/dev/null
    if [ "$P2S_DRY_RUN" = 1 ]; then
      info "[dry] would insert script-file guard into php location blocks in $f"
      _fix_log "NGINX $f: CVE-2019-11043 guard (dry-run)"
      continue
    fi
    awk '
      /location[^{]*\\\.php/ && !done_file { in_php = 1 }
      in_php && /\{/ && !inserted {
        print
        print "        # protection2shell CVE-2019-11043 guard — begin"
        print "        # reject requests whose mapped script file does not exist"
        print "        if (!-f $document_root$fastcgi_script_name) { return 404; }"
        print "        # protection2shell CVE-2019-11043 guard — end"
        inserted = 1
        in_php = 0
        next
      }
      { print }
    ' "$f" > "$f.p2snew" && mv "$f.p2snew" "$f"
    if have_cmd nginx && ! nginx -t >/dev/null 2>&1; then
      err "nginx -t failed after editing $f — reverting"
      restore_backups
      return 1
    fi
    ok "guarded $f"
    _fix_log "NGINX $f: CVE-2019-11043 script-file guard inserted"
  done
}

# ------------------------------------------------------------------------------
# 5. Windows / php-cgi CVE-2024-4577 mitigations
# ------------------------------------------------------------------------------
fix_windows_2024_4577() {
  local outdir="${P2S_OUT_DIR:-$P2S_ROOT/out}"
  mkdir -p "$outdir" 2>/dev/null

  # Always emit the mitigation kit (Windows admins often run the scan from WSL)
  local ht="$outdir/CVE-2024-4577.htaccess" ps="$outdir/CVE-2024-4577-mitigate.ps1"
  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would emit CVE-2024-4577 mitigation kit to $outdir/"
  else
    cp "$P2S_HARDENING/windows-cve-2024-4577.htaccess" "$ht" 2>/dev/null
    cp "$P2S_HARDENING/windows-cve-2024-4577.ps1" "$ps" 2>/dev/null
    record_created "$ht" 2>/dev/null || true
    record_created "$ps" 2>/dev/null || true
    ok "CVE-2024-4577 mitigation kit written to $outdir/"
    _fix_log "EMIT $ht and $ps (CVE-2024-4577)"
  fi

  if [ "$IS_WINDOWS" = 1 ] && [ "${#CGI_BINS[@]}" -gt 0 ]; then
    warn "Windows host with php-cgi detected — deploy the %AD rewrite rules NOW and upgrade PHP"
    _fix_log "WARN Windows php-cgi exposure (CVE-2024-4577)"
  fi
}

# ------------------------------------------------------------------------------
# 6. project-level assists
# ------------------------------------------------------------------------------
fix_projects() {
  [ "${#PROJECT_RECS[@]}" -gt 0 ] || return 0
  step "Project-level assists"
  local p path
  for p in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
    path="$(printf '%s' "$p" | cut -d'|' -f1)"
    [ -d "$path" ] && [ -w "$path" ] || continue
    if [ "$P2S_DRY_RUN" = 1 ]; then
      info "[dry] would drop PHP2Shell hunting notes into $path/"
      continue
    fi
    cat > "$path/PROTECTION2SHELL-NOTES.txt" <<'EOF'
PHP2Shell (CVE-2026-109618 / CVE-2026-109619) — what to check in this project
================================================================================
The fix lives in the PHP runtime, NOT in this application. Updating WordPress/
Laravel/etc. does not patch PHP. After the runtime is patched, all PHP workers
must be restarted.

Interim mitigation for CVE-2026-109618 (while the runtime is still vulnerable):
  * memory_limit = -1  plus  a memory cap OUTSIDE PHP (systemd MemoryMax=,
    cgroup v2 memory.max, container limit) — a tighter memory_limit is the
    opposite of the advisory's guidance, because the exploit steers a
    *predictable* OOM ceiling
  * do NOT use RLIMIT_AS / RLIMIT_DATA (ulimit -v / -d)
  * conservative post_max_size, max_multipart_body_parts, frontend body limit
  * `setup.sh --fix --oom-mitigation` applies the memory_limit half for you
  * containment only — upgrading PHP is the actual fix

Hunting (CISA/NCSC guidance):
  * unusually large or deeply nested multipart/form-data requests in access logs
  * PHP workers killed by the OOM killer, crashing, or hitting memory_limit
    (where one is still set) around attack timestamps
  * unexplained files in web roots (webshells), esp. with recent mtimes
  * outbound connections from php-fpm/httpd children you cannot explain
  * "Allowed memory size exhausted" spikes immediately followed by odd requests

Run `composer audit` (Composer projects) and keep frameworks current, but treat
the runtime upgrade as the actual fix.
EOF
    _fix_log "PROJECT $path: PROTECTION2SHELL-NOTES.txt dropped"
    record_created "$path/PROTECTION2SHELL-NOTES.txt" 2>/dev/null || true
  done
  # composer audit opportunistically (report only)
  if have_cmd composer; then
    for p in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
      path="$(printf '%s' "$p" | cut -d'|' -f1)"
      [ -f "$path/composer.json" ] || continue
      info "composer audit: $path"
      ( cd "$path" && composer audit --no-interaction 2>&1 | tail -5 ) || true
    done
  fi
}

# ------------------------------------------------------------------------------
# 7. source patches (legacy / source builds)
# ------------------------------------------------------------------------------
fix_source_patches() {
  step "Applying bundled source patches to $P2S_SOURCE_DIR"
  if [ ! -d "$P2S_SOURCE_DIR" ]; then
    err "--source-dir '$P2S_SOURCE_DIR' does not exist"
    return 1
  fi
  run "$P2S_PATCHES/apply-source-patches.sh" "$P2S_SOURCE_DIR"
  _fix_log "SOURCE patches applied to $P2S_SOURCE_DIR (note: source-tree edits are external to the backup set and cannot be reverted by ./rollback.sh)"
  warn "source patches were applied to $P2S_SOURCE_DIR — these edits are outside the backup set and are NOT reversible via ./rollback.sh"
}

# ------------------------------------------------------------------------------
# 8. restart workers (mandatory)
# ------------------------------------------------------------------------------
fix_restart_workers() {
  step "Restarting PHP workers (mandatory for PHP2Shell)"
  info "PHP2Shell survives in long-lived worker memory — patches only take effect"
  info "after every worker is recycled."

  # php-fpm first
  local p name ver
  for p in ${FPM_RECS[@]+"${FPM_RECS[@]}"}; do
    name="$(basename "$(printf '%s' "$p" | cut -d'|' -f1)")"
    case "$name" in
      php-fpm)   svc_restart "php-fpm" ;;
      php-fpm*)  # php-fpm8.4 -> service php8.4-fpm (Debian) / php-fpm8.4 (EL)
                 ver="${name#php-fpm}"
                 svc_restart "php${ver}-fpm" || svc_restart "php-fpm${ver}" || svc_restart "php-fpm" ;;
      *)         svc_restart "$name" ;;
    esac
  done
  [ "$APACHE_PRESENT" = 1 ] && { svc_restart "apache2" || svc_restart "httpd"; }
  [ "$NGINX_PRESENT" = 1 ] && svc_restart "nginx"
  [ "$LITESPEED_PRESENT" = 1 ] && svc_restart "lshttpd"
  [ "$FRANKENPHP_PRESENT" = 1 ] && svc_restart "frankenphp"
  _fix_log "RESTART workers: fpm/apache/nginx/litespeed/frankenphp"
}

# ------------------------------------------------------------------------------
# legacy drop-in cleanup (project was named php-secure-patch up to v1.x)
# ------------------------------------------------------------------------------
cleanup_legacy_ini_dropins() {
  local dir legacy
  for dir in "$@"; do
    [ -n "$dir" ] && [ -d "$dir" ] || continue
    for legacy in "$dir/99-pSP-hardening.ini" "$dir/99-psp-hardening.ini"; do
      [ -f "$legacy" ] || continue
      info "found legacy hardening drop-in $legacy (from php-secure-patch v1.x)"
      backup_file "$legacy" >/dev/null 2>&1 || true
      if [ "$P2S_DRY_RUN" = 1 ]; then
        info "[dry] would remove legacy drop-in $legacy"
      else
        rm -f "$legacy" && ok "removed superseded legacy drop-in $legacy"
      fi
      _fix_log "INI remove legacy $legacy (superseded by 99-p2s-hardening.ini)"
    done
  done
}

# ------------------------------------------------------------------------------
# 8. HTTP2Shell — OS-level Brotli carriers
# ------------------------------------------------------------------------------
# Brotli is vendored far more often than it is linked, so this covers only what
# a package manager actually owns: the distro libbrotli, curl and the .NET
# runtime. Node/Bun/Python runtimes and vendored trees are handled separately
# (they are not distro packages, and silently swapping a language runtime under
# a running application is not a "safe fix").
fix_upgrade_brotli_packages() {
  if [ "${#BROTLI_RECS[@]}" -eq 0 ]; then
    debug "no Brotli carriers — skipping Brotli package upgrade"
    return 0
  fi
  if [ "$P2S_NO_UPGRADE" = 1 ]; then
    info "skipping Brotli package upgrades (--no-upgrade)"
    return 0
  fi
  step "Upgrading Brotli decoder packages (HTTP2Shell)"
  if [ "$PKG_MGR" = "none" ]; then
    warn "no package manager detected — upgrade libbrotli/curl manually"
    _fix_log "SKIP brotli upgrade: no package manager"
    return 0
  fi
  require_root_for "Brotli package upgrade"

  local pkgs=""
  case "$PKG_MGR" in
    apt-get)
      pkgs="$(dpkg -l 2>/dev/null | awk '/^ii/ && $2 ~ /^(libbrotli|brotli|curl|libcurl)/ {print $2}' | tr '\n' ' ')"
      if [ -n "$pkgs" ]; then
        info "upgrading: $pkgs"
        run env DEBIAN_FRONTEND=noninteractive apt-get update -qq
        # shellcheck disable=SC2086
        run env DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade $pkgs
        _fix_log "UPGRADE apt (brotli/curl): $pkgs"
      fi ;;
    dnf|yum)
      run "$PKG_MGR" -y update brotli brotli-devel curl libcurl
      _fix_log "UPGRADE $PKG_MGR: brotli curl" ;;
    apk)
      run apk upgrade brotli brotli-dev curl
      _fix_log "UPGRADE apk: brotli curl" ;;
    pacman)
      run pacman -Sy --noconfirm brotli curl
      _fix_log "UPGRADE pacman: brotli curl" ;;
    zypper)
      run zypper --non-interactive update libbrotlidec1 brotli curl
      _fix_log "UPGRADE zypper: brotli curl" ;;
    brew)
      run brew upgrade brotli
      _fix_log "UPGRADE brew: brotli" ;;
    *)
      warn "package manager '$PKG_MGR' not automated — upgrade libbrotli manually" ;;
  esac

  fix_upgrade_python_brotli

  # Node/Bun/.NET are reported with the exact target, never auto-swapped.
  local r carrier ver
  for r in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    carrier="$(printf '%s' "$r" | cut -d'|' -f1)"
    ver="$(printf '%s' "$r" | cut -d'|' -f3)"
    case "$carrier" in
      node|bun|dotnet|envoy)
        case "$carrier" in
          node)   case "$(node_brotli_status "$ver")" in FIXED) continue ;; esac
                  info "Node $ver: upgrade to $(brotli_fixed_for node "$ver") with your version manager, then rebuild native modules and containers" ;;
          bun)    case "$(bun_brotli_status "$ver")" in FIXED) continue ;; esac
                  info "Bun $ver: upgrade to $FIX_BUN, then re-run 'bun build --compile' (the old decoder stays inside existing single-file binaries)" ;;
          dotnet) case "$(dotnet_brotli_status "$ver")" in FIXED) continue ;; esac
                  info ".NET $ver: upgrade the runtime to $(brotli_fixed_for dotnet "$ver")" ;;
          envoy)  case "$(envoy_brotli_status "$ver")" in FIXED) continue ;; esac
                  info "Envoy/Istio $ver: upgrade to $(brotli_fixed_for envoy "$ver") (or remove the brotli decompressor filter)" ;;
        esac
        _fix_log "GUIDE $carrier $ver: manual runtime upgrade required"
        ;;
    esac
  done
  return 0
}

# Python wheels: opt-in only. A blanket pip upgrade inside an application's
# environment can change behaviour, so it needs an explicit flag.
fix_upgrade_python_brotli() {
  local r carrier ver py
  [ "${P2S_UPGRADE_PYTHON:-0}" = 1 ] || return 0
  for r in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    carrier="$(printf '%s' "$r" | cut -d'|' -f1)"
    case "$carrier" in brotli|brotlicffi) : ;; *) continue ;; esac
    ver="$(printf '%s' "$r" | cut -d'|' -f3)"
    case "$(python_brotli_status "$carrier" "$ver")" in
      FIXED) continue ;;
    esac
    py="$(printf '%s' "$r" | cut -d'|' -f4)"
    [ -x "$py" ] || continue
    info "upgrading $carrier in $py"
    run "$py" -m pip install --no-input -U "brotli>=1.2.1" "brotlicffi>=1.2.1.0" \
      && _fix_log "UPGRADE pip ($py): brotli/brotlicffi" \
      || warn "pip upgrade failed in $py — upgrade manually and regenerate the lockfile"
  done
}

# ------------------------------------------------------------------------------
# 9. HTTP2Shell — vendored / source trees
# ------------------------------------------------------------------------------
fix_brotli_sources() {
  local dir
  step "Patching Brotli source trees (HTTP2Shell)"
  for dir in $P2S_BROTLI_SRC; do
    if [ ! -d "$dir" ]; then
      err "--brotli-src '$dir' does not exist"
      return 1
    fi
    if [ -f "$dir/c/common/version.h" ]; then
      if [ "$P2S_DRY_RUN" = 1 ]; then
        run "$P2S_PATCHES/apply-brotli-patch.sh" "$dir" --dry-run
      else
        run "$P2S_PATCHES/apply-brotli-patch.sh" "$dir" --verify
      fi
    else
      if [ "$P2S_DRY_RUN" = 1 ]; then
        run "$P2S_PATCHES/apply-brotli-patch.sh" --find-under "$dir" --dry-run
      else
        run "$P2S_PATCHES/apply-brotli-patch.sh" --find-under "$dir" --verify
      fi
    fi
    _fix_log "SOURCE brotli patched under $dir (outside the backup set — not reversible via rollback.sh)"
  done
  warn "source patches are NOT reversible via rollback.sh; rebuild and redeploy afterwards"
  warn "a rebuilt binary is not a deployed fix: containers must be REBUILT (not"
  warn "restarted from a cached layer) and every process restarted."
  return 0
}
