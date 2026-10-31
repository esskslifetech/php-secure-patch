#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: lib/fix.sh
# Automatic remediation engine.  Every change is backed up first and recorded
# in $PSP_BACKUP_DIR/MANIFEST.txt so ./rollback.sh can undo it wholesale.
#
# Actions:
#   1. upgrade_php_packages   — vendor packages to fixed versions (opt-out: --no-upgrade)
#   2. fix_ini_hardening      — version-aware ini drop-ins (PHP2Shell mitigations first)
#   3. fix_fpm_pools          — php_admin_value so mitigations apply BEFORE request parsing
#   4. fix_nginx_2019_11043   — CVE-2019-11043 script-file guard in php location blocks
#   5. fix_windows_2024_4577  — emit %AD rewrite / PowerShell / htaccess mitigations
#   6. fix_projects           — per-project .htaccess snippet + composer audit hints
#   7. apply_source_patches   — optional: patches/ against a php-src tree (--source-dir)
#   8. restart_workers        — REQUIRED: PHP2Shell lives in long-lived worker state
# ==============================================================================

[ -n "${PSP_FIX_LOADED:-}" ] && return 0
PSP_FIX_LOADED=1

FIX_REPORT=()

_fix_log() {
  FIX_REPORT[${#FIX_REPORT[@]}]="$1"
  action_note "$1"
}

# ------------------------------------------------------------------------------
fix_all() {
  step "Remediation"
  psp_backup_init

  local failed=0

  [ "$PSP_NO_UPGRADE" != 1 ] && fix_upgrade_packages || failed=$((failed+1))
  fix_ini_hardening || failed=$((failed+1))
  fix_fpm_pools || failed=$((failed+1))
  fix_nginx_2019_11043 || failed=$((failed+1))
  fix_windows_2024_4577 || failed=$((failed+1))
  fix_projects || failed=$((failed+1))
  [ -n "${PSP_SOURCE_DIR:-}" ] && fix_source_patches || failed=$((failed+1))
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
; php-secure-patch :: PHP2Shell + general hardening drop-in (auto-generated)
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
      if [ "$PSP_OOM_MITIGATION" = 1 ]; then
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
  if [ "$PSP_STRICT" = 1 ]; then
    cat <<'EOF'
display_errors = Off
zend.assertions = -1
session.cookie_secure = On
EOF
  fi
  if [ "$PSP_LOCKDOWN" = 1 ]; then
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
  local rec bin ver ini scan target
  for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
    bin="$(rec_bin "$rec")"; ver="$(rec_version "$rec")"
    ini="$(rec_ini "$rec")"; scan="$(rec_scandir "$rec")"

    if [ -n "$scan" ] && [ -d "$scan" ] && [ -w "$scan" ]; then
      target="$scan/99-pSP-hardening.ini"
    elif [ -n "$ini" ] && [ -w "$(dirname "$ini")" ]; then
      target="$(dirname "$ini")/99-pSP-hardening.ini"
    elif [ -n "$ini" ] && [ -f "$ini" ]; then
      # last resort: append a marked block to the main ini
      if grep -q 'php-secure-patch' "$ini" 2>/dev/null; then
        info "$ini already hardened — skipping"
        continue
      fi
      backup_file "$ini" >/dev/null
      if [ "$PSP_DRY_RUN" = 1 ]; then
        info "[dry] would append hardening block to $ini"
      else
        { echo ""; echo "; php-secure-patch hardening block — begin"; \
          ini_hardening_content "$ver"; \
          echo "; php-secure-patch hardening block — end"; } >> "$ini"
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
    if [ "$PSP_DRY_RUN" = 1 ]; then
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
  if psp_any_vulnerable_php; then
    info "CVE-2026-109618 interim memory mitigation:"
    info "  vulnerable runtimes want memory_limit=-1 plus a cap OUTSIDE PHP."
    info "  cap the cgroup/systemd slice, e.g. systemd drop-in for php-fpm:"
    info "    [Service]"
    info "    MemoryMax=2G"
    info "    MemoryHigh=1500M"
    info "  or a container limit (docker --memory / k8s resources.limits.memory)."
    info "  Do NOT use RLIMIT_AS / RLIMIT_DATA (ulimit -v / -d) — they turn into"
    info "  fatal allocation errors, which is the bailout path being exploited."
    if [ "$PSP_OOM_MITIGATION" != 1 ]; then
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
      if [ "$PSP_LOCKDOWN" = 1 ]; then
        # Already hardened by an earlier run — lockdown still needs pm.max_requests=1.
        # Replace any existing pm.max_requests line (in or outside the psp block).
        if [ -w "$conf" ]; then
          backup_file "$conf" >/dev/null
          if [ "$PSP_DRY_RUN" = 1 ]; then
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
        info "$conf already contains php-secure-patch block — skipping"
      fi
      continue
    fi
    [ -f "$conf" ] && [ -w "$conf" ] || { warn "$conf not writable — skipping"; continue; }
    backup_file "$conf" >/dev/null

    if [ "$PSP_DRY_RUN" = 1 ]; then
      info "[dry] would append hardening block to $conf"
      _fix_log "FPM $conf: pool hardening (dry-run)"
      continue
    fi

    {
      echo ""
      echo "; php-secure-patch hardening — begin (safe to remove)"
      echo "; PHP2Shell: mitigations must apply BEFORE request parsing => php_admin_*"
      echo "php_admin_value[session.upload_progress.enabled] = 0"
      echo "php_admin_value[allow_url_include] = 0"
      echo "php_admin_flag[expose_php] = off"
      echo "php_admin_value[phar.readonly] = 1"
      echo "php_admin_value[cgi.fix_pathinfo] = 0"
      if [ "$mem" = "unset" ] || [ "$PSP_OOM_MITIGATION" = 1 ]; then
        if [ "$PSP_OOM_MITIGATION" = 1 ]; then
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
      if [ "$pmmr" = "unset" ] || [ "$pmmr" = "0" ] || [ "$PSP_LOCKDOWN" = 1 ]; then
        if [ "$PSP_LOCKDOWN" = 1 ]; then
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
      echo "; php-secure-patch hardening — end"
    } >> "$conf"
    ok "hardened FPM pool $conf"
    _fix_log "FPM $conf: pool hardening applied"
  done

  # validate every fpm binary's config before we restart later
  local fbin
  for p in ${FPM_RECS[@]+"${FPM_RECS[@]}"}; do
    fbin="$(printf '%s' "$p" | cut -d'|' -f1)"
    if [ -x "$fbin" ]; then
      if [ "$PSP_DRY_RUN" = 1 ]; then
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
    if grep -qs 'php-secure-patch.*CVE-2019-11043' "$f"; then
      info "$f already guarded"
      continue
    fi
    [ -w "$f" ] || { warn "$f not writable — skipping"; continue; }
    backup_file "$f" >/dev/null
    if [ "$PSP_DRY_RUN" = 1 ]; then
      info "[dry] would insert script-file guard into php location blocks in $f"
      _fix_log "NGINX $f: CVE-2019-11043 guard (dry-run)"
      continue
    fi
    awk '
      /location[^{]*\\\.php/ && !done_file { in_php = 1 }
      in_php && /\{/ && !inserted {
        print
        print "        # php-secure-patch CVE-2019-11043 guard — begin"
        print "        # reject requests whose mapped script file does not exist"
        print "        if (!-f $document_root$fastcgi_script_name) { return 404; }"
        print "        # php-secure-patch CVE-2019-11043 guard — end"
        inserted = 1
        in_php = 0
        next
      }
      { print }
    ' "$f" > "$f.pspnew" && mv "$f.pspnew" "$f"
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
  local outdir="${PSP_OUT_DIR:-$PSP_ROOT/out}"
  mkdir -p "$outdir" 2>/dev/null

  # Always emit the mitigation kit (Windows admins often run the scan from WSL)
  local ht="$outdir/CVE-2024-4577.htaccess" ps="$outdir/CVE-2024-4577-mitigate.ps1"
  if [ "$PSP_DRY_RUN" = 1 ]; then
    info "[dry] would emit CVE-2024-4577 mitigation kit to $outdir/"
  else
    cp "$PSP_HARDENING/windows-cve-2024-4577.htaccess" "$ht" 2>/dev/null
    cp "$PSP_HARDENING/windows-cve-2024-4577.ps1" "$ps" 2>/dev/null
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
    if [ "$PSP_DRY_RUN" = 1 ]; then
      info "[dry] would drop PHP2Shell hunting notes into $path/"
      continue
    fi
    cat > "$path/PHP2SHELL-README.txt" <<'EOF'
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
    _fix_log "PROJECT $path: PHP2SHELL-README.txt dropped"
    record_created "$path/PHP2SHELL-README.txt" 2>/dev/null || true
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
  step "Applying bundled source patches to $PSP_SOURCE_DIR"
  if [ ! -d "$PSP_SOURCE_DIR" ]; then
    err "--source-dir '$PSP_SOURCE_DIR' does not exist"
    return 1
  fi
  run "$PSP_PATCHES/apply-source-patches.sh" "$PSP_SOURCE_DIR"
  _fix_log "SOURCE patches applied to $PSP_SOURCE_DIR (note: source-tree edits are external to the backup set and cannot be reverted by ./rollback.sh)"
  warn "source patches were applied to $PSP_SOURCE_DIR — these edits are outside the backup set and are NOT reversible via ./rollback.sh"
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
