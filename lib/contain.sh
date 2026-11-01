#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/contain.sh
# Containment — stop exploitation from spreading *before* anything is patched.
#
# Ordering is deliberate. Patching takes time (packages, rebuilds, restarts,
# maintenance windows); an exposed host is being scanned right now. Containment
# removes the channel the exploit travels through, so the window between
# detection and patch is not a window of exposure:
#
#   1. edge guard      refuse `Content-Encoding: br` request bodies (nginx /
#                      Apache / IIS). The decoder never sees the bytes.
#   2. runtime guard   refuse Brotli decompression inside the process
#                      (Node preload, Python import hook) — covers the OUTBOUND
#                      direction, which no perimeter device can see.
#   3. feature kill    PHP: session.upload_progress=Off, request-size bounds,
#                      worker recycling (pm.max_requests) — removes the
#                      cross-request requirement instead of gambling on it.
#   4. isolate         move webshell-shaped files out of the web root (kept,
#                      reversible) so a dropped shell cannot serve a second
#                      request while you are still investigating.
#   5. recycle         restart workers — exploit state lives in long-lived
#                      process memory, so a "patched on disk" host is still
#                      exploitable until every worker has been replaced.
#
# Everything here is reversible through ./rollback.sh: config edits are backed
# up, created files are recorded, and quarantined files keep their original
# path in QUARANTINED.txt.
# ==============================================================================

[ -n "${P2S_CONTAIN_LOADED:-}" ] && return 0
P2S_CONTAIN_LOADED=1

CONTAIN_ACTIONS=()

_contain_note() { CONTAIN_ACTIONS[${#CONTAIN_ACTIONS[@]}]="$1"; action_note "$1"; }

# ------------------------------------------------------------------------------
# entry point
# ------------------------------------------------------------------------------
contain_all() {
  step "Containment — cutting the exploitation channel"
  p2s_backup_init
  local failed=0

  contain_edge_nginx   || failed=$((failed+1))
  contain_edge_apache  || failed=$((failed+1))
  contain_runtime_mitigations || failed=$((failed+1))
  contain_emit_guards  || failed=$((failed+1))
  [ "$P2S_QUARANTINE" = 1 ] && { contain_quarantine || failed=$((failed+1)); }
  contain_recycle_workers || failed=$((failed+1))

  if [ "$failed" -gt 0 ]; then
    err "containment finished with $failed failed step(s) — the host may still be exposed"
    return 1
  fi
  ok "containment applied (${#CONTAIN_ACTIONS[@]} action(s))"
  info "containment is not a patch: run './setup.sh --fix' to close the vulnerability itself."
  return 0
}

# ------------------------------------------------------------------------------
# 1a. nginx — include a deny-br guard inside every server block that serves PHP
# ------------------------------------------------------------------------------
contain_edge_nginx() {
  [ "$NGINX_PRESENT" = 1 ] || { info "nginx not detected — no nginx guard needed"; return 0; }

  local dir target inc f modified=""
  dir="${NGINX_CONF_DIRS[0]:-/etc/nginx}"
  target="$dir/p2s-deny-br.conf"
  inc="include $target;"

  step "nginx: refusing Brotli-compressed request bodies"
  require_root_for "nginx containment"

  if [ -f "$target" ]; then
    backup_file "$target" >/dev/null 2>&1 || true
  else
    record_created "$target"
  fi
  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would write $target"
  else
    if cp "$P2S_CONTAIN_DIR/snippets/nginx-deny-br.conf" "$target"; then
      ok "wrote $target"
      _contain_note "NGINX $target: deny-br snippet installed"
    else
      err "could not write $target"
      return 1
    fi
  fi

  for f in ${NGINX_PHP_CONFS[@]+"${NGINX_PHP_CONFS[@]}"}; do
    case "$f" in "$target") continue ;; esac
    if grep -q 'p2s-deny-br\.conf' "$f" 2>/dev/null; then
      info "$f already guarded"
      continue
    fi
    if [ ! -w "$f" ]; then
      warn "$f not writable — guard NOT applied there"
      continue
    fi
    backup_file "$f" >/dev/null 2>&1 || true
    modified="$modified $f"
    if [ "$P2S_DRY_RUN" = 1 ]; then
      info "[dry] would insert '$inc' into server blocks of $f"
      _contain_note "NGINX $f: deny-br include (dry-run)"
      continue
    fi
    awk -v inc="$inc" '
      { print }
      /server[[:space:]]*\{/ {
        print "        # protection2shell: refuse Brotli request bodies (CVE-2026-111497)"
        print "        " inc
      }
    ' "$f" > "$f.p2snew" && mv "$f.p2snew" "$f" || { err "edit failed: $f"; return 1; }
    ok "guarded $f"
    _contain_note "NGINX $f: deny-br include inserted"
  done

  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would validate with nginx -t"
    return 0
  fi
  if have_cmd nginx; then
    if nginx -t >/dev/null 2>&1; then
      ok "nginx configuration test passed"
    else
      err "nginx -t FAILED after adding the guard — rolling the edits back"
      for f in $modified; do restore_file "$f" || true; done
      rm -f "$target"
      return 1
    fi
  else
    warn "nginx binary not found — cannot validate; guard written but unverified"
  fi
}

# ------------------------------------------------------------------------------
# 1b. Apache — conf snippet + enable + configtest
# ------------------------------------------------------------------------------
contain_edge_apache() {
  [ "$APACHE_PRESENT" = 1 ] || { info "Apache not detected — no Apache guard needed"; return 0; }

  local target enabled="" testcmd=""
  step "Apache: refusing Brotli-compressed request bodies"
  require_root_for "Apache containment"

  if [ -d /etc/apache2/conf-available ]; then
    target="/etc/apache2/conf-available/protection2shell-deny-br.conf"
    enabled="/etc/apache2/conf-enabled/protection2shell-deny-br.conf"
  elif [ -d /etc/httpd/conf.d ]; then
    target="/etc/httpd/conf.d/protection2shell-deny-br.conf"
  elif [ -d /usr/local/etc/httpd/conf.d ]; then
    target="/usr/local/etc/httpd/conf.d/protection2shell-deny-br.conf"
  elif [ -d /opt/homebrew/etc/httpd/conf.d ]; then
    target="/opt/homebrew/etc/httpd/conf.d/protection2shell-deny-br.conf"
  else
    warn "no writable Apache conf.d directory found — guard not applied"
    return 0
  fi

  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would write $target"
    [ -n "$enabled" ] && info "[dry] would enable it via $enabled"
    return 0
  fi

  if [ -f "$target" ]; then backup_file "$target" >/dev/null 2>&1 || true; else record_created "$target"; fi
  cp "$P2S_CONTAIN_DIR/snippets/apache-deny-br.conf" "$target" \
    || { err "could not write $target"; return 1; }
  ok "wrote $target"
  _contain_note "APACHE $target: deny-br snippet installed"

  if [ -n "$enabled" ]; then
    record_created "$enabled"
    ln -sfn "../conf-available/$(basename "$target")" "$enabled" \
      && { ok "enabled $enabled"; _contain_note "APACHE $enabled: enabled"; } \
      || { err "could not enable $enabled"; return 1; }
  fi

  for testcmd in "apachectl configtest" "apache2ctl configtest" "httpd -t"; do
    set -- $testcmd
    have_cmd "$1" || continue
    if "$@" >/dev/null 2>&1; then
      ok "$testcmd passed"
      return 0
    fi
    err "$testcmd FAILED after adding the guard — rolling back"
    rm -f "$target"
    [ -n "$enabled" ] && rm -f "$enabled"
    return 1
  done
  warn "no Apache configtest binary found — guard written but unverified"
}

# ------------------------------------------------------------------------------
# 2. runtime mitigations that exist today (PHP side of the same doctrine)
# ------------------------------------------------------------------------------
contain_runtime_mitigations() {
  if [ "${#PHP_RECS[@]}" -eq 0 ] && [ "${#FPM_POOLS[@]}" -eq 0 ]; then
    debug "no PHP runtime to mitigate"
    return 0
  fi
  step "PHP runtime: killing producers and shortening worker lifetime"
  fix_ini_hardening || return 1
  fix_fpm_pools || return 1
  _contain_note "PHP: ini drop-in + FPM pool mitigations applied"
  return 0
}

# ------------------------------------------------------------------------------
# 3. in-process guards (the outbound direction)
# ------------------------------------------------------------------------------
contain_emit_guards() {
  local sd node_guard py_guard readme
  sd="$(p2s_state_dir)/contain"
  step "Emitting in-process guards to $sd"
  require_root_for "guard installation"

  node_guard="$sd/node-p2s-guard.cjs"
  py_guard="$sd/python-p2s-guard.py"
  readme="$sd/CONTAINMENT-README.txt"

  if [ "$P2S_DRY_RUN" = 1 ]; then
    info "[dry] would install $node_guard, $py_guard, envoy snippet and Windows kit"
    return 0
  fi

  mkdir -p "$sd" || { err "cannot create $sd"; return 1; }
  cp "$P2S_CONTAIN_DIR/guards/node-p2s-guard.cjs" "$node_guard" || return 1
  cp "$P2S_CONTAIN_DIR/guards/python-p2s-guard.py" "$py_guard" || return 1
  cp "$P2S_CONTAIN_DIR/snippets/envoy-remove-brotli-decompressor.yaml" "$sd/" 2>/dev/null || true
  cp "$P2S_CONTAIN_DIR/windows-iis-http2shell.ps1" "$sd/" 2>/dev/null || true
  record_created "$node_guard"
  record_created "$py_guard"

  cat > "$readme" <<EOF
protection2shell — containment artifacts
========================================
Installed $(date -u +%Y-%m-%dT%H:%M:%SZ) by $(basename "$0")

These files are guards, not patches. They make the vulnerable decode path
unreachable; only upgrading the runtime/decoder removes it.

1) Node.js / Bun  ($node_guard)
   Refuses inbound requests with "Content-Encoding: br" (415) and disables
   zlib.brotliDecompress*/BrotliDecompress. OUTBOUND fetch() responses cannot be
   guarded in-process — keep untrusted egress away from this runtime or upgrade.

   systemd drop-in for each service:
       mkdir -p /etc/systemd/system/<unit>.d
       cat > /etc/systemd/system/<unit>.d/protection2shell-guard.conf <<'CONF'
       [Service]
       Environment=NODE_OPTIONS=--require $node_guard
       CONF
       systemctl daemon-reload && systemctl restart <unit>

2) Python  ($py_guard)
   Fails closed in urllib3/requests, httpx, aiohttp and the brotli modules.
   Install as sitecustomize.py on PYTHONPATH, or import it from your entry point.
   Then upgrade: pip install -U "brotli>=1.2.1" "brotlicffi>=1.2.1.0"
   (regenerate lockfiles and rebuild images — a running container keeps the old
   wheel until it is rebuilt).

3) Envoy / Istio  (envoy-remove-brotli-decompressor.yaml)
   Remove the brotli *decompressor* filter entry, then patch to
   1.40.0 / 1.39.3 / 1.38.6 / 1.37.8 (Istio 1.31.2 / 1.30.6 / 1.29.9).

4) Windows / IIS  (windows-iis-http2shell.ps1)
   .\\windows-iis-http2shell.ps1 -SitePath C:\\inetpub\\wwwroot

Remove all of this with: ./rollback.sh
EOF
  record_created "$readme"
  ok "guards installed in $sd"
  _contain_note "GUARDS $sd: node/python/envoy/windows containment artifacts"

  if [ "${#P2S_NODE_SERVICES[@]}" -gt 0 ]; then
    info "node/bun services detected — wire the guard, then restart them:"
    local s
    for s in ${P2S_NODE_SERVICES[@]+"${P2S_NODE_SERVICES[@]}"}; do
      info "    $s"
    done
  fi
  return 0
}

# ------------------------------------------------------------------------------
# 4. quarantine webshell-shaped artifacts (kept, reversible)
# ------------------------------------------------------------------------------
contain_quarantine() {
  local roots="" r f dest n=0
  step "Quarantining webshell-shaped files (reversible)"
  require_root_for "quarantine"

  for r in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
    roots="$roots $(printf '%s' "$r" | cut -d'|' -f1)"
  done
  for r in /var/www /srv/www /usr/share/nginx/html /usr/share/httpd; do
    [ -d "$r" ] && roots="$roots $r"
  done

  # Only high-confidence shapes. Recent-but-ordinary PHP is NOT touched: a
  # deploy would be indistinguishable from a dropping, and moving a live file is
  # an outage, not containment.
  for r in $roots; do
    [ -d "$r" ] || continue
    for f in $(find "$r" -type f \
                 \( -name '.*.php' -o -name '*.php.jpg' -o -name '*.php.png' \
                    -o -name '*.php.gif' -o -name '*.php.txt' -o -name '*.php.bak' \) \
                 2>/dev/null | head -100); do
      case "$f" in
        */vendor/*|*/node_modules/*|*/.git/*|*/cache/*|*/storage/framework/*) continue ;;
      esac
      [ -L "$f" ] && continue
      printf '%s\n' "  candidate: $f"
      n=$((n+1))
    done
    # PHP inside an upload directory
    for f in $(find "$r" -type d -iname '*upload*' 2>/dev/null | while IFS= read -r d; do
                 find "$d" -maxdepth 2 -type f -name '*.php' 2>/dev/null; done | head -100); do
      case "$f" in */vendor/*|*/node_modules/*) continue ;; esac
      [ -L "$f" ] && continue
      printf '%s\n' "  candidate: $f"
      n=$((n+1))
    done
  done

  if [ "$n" -eq 0 ]; then
    info "no webshell-shaped files found — nothing to quarantine"
    _contain_note "QUARANTINE: no candidates"
    return 0
  fi

  if ! confirm "Quarantine $n file(s) into ${P2S_BACKUP_DIR}/quarantine (reversible with rollback.sh)?"; then
    info "quarantine skipped by user"
    return 0
  fi

  # Re-walk and move (the confirmation above decided *whether*, not *what*).
  local moved=0
  for r in $roots; do
    [ -d "$r" ] || continue
    for f in $(find "$r" -type f \
                 \( -name '.*.php' -o -name '*.php.jpg' -o -name '*.php.png' \
                    -o -name '*.php.gif' -o -name '*.php.txt' -o -name '*.php.bak' \) \
                 2>/dev/null | head -100); do
      case "$f" in */vendor/*|*/node_modules/*|*/.git/*|*/cache/*|*/storage/framework/*) continue ;; esac
      dest="$(quarantine_file "$f")" && { ok "quarantined $f -> $dest"; moved=$((moved+1)); }
    done
    for f in $(find "$r" -type d -iname '*upload*' 2>/dev/null | while IFS= read -r d; do
                 find "$d" -maxdepth 2 -type f -name '*.php' 2>/dev/null; done | head -100); do
      case "$f" in */vendor/*|*/node_modules/*) continue ;; esac
      dest="$(quarantine_file "$f")" && { ok "quarantined $f -> $dest"; moved=$((moved+1)); }
    done
  done
  _contain_note "QUARANTINE: $moved file(s) moved to ${P2S_BACKUP_DIR}/quarantine"
  warn "quarantined files are evidence: review them before deleting anything"
}

# ------------------------------------------------------------------------------
# 5. recycle every worker (exploit state lives in process memory)
# ------------------------------------------------------------------------------
contain_recycle_workers() {
  step "Recycling workers so no existing process keeps exploit state"
  fix_restart_workers || return 1
  if [ "${#P2S_NODE_SERVICES[@]}" -gt 0 ]; then
    info "node/bun services are NOT restarted automatically (that is your change"
    info "window): ${P2S_NODE_SERVICES[*]}"
  fi
  return 0
}
