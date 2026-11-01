#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/report.sh
# Human-readable report + machine-readable JSON report.
# ==============================================================================

[ -n "${P2S_REPORT_LOADED:-}" ] && return 0
P2S_REPORT_LOADED=1

cve_color() {
  case "$1" in
    FIXED|MITIGATED|NOT-AFFECTED|NOT-FOUND) printf '%s' "$C_GREEN" ;;
    VULNERABLE) printf '%s' "$C_RED" ;;
    MITIGATE|UNKNOWN) printf '%s' "$C_YELLOW" ;;
    *) printf '%s' "$C_YELLOW" ;;
  esac
}

report_human() {
  step "Security report"
  log "${C_BOLD}Host:${C_RESET}  $OS_PRETTY  (family=$OS_FAMILY, pkg=$PKG_MGR)"

  log ""
  log "${C_BOLD}PHP installations:${C_RESET}"
  if [ "${#PHP_RECS[@]}" -eq 0 ]; then
    log "  (none found)"
  else
    local rec
    for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
      local v st
      v="$(rec_version "$rec")"
      st="$(php2shell_status "$v")"
      log "  $(rec_bin "$rec")"
      log "    version : $v   SAPI: $(rec_sapi "$rec")"
      log "    PHP2Shell: $(cve_color "$st")${st}${C_RESET}  (fixed in: $(php2shell_fixed_for "$v"))"
      log "    ini: $(rec_ini "$rec" | sed 's/^$/(default)/')  scan: $(rec_scandir "$rec" | sed 's/^$/(none)/')"
    done
  fi

  if [ "${#FPM_POOLS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}PHP-FPM pools:${C_RESET}"
    local p
    for p in ${FPM_POOLS[@]+"${FPM_POOLS[@]}"}; do
      log "  $(printf '%s' "$p" | cut -d'|' -f1)  (user=$(printf '%s' "$p" | cut -d'|' -f2), listen=$(printf '%s' "$p" | cut -d'|' -f4), pm.max_requests=$(printf '%s' "$p" | cut -d'|' -f5))"
    done
  fi

  log ""
  log "${C_BOLD}Web servers:${C_RESET}"
  log "  nginx: $([ "$NGINX_PRESENT" = 1 ] && echo "yes (${#NGINX_PHP_CONFS[@]} php conf(s))" || echo no)"
  log "  apache: $([ "$APACHE_PRESENT" = 1 ] && echo "yes (modules: ${APACHE_MODULES:-?})" || echo no)"
  log "  litespeed: $([ "$LITESPEED_PRESENT" = 1 ] && echo yes || echo no)   frankenphp: $([ "$FRANKENPHP_PRESENT" = 1 ] && echo yes || echo no)"

  if [ "${#PROJECT_RECS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}Projects:${C_RESET}"
    local pr
    for pr in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
      log "  [$(printf '%s' "$pr" | cut -d'|' -f2)] $(printf '%s' "$pr" | cut -d'|' -f1)  ver=$(printf '%s' "$pr" | cut -d'|' -f3)  php-req=$(printf '%s' "$pr" | cut -d'|' -f4)"
    done
  fi

  log ""
  log "${C_BOLD}CVE verdicts:${C_RESET}"
  local r id status ev fx
  for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
    id="$(printf '%s' "$r" | cut -d'|' -f1)"
    status="$(printf '%s' "$r" | cut -d'|' -f2)"
    ev="$(printf '%s' "$r" | cut -d'|' -f3)"
    fx="$(printf '%s' "$r" | cut -d'|' -f4)"
    printf '  %s%-20s %-13s%s %s\n' "$(cve_color "$status")" "$id" "$status" "$C_RESET" "$ev"
    [ "$fx" != "-" ] && log "      fix: $fx"
  done

  # ---- HTTP2Shell (CVE-2026-111497) ------------------------------------------
  if [ "${#BROTLI_RECS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}Brotli decoder carriers (HTTP2Shell, $BROTLI_CVE):${C_RESET}"
    local br bst
    for br in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
      bst="$(brotli_record_status "$br")"
      log "  $(cve_color "$bst")$(printf '%-16s' "$bst")${C_RESET} $(printf '%s' "$br" | cut -d'|' -f1) $(printf '%s' "$br" | cut -d'|' -f3)"
      log "      path: $(printf '%s' "$br" | cut -d'|' -f4)"
      log "      evidence: $(printf '%s' "$br" | cut -d'|' -f5)"
      log "      fix: $(brotli_fixed_for "$(printf '%s' "$br" | cut -d'|' -f1)" "$(printf '%s' "$br" | cut -d'|' -f3)")"
    done
  fi

  if [ "${#BROTLI_FINDINGS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}HTTP2Shell findings:${C_RESET}"
    local bf
    for bf in ${BROTLI_FINDINGS[@]+"${BROTLI_FINDINGS[@]}"}; do
      printf '  [%-8s] %-22s %s\n' \
        "$(printf '%s' "$bf" | cut -d'|' -f2)" \
        "$(printf '%s' "$bf" | cut -d'|' -f1)" \
        "$(printf '%s' "$bf" | cut -d'|' -f4)"
      log "      target: $(printf '%s' "$bf" | cut -d'|' -f3)"
      log "      fix:    $(printf '%s' "$bf" | cut -d'|' -f5)"
    done
    log ""
    brotli_status_note | sed 's/^/  /'
  fi

  if [ "${#HARDENING_RECORDS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}Hardening findings:${C_RESET}"
    for r in ${HARDENING_RECORDS[@]+"${HARDENING_RECORDS[@]}"}; do
      printf '  [%-8s] %-22s %s\n' \
        "$(printf '%s' "$r" | cut -d'|' -f2)" \
        "$(printf '%s' "$r" | cut -d'|' -f1)" \
        "$(printf '%s' "$r" | cut -d'|' -f4)"
      log "      target: $(printf '%s' "$r" | cut -d'|' -f3)"
      log "      fix:    $(printf '%s' "$r" | cut -d'|' -f5)"
    done
  fi

  if [ "${#P2S_ACTIONS[@]}" -gt 0 ]; then
    log ""
    log "${C_BOLD}Actions:${C_RESET}"
    local a
    for a in ${P2S_ACTIONS[@]+"${P2S_ACTIONS[@]}"}; do log "  * $a"; done
  fi
}

# ------------------------------------------------------------------------------
report_json() { # report_json <outfile>
  local out="$1" rec first
  {
    printf '{\n'
    printf '  "generated_at": "%s",\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "dry_run": %s,\n' "$([ "$P2S_DRY_RUN" = 1 ] && echo true || echo false)"
    printf '  "host": {\n'
    printf '    "os": "%s",\n' "$(json_escape "$OS_PRETTY")"
    printf '    "os_id": "%s",\n' "$(json_escape "$OS_ID")"
    printf '    "os_family": "%s",\n' "$(json_escape "$OS_FAMILY")"
    printf '    "package_manager": "%s"\n' "$(json_escape "$PKG_MGR")"
    printf '  },\n'

    printf '  "php_installs": ['
    first=1
    for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    {"bin": "%s", "version": "%s", "sapi": "%s", "ini": "%s", "scan_dir": "%s", "php2shell": "%s"}' \
        "$(json_escape "$(rec_bin "$rec")")" \
        "$(json_escape "$(rec_version "$rec")")" \
        "$(json_escape "$(rec_sapi "$rec")")" \
        "$(json_escape "$(rec_ini "$rec")")" \
        "$(json_escape "$(rec_scandir "$rec")")" \
        "$(json_escape "$(php2shell_status "$(rec_version "$rec")")")"
    done
    printf '\n  ],\n'

    printf '  "fpm_pools": ['
    first=1
    for rec in ${FPM_POOLS[@]+"${FPM_POOLS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    {"conf": "%s", "user": "%s", "listen": "%s", "pm_max_requests": "%s", "hardened": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f5)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f8)")"
    done
    printf '\n  ],\n'

    printf '  "projects": ['
    first=1
    for rec in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    {"path": "%s", "type": "%s", "version": "%s", "php_constraint": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f3)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")"
    done
    printf '\n  ],\n'

    printf '  "cves": ['
    first=1
    for rec in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    {"id": "%s", "status": "%s", "evidence": "%s", "fix": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f3)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")"
    done
    printf '\n  ],\n'

    printf '  "tool": {"name": "protection2shell", "version": "%s"},\n' "$P2S_TOOL_VERSION"

    printf '  "http2shell": {\n'
    printf '    "cve": "%s",\n' "$BROTLI_CVE"
    printf '    "carriers": ['
    first=1
    for rec in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n      {"carrier": "%s", "name": "%s", "version": "%s", "path": "%s", "evidence": "%s", "certainty": "%s", "status": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f3)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f5)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f6)")" \
        "$(json_escape "$(brotli_record_status "$rec")")"
    done
    printf '\n    ],\n'
    printf '    "findings": ['
    first=1
    for rec in ${BROTLI_FINDINGS[@]+"${BROTLI_FINDINGS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n      {"id": "%s", "severity": "%s", "target": "%s", "message": "%s", "fix": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f3)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f5)")"
    done
    printf '\n    ]\n'
    printf '  },\n'

    printf '  "verification": {"verified": %s, "pending": %s, "unknown": %s},\n' \
      "${P2S_VERIFIED:-0}" "${P2S_PENDING:-0}" "${P2S_UNKNOWN:-0}"

    printf '  "hardening_findings": ['
    first=1
    for rec in ${HARDENING_RECORDS[@]+"${HARDENING_RECORDS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    {"id": "%s", "severity": "%s", "target": "%s", "message": "%s", "fix": "%s"}' \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f1)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f2)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f3)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f4)")" \
        "$(json_escape "$(printf '%s' "$rec" | cut -d'|' -f5)")"
    done
    printf '\n  ],\n'

    printf '  "actions": ['
    first=1
    for rec in ${P2S_ACTIONS[@]+"${P2S_ACTIONS[@]}"}; do
      [ "$first" = 1 ] || printf ','
      first=0
      printf '\n    "%s"' "$(json_escape "$rec")"
    done
    printf '\n  ]\n'
    printf '}\n'
  } > "$out"
  ok "JSON report written to $out"
}

# exit code helper: 2 when unpatched critical exposure remains (audit mode)
report_exit_code() {
  local r status worst=0
  for r in ${CVE_RECORDS[@]+"${CVE_RECORDS[@]}"}; do
    status="$(printf '%s' "$r" | cut -d'|' -f2)"
    case "$status" in VULNERABLE|MITIGATE) return 2 ;; esac
  done
  return 0
}
