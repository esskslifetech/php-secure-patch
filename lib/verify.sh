#!/usr/bin/env bash
# ==============================================================================
# protection2shell :: lib/verify.sh
# Post-remediation verification: "did the fix actually land on this host?"
#
# This exists because the two failure modes that matter are both silent:
#   * the package is fixed but the process was never restarted (exploit state
#     lives in worker memory — on-disk correctness is not runtime correctness);
#   * the version string says patched while the decoder in the running binary is
#     still vulnerable (Node keeps reporting brotli 1.2.0 after the fix; Debian
#     keeps the upstream version and appends a revision).
#
# Verification therefore reports three states per item: ok / pending / unknown.
# "unknown" is never folded into "ok" — a false clean bill is worse than a
# visible gap.
# ==============================================================================

[ -n "${P2S_VERIFY_LOADED:-}" ] && return 0
P2S_VERIFY_LOADED=1

P2S_VERIFIED=0
P2S_PENDING=0
P2S_UNKNOWN=0
VERIFY_ROWS=()

_v_ok()      { P2S_VERIFIED=$((P2S_VERIFIED+1)); VERIFY_ROWS[${#VERIFY_ROWS[@]}]="ok|$1|$2"; }
_v_pending() { P2S_PENDING=$((P2S_PENDING+1));   VERIFY_ROWS[${#VERIFY_ROWS[@]}]="pending|$1|$2"; }
_v_unknown() { P2S_UNKNOWN=$((P2S_UNKNOWN+1));   VERIFY_ROWS[${#VERIFY_ROWS[@]}]="unknown|$1|$2"; }

_v_color() {
  case "$1" in
    ok)      printf '%s' "$C_GREEN" ;;
    pending) printf '%s' "$C_RED" ;;
    *)       printf '%s' "$C_YELLOW" ;;
  esac
}

# ------------------------------------------------------------------------------
# PHP side
# ------------------------------------------------------------------------------
verify_php() {
  local rec bin ver st ini scan dropin
  for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
    bin="$(rec_bin "$rec")"; ver="$(rec_version "$rec")"
    ini="$(rec_ini "$rec")"; scan="$(rec_scandir "$rec")"
    st="$(php2shell_status "$ver")"
    case "$st" in
      FIXED|NOT-AFFECTED)
        _v_ok "PHP PHP2Shell" "$bin — PHP $ver ($st)" ;;
      *)
        _v_pending "PHP PHP2Shell" "$bin — PHP $ver still $st; fixed release: $(php2shell_fixed_for "$ver")" ;;
    esac

    dropin=""
    [ -n "$scan" ] && [ -f "$scan/99-p2s-hardening.ini" ] && dropin="$scan/99-p2s-hardening.ini"
    [ -z "$dropin" ] && [ -n "$ini" ] && [ -f "$(dirname "$ini")/99-p2s-hardening.ini" ] \
      && dropin="$(dirname "$ini")/99-p2s-hardening.ini"
    if [ -n "$dropin" ]; then
      if grep -q 'session.upload_progress.enabled *= *Off' "$dropin" 2>/dev/null; then
        _v_ok "PHP containment" "$dropin present, session.upload_progress disabled"
      else
        _v_pending "PHP containment" "$dropin present but does not disable session.upload_progress"
      fi
    else
      _v_unknown "PHP containment" "no 99-p2s-hardening.ini drop-in found for $bin"
    fi
  done
}

# ------------------------------------------------------------------------------
# HTTP2Shell side
# ------------------------------------------------------------------------------
verify_brotli() {
  local rec carrier name ver path cert st fix
  for rec in ${BROTLI_RECS[@]+"${BROTLI_RECS[@]}"}; do
    carrier="$(printf '%s' "$rec" | cut -d'|' -f1)"
    name="$(printf '%s' "$rec" | cut -d'|' -f2)"
    ver="$(printf '%s' "$rec" | cut -d'|' -f3)"
    path="$(printf '%s' "$rec" | cut -d'|' -f4)"
    cert="$(printf '%s' "$rec" | cut -d'|' -f6)"
    st="$(brotli_record_status "$rec")"
    fix="$(brotli_fixed_for "$carrier" "$ver")"
    case "$st" in
      FIXED|NOT-AFFECTED)
        if [ "$cert" = "high" ]; then
          _v_ok "HTTP2Shell $carrier" "$name at $path — $st (capability-verified)"
        else
          _v_unknown "HTTP2Shell $carrier" "$name at $path — version says $st, certainty $cert (probe the binary)"
        fi ;;
      *)
        _v_pending "HTTP2Shell $carrier" "$name at $path — $st; fix: $fix" ;;
    esac
  done
}

# ------------------------------------------------------------------------------
# containment artifacts
# ------------------------------------------------------------------------------
verify_containment() {
  local d target f found=0 sd
  if [ "$NGINX_PRESENT" = 1 ]; then
    d="${NGINX_CONF_DIRS[0]:-/etc/nginx}"
    target="$d/p2s-deny-br.conf"
    if [ -f "$target" ]; then
      _v_ok "containment nginx" "$target installed"
    else
      _v_pending "containment nginx" "no deny-br snippet in $d (run --contain)"
    fi
    for f in ${NGINX_PHP_CONFS[@]+"${NGINX_PHP_CONFS[@]}"}; do
      if grep -q 'p2s-deny-br\.conf' "$f" 2>/dev/null; then found=$((found+1)); fi
    done
    if [ "${#NGINX_PHP_CONFS[@]}" -gt 0 ] && [ "$found" -eq 0 ]; then
      _v_pending "containment nginx" "no server block includes the deny-br guard"
    fi
  fi

  if [ "$APACHE_PRESENT" = 1 ]; then
    if [ -f /etc/apache2/conf-enabled/protection2shell-deny-br.conf ] \
       || [ -f /etc/apache2/conf-available/protection2shell-deny-br.conf ] \
       || [ -f /etc/httpd/conf.d/protection2shell-deny-br.conf ]; then
      _v_ok "containment apache" "deny-br snippet installed"
    else
      _v_pending "containment apache" "no deny-br snippet (run --contain)"
    fi
  fi

  sd="$(p2s_state_dir)/contain"
  if [ -f "$sd/node-p2s-guard.cjs" ] || [ -f "$sd/python-p2s-guard.py" ]; then
    _v_ok "containment process guards" "$sd (node/python guards emitted)"
  else
    _v_unknown "containment process guards" "no guards in $sd (only needed for Node/Python carriers)"
  fi
}

# ------------------------------------------------------------------------------
# entry point
# ------------------------------------------------------------------------------
verify_all() {
  P2S_VERIFIED=0; P2S_PENDING=0; P2S_UNKNOWN=0; VERIFY_ROWS=()
  step "Verification"

  verify_php
  verify_brotli
  verify_containment

  local row state what detail
  for row in ${VERIFY_ROWS[@]+"${VERIFY_ROWS[@]}"}; do
    state="${row%%|*}"
    row="${row#*|}"
    what="${row%%|*}"
    detail="${row#*|}"
    printf '  %s[%-7s]%s %-28s %s\n' \
      "$(_v_color "$state")" "$state" "$C_RESET" "$what" "$detail"
  done

  log ""
  log "  verified: $P2S_VERIFIED   pending: $P2S_PENDING   unknown: $P2S_UNKNOWN"
  if [ "$P2S_PENDING" -gt 0 ]; then
    warn "$P2S_PENDING item(s) still need action — this host is not fixed yet"
    return 1
  fi
  if [ "$P2S_UNKNOWN" -gt 0 ]; then
    info "$P2S_UNKNOWN item(s) could not be verified from this host (containers,"
    info "vendored builds and remote runtimes are invisible here) — investigate"
    info "before recording this host as clean."
    return 0
  fi
  ok "every verifiable item on this host is fixed"
  return 0
}
