#!/usr/bin/env bash
# ==============================================================================
# php-secure-patch :: lib/detect.sh
# Detects: operating system, package manager, every PHP installation + version
# + SAPI + ini state, PHP-FPM pools, web servers (nginx/Apache/LiteSpeed/
# FrankenPHP/php-cgi) and PHP projects on disk (WordPress, Joomla, Drupal,
# Moodle, MediaWiki, phpBB, Composer/Laravel/Symfony/Magento...).
#
# Result globals (all set by detect_all):
#   OS_ID OS_VERSION_ID OS_FAMILY OS_PRETTY OS_KERNEL PKG_MGR IS_WINDOWS
#   PHP_RECS[]   bin|version|sapi|ini_file|scan_dir|k=v;k=v;...
#   FPM_RECS[]   bin|version
#   FPM_POOLS[]  conf|user|group|listen|pm_max_requests|memory_limit|limit_ext|hardened
#   NGINX_PRESENT NGINX_CONF_DIRS[] NGINX_PHP_CONFS[] NGINX_SPLITPATH_CONFS[]
#   APACHE_PRESENT APACHE_BIN APACHE_CONF_DIRS[] APACHE_MODULES
#   LITESPEED_PRESENT LSAPI_BINS[] FRANKENPHP_PRESENT CGI_BINS[]
#   PROJECT_RECS[] path|type|version|php_constraint|extra
# ==============================================================================

[ -n "${PSP_DETECT_LOADED:-}" ] && return 0
PSP_DETECT_LOADED=1

OS_ID=""; OS_VERSION_ID=""; OS_FAMILY=""; OS_PRETTY=""; OS_KERNEL=""; PKG_MGR=""; IS_WINDOWS=0
PHP_RECS=()
FPM_RECS=(); FPM_POOLS=()
NGINX_PRESENT=0; NGINX_CONF_DIRS=(); NGINX_PHP_CONFS=(); NGINX_SPLITPATH_CONFS=()
APACHE_PRESENT=0; APACHE_BIN=""; APACHE_CONF_DIRS=(); APACHE_MODULES=""
LITESPEED_PRESENT=0; LSAPI_BINS=(); FRANKENPHP_PRESENT=0; CGI_BINS=()
PROJECT_RECS=()

# field helpers for PHP_RECS entries
rec_bin()       { printf '%s' "$1" | cut -d'|' -f1; }
rec_version()   { printf '%s' "$1" | cut -d'|' -f2; }
rec_sapi()      { printf '%s' "$1" | cut -d'|' -f3; }
rec_ini()       { printf '%s' "$1" | cut -d'|' -f4; }
rec_scandir()   { printf '%s' "$1" | cut -d'|' -f5; }
rec_setting() { # rec_setting <record> <ini-key>
  printf '%s' "$1" | cut -d'|' -f6 | tr ';' '\n' \
    | awk -F= -v k="$2" '$1==k {sub(/^[^=]*=/,""); print; exit}'
}

# ------------------------------------------------------------------------------
# OS / package manager
# ------------------------------------------------------------------------------
detect_os() {
  OS_KERNEL="$(uname -s 2>/dev/null || echo unknown)"
  case "$OS_KERNEL" in
    MINGW*|MSYS*|CYGWIN*|Windows_NT) IS_WINDOWS=1 ;;
  esac

  if [ "$IS_WINDOWS" = 1 ]; then
    OS_ID="windows"; OS_FAMILY="windows"; OS_PRETTY="Windows ($OS_KERNEL)"
  elif [ -f /etc/os-release ]; then
    # shellcheck disable=SC1091
    OS_ID="$(. /etc/os-release 2>/dev/null && echo "${ID:-unknown}")"
    OS_VERSION_ID="$(. /etc/os-release 2>/dev/null && echo "${VERSION_ID:-}")"
    OS_PRETTY="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$OS_ID}")"
  elif [ "$OS_KERNEL" = "Darwin" ]; then
    OS_ID="macos"; OS_PRETTY="macOS $(sw_vers -productVersion 2>/dev/null)"
  else
    OS_ID="unknown"; OS_PRETTY="$OS_KERNEL"
  fi

  case "$OS_ID" in
    debian|ubuntu|linuxmint|pop|kali|raspbian|elementary|zorin) OS_FAMILY="debian" ;;
    rhel|centos|rocky|almalinux|fedora|oracle|amzn)             OS_FAMILY="rhel" ;;
    alpine)                                                     OS_FAMILY="alpine" ;;
    arch|manjaro|endeavouros)                                   OS_FAMILY="arch" ;;
    sles|suse|opensuse*|opensuse-leap|opensuse-tumbleweed)      OS_FAMILY="suse" ;;
    macos)                                                      OS_FAMILY="macos" ;;
    windows)                                                    OS_FAMILY="windows" ;;
    *)                                                          OS_FAMILY="other" ;;
  esac

  if   have_cmd apt-get; then PKG_MGR="apt-get"
  elif have_cmd dnf;      then PKG_MGR="dnf"
  elif have_cmd yum;      then PKG_MGR="yum"
  elif have_cmd apk;      then PKG_MGR="apk"
  elif have_cmd pacman;   then PKG_MGR="pacman"
  elif have_cmd zypper;   then PKG_MGR="zypper"
  elif have_cmd brew;     then PKG_MGR="brew"
  elif have_cmd choco;    then PKG_MGR="choco"
  else PKG_MGR="none"
  fi

  ok "system: $OS_PRETTY (family=$OS_FAMILY, pkg=$PKG_MGR)"
}

# ------------------------------------------------------------------------------
# PHP installations
# ------------------------------------------------------------------------------
_PSP_PROBE_PHP='
$keys = array("disable_functions","memory_limit","allow_url_include","allow_url_fopen",
  "cgi.fix_pathinfo","expose_php","phar.readonly","session.upload_progress.enabled",
  "session.cookie_httponly","session.cookie_secure","session.cookie_samesite",
  "session.use_strict_mode","max_execution_time","post_max_size","upload_max_filesize",
  "zend.assertions","display_errors","open_basedir","max_multipart_body_parts",
  "fatal_error_backtraces","opcache.enable","cgi.force_redirect");
$bools = array("allow_url_include","allow_url_fopen","cgi.fix_pathinfo","expose_php",
  "phar.readonly","session.upload_progress.enabled","session.cookie_httponly",
  "session.cookie_secure","session.use_strict_mode","display_errors",
  "fatal_error_backtraces","opcache.enable","cgi.force_redirect");
foreach ($keys as $k) {
  $v = ini_get($k);
  if ($v === false) {
    $out = "__unset__";                       // directive does not exist here
  } elseif (in_array($k, $bools, true)) {
    $out = ($v === "" || $v === "0" || strcasecmp($v, "Off") === 0 || strcasecmp($v, "No") === 0) ? "0" : "1";
  } else {
    $out = (string)$v;
  }
  $out = str_replace(array("|", ";"), array("/", ","), $out);
  echo $k, "=", $out, "\n";
}
'

php_candidates() {
  local c n
  for n in php php8.5 php8.4 php8.3 php8.2 php8.1 php8.0 php7.4 php7.3 php7.2 php7.1 \
           php-cgi php-cgi8.5 php-cgi8.4 php-cgi8.3 php-cgi8.2 php-cgi8.1 php-cgi8.0 \
           lsphp lsphp85 lsphp84 lsphp83 lsphp82 lsphp81; do
    c="$(command -v "$n" 2>/dev/null)" && printf '%s\n' "$c"
  done
  for c in /usr/bin/php* /usr/sbin/php* /usr/local/bin/php* /opt/homebrew/bin/php* \
           /usr/local/lsws/lsphp*/bin/lsphp* /usr/local/lsws/bin/lsphp* /opt/lampp/bin/php; do
    [ -f "$c" ] && [ -x "$c" ] && printf '%s\n' "$c"
  done
  if have_cmd update-alternatives; then
    update-alternatives --list php 2>/dev/null
  fi
}

probe_php_bin() { # -> prints one PHP_RECS line (or nothing)
  local bin="$1" base version sapi ini scan settings
  base="$(basename "$bin")"
  # only real interpreters: php, phpX.Y, php-cgi, lsphp...
  case "$base" in
    php|php[0-9]*|php-cgi|php-cgi[0-9]*|phpdbg|lsphp|lsphp[0-9]*) : ;;
    *) return 0 ;;
  esac
  case "$base" in phpdbg*) return 0 ;; esac

  version="$("$bin" -r 'echo PHP_VERSION;' 2>/dev/null)" || return 0
  [ -n "$version" ] || return 0
  sapi="$("$bin" -r 'echo php_sapi_name();' 2>/dev/null)"
  ini="$("$bin" --ini 2>/dev/null | awk -F': *' '/Loaded Config File/{print $2; exit}')"
  [ "$ini" = "(none)" ] && ini=""
  scan="$("$bin" --ini 2>/dev/null | awk -F': *' '/Scan for additional .ini files/{print $2; exit}')"
  [ "$scan" = "(none)" ] && scan=""
  settings="$("$bin" -r "$_PSP_PROBE_PHP" 2>/dev/null | tr '\n' ';')"
  printf '%s|%s|%s|%s|%s|%s\n' "$bin" "$version" "$sapi" "$ini" "$scan" "$settings"
}

detect_php_all() {
  local cand rec dup seen=""
  PHP_RECS=()
  while IFS= read -r cand; do
    [ -n "$cand" ] || continue
    case " $seen " in *" $cand "*) continue ;; esac
    seen="$seen $cand"
    rec="$(probe_php_bin "$cand")"
    if [ -n "$rec" ]; then
      PHP_RECS[${#PHP_RECS[@]}]="$rec"
      debug "php: $rec"
      case "$(rec_sapi "$rec")" in
        cgi|cgi-fcgi) CGI_BINS[${#CGI_BINS[@]}]="$(rec_bin "$rec")" ;;
      esac
    fi
  done <<EOF
$(php_candidates | sort -u)
EOF

  if [ "${#PHP_RECS[@]}" -eq 0 ]; then
    warn "no PHP interpreter found on PATH or in standard prefixes"
  else
    ok "found ${#PHP_RECS[@]} PHP installation(s)"
    for rec in ${PHP_RECS[@]+"${PHP_RECS[@]}"}; do
      log "     - $(rec_bin "$rec")  PHP $(rec_version "$rec")  [$(rec_sapi "$rec")]  ini=$(rec_ini "$rec" | sed 's/^$/(default)/')"
    done
  fi
}

# ------------------------------------------------------------------------------
# PHP-FPM
# ------------------------------------------------------------------------------
detect_fpm() {
  local c n bin version conf
  FPM_RECS=(); FPM_POOLS=()
  for n in php-fpm php-fpm8.5 php-fpm8.4 php-fpm8.3 php-fpm8.2 php-fpm8.1 php-fpm8.0 php-fpm7.4; do
    c="$(command -v "$n" 2>/dev/null)" || continue
    version="$("$c" -v 2>/dev/null | awk 'NR==1{print $2}')"
    FPM_RECS[${#FPM_RECS[@]}]="$c|$version"
  done
  for c in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm* /opt/homebrew/sbin/php-fpm* /usr/sbin/php-fpm8*; do
    [ -x "$c" ] || continue
    case " ${FPM_RECS[*]} " in *"|$c|"*|*" $c|"*) continue ;; esac
    version="$("$c" -v 2>/dev/null | awk 'NR==1{print $2}')"
    FPM_RECS[${#FPM_RECS[@]}]="$c|$version"
  done

  # pool configs
  local pooldirs="/etc/php /etc/php-fpm.d /etc/php-fpm.conf /usr/local/etc/php-fpm.d \
                  /opt/homebrew/etc/php /opt/homebrew/etc/php-fpm.conf"
  for conf in $(find /etc/php /usr/local/etc/php-fpm.d /opt/homebrew/etc/php \
                 -type f -name '*.conf' 2>/dev/null | grep -E 'fpm|pool' ; \
               ls /etc/php-fpm.conf /etc/php-fpm.d/*.conf 2>/dev/null); do
    [ -f "$conf" ] || continue
    # php-fpm.conf is the main config; pools are what we harden
    [ "$(basename "$conf")" = "php-fpm.conf" ] && continue
    grep -qE '^\s*\[|pm\.|listen\s*=' "$conf" 2>/dev/null || continue
    FPM_POOLS[${#FPM_POOLS[@]}]="$(fpm_pool_record "$conf")"
  done

  if [ "${#FPM_RECS[@]}" -gt 0 ]; then
    ok "PHP-FPM: ${#FPM_RECS[@]} binary/binaries, ${#FPM_POOLS[@]} pool config(s)"
  else
    debug "no php-fpm binary found"
  fi
}

fpm_pool_record() {
  local conf="$1" user group listen pmmr mem lim hardened="no"
  user="$(awk -F= '/^[[:space:]]*user[[:space:]]*=/{gsub(/[ \t]/,"",$2);print $2;exit}' "$conf")"
  group="$(awk -F= '/^[[:space:]]*group[[:space:]]*=/{gsub(/[ \t]/,"",$2);print $2;exit}' "$conf")"
  listen="$(awk -F= '/^[[:space:]]*listen[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2);print $2;exit}' "$conf")"
  pmmr="$(awk -F= '/^[[:space:]]*pm\.max_requests[[:space:]]*=/{gsub(/[ \t]/,"",$2);print $2;exit}' "$conf")"
  mem="$(awk -F= '/php_(admin_)?value\[memory_limit\]/{gsub(/[ \t\]]/,"",$2);print $2;exit}' "$conf")"
  lim="$(awk -F= '/^[[:space:]]*security\.limit_extensions[[:space:]]*=/{gsub(/^[ \t]+|[ \t]+$/,"",$2);print $2;exit}' "$conf")"
  grep -q 'php-secure-patch' "$conf" 2>/dev/null && hardened="yes"
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$conf" "${user:-?}" "${group:-?}" "${listen:-?}" \
    "${pmmr:-unset}" "${mem:-unset}" "${lim:-unset}" "$hardened"
}

# ------------------------------------------------------------------------------
# Web servers
# ------------------------------------------------------------------------------
detect_webservers() {
  NGINX_PRESENT=0; APACHE_PRESENT=0; LITESPEED_PRESENT=0; FRANKENPHP_PRESENT=0
  NGINX_CONF_DIRS=(); NGINX_PHP_CONFS=(); NGINX_SPLITPATH_CONFS=()
  APACHE_CONF_DIRS=(); APACHE_BIN=""; APACHE_MODULES=""; LSAPI_BINS=()

  # ---- nginx ----
  if have_cmd nginx || [ -d /etc/nginx ] || [ -d /usr/local/etc/nginx ]; then
    NGINX_PRESENT=1
    for d in /etc/nginx /usr/local/etc/nginx /opt/homebrew/etc/nginx; do
      [ -d "$d" ] && NGINX_CONF_DIRS[${#NGINX_CONF_DIRS[@]}]="$d"
    done
    for d in ${NGINX_CONF_DIRS[@]+"${NGINX_CONF_DIRS[@]}"}; do
      local f
      for f in $(find "$d" -type f \( -name '*.conf' -o -name '*.vhost' -o -name 'default*' \) 2>/dev/null); do
        if grep -qsE 'fastcgi_pass|fastcgi_split_path_info|include.*php' "$f"; then
          NGINX_PHP_CONFS[${#NGINX_PHP_CONFS[@]}]="$f"
          grep -qs 'fastcgi_split_path_info' "$f" && \
            NGINX_SPLITPATH_CONFS[${#NGINX_SPLITPATH_CONFS[@]}]="$f"
        fi
      done
    done
    ok "nginx detected (${#NGINX_PHP_CONFS[@]} php/fastcgi conf(s), ${#NGINX_SPLITPATH_CONFS[@]} with fastcgi_split_path_info)"
  fi

  # ---- apache ----
  # require a real binary, or a conf dir that actually contains config files
  local apache_conf_evidence=""
  for d in /etc/apache2 /etc/httpd /usr/local/etc/httpd /opt/homebrew/etc/httpd /opt/lampp/etc; do
    [ -d "$d" ] && ls "$d"/*.conf "$d"/conf*/*.conf >/dev/null 2>&1 && apache_conf_evidence=1
  done
  if have_cmd apachectl || have_cmd apache2ctl || have_cmd httpd || [ -n "$apache_conf_evidence" ]; then
    APACHE_PRESENT=1
    APACHE_BIN="$(command -v apache2ctl || command -v apachectl || command -v httpd || true)"
    for d in /etc/apache2 /etc/httpd /usr/local/etc/httpd /opt/homebrew/etc/httpd /opt/lampp/etc; do
      [ -d "$d" ] && APACHE_CONF_DIRS[${#APACHE_CONF_DIRS[@]}]="$d"
    done
    if [ -n "$APACHE_BIN" ]; then
      APACHE_MODULES="$("$APACHE_BIN" -M 2>/dev/null | tr ' ' '\n' | grep -E '^(php|cgi|fcgid|proxy_fcgi|actions|rewrite)' | tr '\n' ' ')"
    fi
    if [ -z "$APACHE_MODULES" ]; then
      for d in ${APACHE_CONF_DIRS[@]+"${APACHE_CONF_DIRS[@]}"}; do
        APACHE_MODULES="$APACHE_MODULES $(grep -hsE '^\s*LoadModule\s+' "$d" -r 2>/dev/null \
          | grep -E 'php|cgi|fcgid|proxy_fcgi' | awk '{print $2}' | tr '\n' ' ')"
      done
    fi
    ok "Apache detected (modules: ${APACHE_MODULES:-none found})"
  fi

  # ---- LiteSpeed / lsphp ----
  if have_cmd lshttpd || [ -d /usr/local/lsws ]; then
    LITESPEED_PRESENT=1
    for c in /usr/local/lsws/bin/lsphp* /usr/local/lsws/lsphp*/bin/lsphp*; do
      [ -x "$c" ] && LSAPI_BINS[${#LSAPI_BINS[@]}]="$c"
    done
    ok "LiteSpeed detected (${#LSAPI_BINS[@]} lsphp binary/binaries)"
  fi

  # ---- FrankenPHP ----
  if have_cmd frankenphp || [ -x /usr/local/bin/frankenphp ] || [ -x /usr/bin/frankenphp ]; then
    FRANKENPHP_PRESENT=1
    ok "FrankenPHP detected"
  fi
}

# ------------------------------------------------------------------------------
# Projects on disk
# ------------------------------------------------------------------------------
detect_projects() {
  PROJECT_RECS=()
  local roots="$*"
  if [ -z "$roots" ]; then
    roots="/var/www /srv/www /srv/http /usr/share/nginx/html /usr/share/httpd \
           /opt/lampp/htdocs /opt /home/*/public_html /home/*/www /home/*/htdocs"
  fi
  local r expanded=""
  for r in $roots; do
    # shellcheck disable=SC2086
    for e in $r; do [ -d "$e" ] && expanded="$expanded $e"; done
  done

  for r in $expanded; do
    debug "scanning for projects under $r"
    detect_projects_wp "$r"
    detect_projects_drupal "$r"
    detect_projects_joomla "$r"
    detect_projects_moodle "$r"
    detect_projects_mediawiki "$r"
    detect_projects_phpbb "$r"
    detect_projects_composer "$r"
  done

  # de-duplicate by path
  local out=() rec path seen=""
  for rec in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
    path="$(printf '%s' "$rec" | cut -d'|' -f1)"
    case " $seen " in *" $path "*) continue ;; esac
    seen="$seen $path"
    out[${#out[@]}]="$rec"
  done
  PROJECT_RECS=("${out[@]}")

  if [ "${#PROJECT_RECS[@]}" -gt 0 ]; then
    ok "found ${#PROJECT_RECS[@]} PHP project(s)"
    for rec in ${PROJECT_RECS[@]+"${PROJECT_RECS[@]}"}; do
      log "     - $(printf '%s' "$rec" | cut -d'|' -f2) @ $(printf '%s' "$rec" | cut -d'|' -f1) $(printf '%s' "$rec" | cut -d'|' -f3)"
    done
  else
    info "no PHP projects found under scanned roots (use --scan-path to add roots)"
  fi
}

_project_add() { PROJECT_RECS[${#PROJECT_RECS[@]}]="$1|$2|$3|$4|$5"; }

detect_projects_wp() {
  local r d ver
  for d in $(find "$1" -maxdepth 4 -type f -name 'wp-load.php' 2>/dev/null); do
    d="$(dirname "$d")"
    [ -f "$d/wp-includes/version.php" ] || continue
    ver="$(sed -n "s/.*\$wp_version[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$d/wp-includes/version.php" 2>/dev/null | head -1)"
    _project_add "$d" "wordpress" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_drupal() {
  local r d ver
  for d in $(find "$1" -maxdepth 5 -type f -path '*/core/lib/Drupal.php' 2>/dev/null); do
    d="$(dirname "$(dirname "$(dirname "$d")")")"
    ver="$(grep -oE "const VERSION = '[^']+'" "$d/core/lib/Drupal.php" 2>/dev/null | sed "s/.*'\(.*\)'/\1/")"
    _project_add "$d" "drupal" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_joomla() {
  local d ver
  for d in $(find "$1" -maxdepth 3 -type f -name 'configuration.php' 2>/dev/null); do
    d="$(dirname "$d")"
    [ -f "$d/libraries/src/Version.php" ] || [ -f "$d/administrator/manifests/files/joomla.xml" ] || continue
    if [ -f "$d/libraries/src/Version.php" ]; then
      ver="$(awk '/MAJOR_VERSION = /{a=$3} /MINOR_VERSION = /{b=$3} /PATCH_VERSION = /{c=$3} END{gsub(/;/,"",a);gsub(/;/,"",b);gsub(/;/,"",c);print a"."b"."c}' "$d/libraries/src/Version.php" 2>/dev/null)"
    fi
    [ "$ver" = "..." ] && ver=""
    _project_add "$d" "joomla" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_moodle() {
  local d ver
  for d in $(find "$1" -maxdepth 3 -type f -name 'version.php' 2>/dev/null); do
    d="$(dirname "$d")"
    [ -f "$d/config.php" ] || continue
    grep -q 'MOODLE_INTERNAL' "$d/version.php" 2>/dev/null || continue
    ver="$(sed -n "s/.*\$release[[:space:]]*=[[:space:]]*'\([^']*\)'.*/\1/p" "$d/version.php" 2>/dev/null | head -1)"
    [ -z "$ver" ] && ver="$(sed -n "s/.*\$version[[:space:]]*=[[:space:]]*\([0-9]*\).*/\1/p" "$d/version.php" 2>/dev/null | head -1)"
    _project_add "$d" "moodle" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_mediawiki() {
  local d ver
  for d in $(find "$1" -maxdepth 3 -type f -name 'LocalSettings.php' 2>/dev/null); do
    d="$(dirname "$d")"
    [ -f "$d/includes/Defines.php" ] || continue
    ver="$(grep -hoE "define\(\s*'MW_VERSION',\s*'[^']+'" "$d/includes/Defines.php" 2>/dev/null | sed "s/.*'\([^']*\)'\s*)/\1/" | tail -1)"
    _project_add "$d" "mediawiki" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_phpbb() {
  local d ver
  for d in $(find "$1" -maxdepth 3 -type f -path '*/includes/constants.php' 2>/dev/null); do
    d="$(dirname "$(dirname "$d")")"
    [ -f "$d/common.php" ] || continue
    ver="$(grep -oE "PHPBB_VERSION',\s*'[^']+" "$d/includes/constants.php" 2>/dev/null | sed "s/.*'\([^']*\)$/\1/")"
    _project_add "$d" "phpbb" "${ver:-unknown}" "-" "-"
  done
}

detect_projects_composer() {
  local f d name fw ver constraint
  for f in $(find "$1" -maxdepth 3 -type f -name 'composer.json' 2>/dev/null); do
    d="$(dirname "$f")"
    fw="composer"; ver="-"; constraint="-"
    for name in "laravel/framework:laravel" "symfony/symfony:symfony" "symfony/http-kernel:symfony" \
                "drupal/core:drupal" "yiisoft/yii2:yii" "cakephp/cakephp:cakephp" \
                "codeigniter4/framework:codeigniter" "magento/product-community-edition:magento" \
                "magento/product-enterprise-edition:magento" "shopware/shopware:shopware" \
                "phpmyadmin/phpmyadmin:phpmyadmin" "nextcloud/server:nextcloud" \
                "typo3/cms:typo3" "silverstripe/silverstripe-framework:silverstripe" \
                "craftcms/cms:craft" "prestashop/prestashop:prestashop" "October\Rain:october"; do
      pkg="${name%%:*}"; label="${name##*:}"
      if grep -q "\"$pkg\"" "$f" 2>/dev/null; then
        fw="$label"
        ver="$(composer_pkg_version "$d/composer.lock" "$pkg")"
        break
      fi
    done
    constraint="$(sed -n 's/.*"php"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" 2>/dev/null | head -1)"
    _project_add "$d" "$fw" "${ver:-unknown}" "${constraint:--}" "-"
  done
}

composer_pkg_version() { # composer_pkg_version <lock> <pkg>
  local lock="$1" pkg="$2"
  [ -f "$lock" ] || { printf '%s' "unknown"; return 0; }
  awk -v pkg="$pkg" '
    /"name"[[:space:]]*:[[:space:]]*"/ {
      line = $0
      sub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      if (line == pkg) { want = 1 } else { want = 0 }
    }
    want && /"version"[[:space:]]*:[[:space:]]*"/ {
      line = $0
      sub(/.*"version"[[:space:]]*:[[:space:]]*"/, "", line)
      sub(/".*/, "", line)
      print line
      exit
    }
  ' "$lock" 2>/dev/null | head -1 | sed 's/^$/unknown/'
}

# ------------------------------------------------------------------------------
detect_all() {
  detect_os
  detect_php_all
  detect_fpm
  detect_webservers
}
