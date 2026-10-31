# php-secure-patch

[![CI](https://github.com/esskslifetech/php-secure-patch/actions/workflows/ci.yml/badge.svg)](https://github.com/esskslifetech/php-secure-patch/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform: linux | macos | windows-git-bash](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](#requirements)

**PHP2Shell & friends — detect, audit and fix PHP security posture on any host,
automatically.** Maintained by **ESS KS Life Tech**.

One command finds every PHP installation, version, SAPI, web server and PHP
project on a system, audits them against the critical PHP vulnerabilities
(**CVE-2026-109618, CVE-2026-109619, CVE-2026-115560, CVE-2024-4577,
CVE-2019-11043**) plus general hardening, and then **fixes everything it safely
can** — package upgrades, version-aware ini hardening, PHP-FPM pool lockdown,
nginx guards, worker recycling — with full backups and one-command rollback.
The `patches/` directory additionally contains **real, verified upstream source
patches** extracted from PHP's own release tarballs for anyone building PHP
from source or stuck on an EOL branch.

```
./setup.sh            # detect + audit + report (read-only)
sudo ./setup.sh --fix # apply every safe fix automatically
```

---

## The vulnerabilities

| CVE | Name | CVSS | Type | Fixed in | Status |
|---|---|---|---|---|---|
| **CVE-2026-109618** | PHP2Shell — RCE via OOM corruption | 9.2 (v4.0) | unauth RCE | **8.5.12 / 8.4.27 / 8.3.36 / 8.2.35** (2026-10-21) | **CISA KEV, exploited in the wild** |
| **CVE-2026-109619** | PHP2Shell — RCE via stale global state | 9.2 (v4.0) | unauth RCE | same as above | **CISA KEV, exploited in the wild** |
| **CVE-2026-115560** | session.serialize_handler switching (info) | — | unauth RCE (unconfirmed) | keep `session.upload_progress.enabled=0` until next bugfix release | advisory pending |
| **CVE-2024-4577** | PHP-CGI argument injection (Windows) | 9.8 | unauth RCE | 8.3.8 / 8.2.20 / 8.1.29 (2024-06-06) | CISA KEV |
| **CVE-2019-11043** | PHP-FPM env_path_info underflow | 9.8 | unauth RCE | 7.3.11 / 7.2.24 / 7.1.33 (2019-10-24) | CISA KEV |

PHP2Shell affects **every PHP release from 5.4 onward** serving web requests —
PHP-FPM, Apache mod_php (highest risk: a single unauthenticated request can
trigger exploitation before application code runs), php-cgi, FrankenPHP and
LiteSpeed.

What "no fix for you" actually means depends on which support channel is
missing — these are three different questions:

| Condition | 8.2 – 8.5 | 7.4 / 8.0 / 8.1 | ≤ 7.3, PHP 5 |
|---|---|---|---|
| Upstream-supported release | yes | **no** — branch EOL | **no** |
| Upstream source backport | n/a (fixed release) | **yes** — `patches/legacy/` | **no** |
| Vendor / LTS backport possible | n/a | yes — distro ESM/ELS/LTSS, vendor PHP builds | yes — ask the vendor; some distros backport into ESM (e.g. Ubuntu publishes fixed PHP 5 for Trusty ESM) |

So: an EOL branch is **not** automatically unfixable. The toolkit reports which
of the three channels applies for each detected runtime (`php2shell_support_note`
in `lib/cve_db.sh`) instead of declaring the host hopeless — and only says
"migrate" when upstream *and* your vendor have nothing.

Full technical write-up: [SECURITY-RESEARCH.md](SECURITY-RESEARCH.md).

---

## Get it

```sh
git clone https://github.com/esskslifetech/php-secure-patch.git
cd php-secure-patch
./tests/run-tests.sh        # sanity-check the checkout, no root needed
```

Nothing to compile, nothing to install, no package manager: plain bash plus
coreutils/awk/sed/grep. If you fetched a source archive instead of cloning, mark
the entry points executable first (`chmod +x setup.sh rollback.sh install.sh
hunt/hunt.sh tests/run-tests.sh patches/apply-source-patches.sh`); a git
checkout already carries the mode bits.

Then pick a mode below. `sudo ./install.sh` is only needed if you want the
`php-secure-patch` / `php-secure-patch-hunt` wrappers on `PATH` for cron.

---

## Quick start

```sh
# 1. audit this host (safe, read-only)
./setup.sh --json report.json

# 2. fix everything (as root; backs up every file it touches)
sudo ./setup.sh --fix --yes

# 3. preview instead of changing anything
sudo ./setup.sh --fix --dry-run

# 4. undo
sudo ./rollback.sh            # newest backup set
sudo ./rollback.sh --list     # show sets

# 5. self-test the toolkit
./tests/run-tests.sh
```

### What `--fix` does, in order

1. **Upgrade PHP packages** to fixed releases via the system package manager
   (apt/dnf/yum/apk/pacman/zypper/brew). `--no-upgrade` to skip.
2. **Ini hardening** — writes a version-aware `99-pSP-hardening.ini` drop-in per
   PHP install: `session.upload_progress.enabled=Off` (kills the confirmed
   CVE-2026-109619 producer), conservative `post_max_size` /
   `upload_max_filesize` / `max_multipart_body_parts` bounds, `fatal_error_backtraces=Off`
   on PHP 8.5, plus baseline hardening (`allow_url_include`, `expose_php`,
   `phar.readonly`, session cookies, …). `memory_limit` is **not** quietly
   tightened on a vulnerable runtime — see [Memory](#memory-why--1-and-why-it-needs-a-cgroup-cap).
3. **PHP-FPM pool hardening** — same mitigations as `php_admin_value` so they
   apply *before request parsing* and cannot be re-enabled per-directory,
   plus `pm.max_requests` (250–500 = reduced exposure; `1` via `--lockdown` =
   no worker serves a second request), `security.limit_extensions`,
   `request_terminate_timeout`.
4. **nginx CVE-2019-11043 guard** — inserts `if (!-f $document_root$fastcgi_script_name)
   { return 404; }` into `location ~ \.php` blocks that use
   `fastcgi_split_path_info`, with `nginx -t` validation and auto-rollback.
5. **CVE-2024-4577 kit** — emits the `%AD` rewrite rules, `.htaccess` and a
   Windows PowerShell mitigation script (`hardening/windows-cve-2024-4577.*`).
6. **Project assists** — drops PHP2Shell hunting notes into every detected
   project and runs `composer audit` where available.
7. **Source patches** (optional `--source-dir DIR`) — applies `patches/` to a
   PHP source tree (see below).
8. **Restarts/recycles every PHP worker** — mandatory: PHP2Shell lives in
   long-lived worker memory; patches only take effect after a restart.

Every touched file is copied to a timestamped backup set
(`/var/backups/php-secure-patch/<ts>/` or `~/.php-secure-patch/backups/`) with a
`MANIFEST.txt`, so `./rollback.sh` restores everything exactly.

### Memory: why `-1`, and why it needs a cgroup cap

CVE-2026-109618 is steered through a *predictable* per-request memory ceiling:
the attacker aims PHP at a controlled out-of-memory during request setup. That
makes the advisory's interim mitigation counter-intuitive — it is not "set a
tighter limit":

* **vulnerable runtime** → `memory_limit = -1` removes the lever, **plus** a cap
  *outside* PHP (systemd `MemoryMax=`, cgroup v2 `memory.max`, container limit).
  With no PHP ceiling, that external cap is the only thing stopping one request
  from eating the host.
* **patched runtime** → keep a finite `memory_limit`; the OOM-corruption path is
  gone, so the bound is purely your availability guard.
* **never** `RLIMIT_AS` / `RLIMIT_DATA` (`ulimit -v`, `ulimit -d`) — they show up
  as fatal allocation errors, which is the very bailout being exploited.

Because `-1` trades exploitability for availability, `--fix` does **not** write
it behind your back. The audit reports it as `H-001` and you opt in:

```sh
sudo ./setup.sh --fix --oom-mitigation     # writes memory_limit = -1
sudo systemctl edit php8.3-fpm             # [Service] MemoryMax=2G / MemoryHigh=1500M
```

Both settings are containment. Only upgrading PHP closes the vulnerability.

### Flags

| Flag | Effect |
|---|---|
| `--fix` | apply fixes (default is audit-only) |
| `--yes` / `-y` | never prompt |
| `--dry-run` | print planned actions, change nothing |
| `--strict` | shared-hosting grade: `display_errors=Off`, `zend.assertions=-1`, `cookie_secure` |
| `--lockdown` | `pm.max_requests=1` — no worker serves a second request, which removes the cross-request requirement of CVE-2026-109619 (real performance cost; it does not close CVE-2026-109618) |
| `--oom-mitigation` | write `memory_limit=-1` for vulnerable runtimes (CVE-2026-109618 interim mitigation; pair it with an OS/container memory cap) |
| `--no-upgrade` | skip package upgrades |
| `--source-dir DIR` | also patch a php-src tree |
| `--scan-path DIR` | extra project root (repeatable) |
| `--json FILE` | machine-readable report |
| `--rollback [DIR]` | restore a backup set |
| `--verbose` | debug output |

**Exit codes** (cron/CI friendly): `0` = clean (or fixed), `2` = vulnerable
exposure remains in audit mode, `1` = error.

---

## Source patches (`patches/`)

Real unified diffs against official PHP trees — provenance and verification
details in [`patches/README.md`](patches/README.md):

| Patch | Fixes | Verified against |
|---|---|---|
| `upstream-php2shell-CVE-2026-109618-109619.patch` (5,385 lines) | both PHP2Shell CVEs | php-8.3.35 — 0 failed hunks |
| `CVE-2019-11043-env-path-info-underflow.patch` | CVE-2019-11043 | php-7.3.10 — clean |
| `CVE-2024-4577-php-cgi-argument-injection.patch` | CVE-2024-4577 | php-8.3.7 — clean |
| `legacy/php2shell-minimal-backport-7.4-8.1.patch` | PHP2Shell producer kill for EOL branches | php-7.4.33 / 8.0.30 / 8.1.29 / 8.3.35 |

```sh
./patches/apply-source-patches.sh /usr/src/php-src            # auto-select + apply
./patches/apply-source-patches.sh /usr/src/php-src --rebuild  # + build + install
```

**Priority of fixes:** (1) vendor/distro fixed packages → (2) official fixed
release → (3) distro/LTS backported packages → (4) source patches → (5) config
mitigations + migration plan. PHP states **no configuration change fully
mitigates PHP2Shell** — the config layer buys time, the version fix ends it.

---

## Detection coverage

* **OS**: Debian/Ubuntu/EL/Alpine/Arch/SUSE/macOS/Windows(Git-Bash)/WSL, with
  package-manager identification.
* **PHP runtimes**: every interpreter on `PATH` and in standard prefixes
  (`/usr/bin/php*`, Homebrew, XAMPP, LiteSpeed `lsphp`, `update-alternatives`),
  probed for version, SAPI, `php --ini` location and 22 security-relevant ini
  values.
* **SAPIs / servers**: PHP-FPM (binary + every pool config), nginx (fastcgi
  configs, `fastcgi_split_path_info`), Apache (`apachectl -M` module scan),
  LiteSpeed/lsphp, FrankenPHP, php-cgi.
* **Projects** (bash + `scanner/project-scanner.php`): WordPress, Joomla,
  Drupal, Moodle, MediaWiki, phpBB, Laravel, Symfony, Magento, Yii, CakePHP,
  CodeIgniter, TYPO3, Shopware, PrestaShop, Nextcloud, phpMyAdmin, Craft,
  SilverStripe, generic Composer trees — with framework versions (marker files
  / `composer.lock`) and the project's own `php` requirement.

---

## Upgrading PHP branches

Package upgrades keep you on the same PHP branch. To leave an EOL branch:

* **Debian/Ubuntu** — the distro ships a single branch per release. To move up,
  add [deb.sury.org](https://deb.sury.org/) (Ondřej Surý's PHP repository):
  `curl -sSLo /tmp/debsuryorg-archive-keyring.deb https://packages.sury.org/debsuryorg-archive-keyring.deb`
  then `apt install php8.4 php8.4-fpm` (adjust version), and re-run
  `./setup.sh --fix`.
* **RHEL/CentOS/Alma/Rocky** — use the **remi** repository
  (`dnf module reset php && dnf module enable php:remi-8.4`).
* **Alpine** — `apk add php84 php84-fpm` (parallel packages per branch).
* **macOS** — `brew install php@8.4 && brew link --overwrite --force php@8.4`.
* **From source** — build the fixed release, or apply `patches/` to your tree
  (`./patches/apply-source-patches.sh /usr/src/php-src --rebuild`).

After any upgrade: **restart every PHP worker** — `systemctl restart php*-fpm`,
`apachectl graceful`, etc. Re-run `./setup.sh` until the report is clean.

---

## Cron / CI usage

```sh
# nightly audit, non-zero exit when exposure remains (exit code 2)
15 3 * * * root /usr/local/bin/php-secure-patch --json /var/log/php-secure-patch.json \
    || mail -s "PHP exposure on $(hostname)" admin@example.com

# CI gate on container images / build agents
php-secure-patch --json report.json --no-upgrade
# exit 0 = clean, 2 = vulnerable PHP or unmitigated CVE findings

# weekly compromise hunt (after patching)
0 6 * * 1 root /usr/local/bin/php-secure-patch-hunt --fail-on-findings
```

`sudo ./install.sh` installs `php-secure-patch`, `php-secure-patch-rollback`
and `php-secure-patch-hunt` into `/usr/local/bin` (from `/opt/php-secure-patch`);
`sudo ./install.sh --uninstall` removes them.

---

## After patching: hunt for compromise

CISA/NCSC guidance — both CVEs are triggered by errors inside a request:

* unusually large or **deeply nested multipart/form-data** requests in access logs
* PHP workers **killed by the kernel OOM killer**, crashing, or hitting
  `memory_limit` (on hosts that still set one) around attack timestamps
* **unexplained files in web roots** (webshells) with recent mtimes
* **outbound connections** from `php-fpm`/`httpd` children you cannot explain
* `Allowed memory size exhausted` spikes immediately followed by odd requests

Automated: `./hunt/hunt.sh` scans access logs, PHP error logs and web roots for
exactly these indicators (large POSTs, `upload_progress` probes, `%ad`/`-d`
cgi-arg probes, OOM bursts, fresh/hidden/double-extension PHP droppings).
`hunt/sigma_php2shell.yml` is a SIGMA rule for your SIEM.

---

## Repository layout

```
setup.sh                  main entry (detect → audit → fix → report)
rollback.sh               restore any backup set
install.sh                install/uninstall system-wide wrappers
lib/common.sh             logging, backups, version math, service control
lib/detect.sh             OS / PHP / SAPI / webserver / project detection
lib/cve_db.sh             CVE knowledge base + verdict engine + hardening checks
lib/fix.sh                remediation engine (all changes backed up)
lib/report.sh             human + JSON reporting
patches/                  verified upstream source patches + applier
hardening/                ini / FPM / nginx / Apache / Windows templates
hunt/hunt.sh              post-patch compromise hunting (log + webroot scan)
hunt/sigma_php2shell.yml  SIEM detection rule
scanner/project-scanner.php   deep composer-aware project detection
tests/run-tests.sh        self-test suite (no root needed)
SECURITY-RESEARCH.md      full technical research on the CVEs
CONTRIBUTING.md           ground rules, test expectations, PR checklist
SECURITY.md               coordinated disclosure for bugs in the toolkit itself
LICENSE                   MIT
.github/workflows/ci.yml  CI: bash -n, self-tests, shellcheck, php -l
```

## Requirements

bash 3.2+ (macOS included), coreutils, awk/sed/grep. Root only for `--fix` on
system paths. No other dependencies.

## Disclaimer

This toolkit applies well-understood, documented mitigations and takes backups
of everything it changes — but test `--fix` in a staging environment first, and
read the report it prints. `--strict`/`--lockdown` trade compatibility for
containment: review before production use.

Run it only on hosts you own or are authorized to administer. It upgrades
packages, rewrites ini files and FPM pools, edits nginx/Apache configuration and
restarts services.

---

## Contributing

Contributions are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first. The
toolkit stays dependency-free, bash 3.2 compatible, and every `--fix` action
stays reversible through `rollback.sh`. Behaviour changes need a case in
`tests/run-tests.sh`.

## Security

Found a way to make this toolkit do something harmful — a detected path reaching
a command, an unsafe temp file, a rollback that drops a file? Report it privately
through the process in [SECURITY.md](SECURITY.md), never in a public issue. This
toolkit runs as root, so its own bugs are treated as vulnerabilities.

Bugs in **PHP** itself belong with the PHP project or your distribution.

## Author

Built and maintained by **ESS KS Life Tech**.

Canonical repository: **https://github.com/esskslifetech/php-secure-patch** —
issues, releases and private security advisories live there. If you received
this as a tarball or a vendor copy, clone the repository to get fixes.

## License

MIT — see [LICENSE](LICENSE).
