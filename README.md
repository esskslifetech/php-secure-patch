# PROTECTION2Shell

[![CI](https://github.com/esskslifetech/php-secure-patch/actions/workflows/ci.yml/badge.svg)](https://github.com/esskslifetech/php-secure-patch/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform: linux | macos | windows-git-bash | containers](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows%20%7C%20containers-lightgrey.svg)](#works-on-most-systems)

**Contain the `*2Shell` families, then patch them out of the host — automatically.**
Maintained by **ESS KS Life Tech**.

`protection2shell` is one dependency-free toolkit that covers **PHP2Shell**
(CVE-2026-109618, CVE-2026-109619) and **HTTP2Shell** (CVE-2026-111497, the
Brotli decoder out-of-bounds write behind Node2Shell / Broccoli2Shell /
Brotli2Shell), plus the older PHP RCEs that are still being exploited
(CVE-2024-4577, CVE-2019-11043) and the PHP session hardening around
CVE-2026-115560.

It does three things, in that order, because that is the order that stops an
incident:

1. **Contains** — cuts the channel exploitation travels through: refuse
   Brotli-compressed request bodies at the edge, fail closed on in-process
   decompression, kill the PHP exploit producers, recycle workers, optionally
   quarantine webshell-shaped files. Minutes, reversible, no version change.
2. **Fixes** — closes the vulnerability permanently: package upgrades, verified
   upstream **source patches** for PHP *and* Brotli (including vendored copies
   no package manager owns), ini/FPM hardening, nginx/Apache guards, then a
   mandatory worker restart.
3. **Verifies** — re-checks the result and says `ok` / `pending` / `unknown` per
   item instead of trusting a version string or an exit code.

```sh
./setup.sh --auto          # contain + fix + verify, unattended (root)
./setup.sh                 # read-only audit and report
```

Renamed in v2.0.0: this project was **php-secure-patch** up to v1.x. The GitHub
repository slug is unchanged so existing clones, links and CI badges keep
working — rename it in repository Settings if you want the new name everywhere.
Old
commands, backup sets and config drop-ins keep working — see
[Migrating from php-secure-patch](#migrating-from-php-secure-patch).

---

## Why one toolkit for both families

PHP2Shell and HTTP2Shell look unrelated and are operationally identical:

* both are **unauthenticated request-parsing memory bugs** in a component that
  is *vendored* rather than linked, so package managers alone cannot fix them;
* both are exploitable **before application code runs**, which means application
  frameworks, WAFs and "we use a modern stack" are not answers;
* both need a **rebuild + restart**, not just an upgrade — a patched file on
  disk with a long-lived vulnerable worker still running is still exploitable;
* both have a **containment story that works today** and a **patching story that
  takes a change window**.

So the toolkit has one pipeline, two vulnerability modules, and a hard rule: a
`--fix` run is not finished until the workers have been recycled and `--verify`
says so.

| CVE | Family | CVSS | Type | Fixed in | Status |
|---|---|---|---|---|---|
| **CVE-2026-109618** | PHP2Shell — RCE via OOM corruption | 9.2 (v4.0) | unauth RCE | PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 | **CISA KEV** |
| **CVE-2026-109619** | PHP2Shell — RCE via stale global state | 9.2 (v4.0) | unauth RCE | same as above | **CISA KEV** |
| **CVE-2026-111497** | HTTP2Shell — Brotli heap out-of-bounds write (CWE-787 ← CWE-252) | 9.2 (v4.0) | unauth RCE/DoS | Brotli 1.0.10 / 1.1.1 / 1.2.1; Node 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; `brotli` 1.2.1 / `brotlicffi` 1.2.1.0; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; .NET 8.0.33 / 9.0.22 / 10.0.14 | **CISA KEV (due 2026-11-10)** |
| **CVE-2026-115560** | PHP session.serialize_handler switching (info) | — | unauth RCE (unconfirmed) | keep `session.upload_progress.enabled=0` for now | advisory pending |
| **CVE-2024-4577** | PHP-CGI argument injection (Windows) | 9.8 | unauth RCE | 8.3.8 / 8.2.20 / 8.1.29 | CISA KEV |
| **CVE-2019-11043** | PHP-FPM env_path_info underflow | 9.8 | unauth RCE | 7.3.11 / 7.2.24 / 7.1.33 | CISA KEV |

Full technical write-ups: [SECURITY-RESEARCH.md](SECURITY-RESEARCH.md) (PHP2Shell)
and [docs/HTTP2SHELL.md](docs/HTTP2SHELL.md) (HTTP2Shell, including where the
public reporting over- and under-states the risk).

### The one thing to understand about HTTP2Shell

It is **not** an HTTP/2 protocol bug. It is the Brotli *decoder* — reached
wherever `Content-Encoding: br` is decompressed, which is HTTP/1.1 and HTTP/2
alike, inbound **and** outbound. Remote denial of service is universal; remote
code execution is per-build (demonstrated on linux/arm64 against one Node build;
on linux/x86-64 a measured reproduction could not reach pointer control). Plan
for DoS, patch for RCE, and never read "no working exploit on my architecture
yet" as safety.

---

## Get it

```sh
git clone https://github.com/esskslifetech/php-secure-patch.git protection2shell
cd protection2shell
./tests/run-tests.sh        # sanity-check the checkout, no root needed
```

Nothing to compile, nothing to install, no package manager: plain bash plus
coreutils/awk/sed/grep.

From a zip or a source archive, run `bash setup.sh` instead of `./setup.sh`:
Windows Explorer, Finder and most GUI zip tools drop the executable bit, and
`bash <script>` does not need it. Nothing else changes. **Installation
troubleshooting — exec bits, `sh` vs `bash`, missing `sudo`, Alpine, Windows,
WSL, exit code 2 — is in [INSTALL.md](INSTALL.md).**

Install on `PATH` in one step, root or not:

```sh
sudo ./install.sh                                              # /opt + /usr/local/bin + optional --timer
./install.sh --prefix "$HOME/.local/share/protection2shell" \
             --bin "$HOME/.local/bin"                          # no root required
```

---

## Quick start

```sh
# 1. audit this host (safe, read-only) — humans and machines
./setup.sh
./setup.sh --json report.json

# 2. stop exploitation from spreading RIGHT NOW (no upgrades, no downtime)
sudo ./setup.sh --contain --yes

# 3. close the vulnerabilities (backs up every file it touches)
sudo ./setup.sh --fix --yes

# 4. everything, unattended, then verified
sudo ./setup.sh --auto

# 5. prove it afterwards
sudo ./setup.sh --verify

# 6. undo any of it
sudo ./rollback.sh --list
sudo ./rollback.sh
```

### Modes

| Command | What it does | Downtime | Root |
|---|---|---|---|
| `./setup.sh` | detect + audit + report | none | no |
| `--contain` | edge guards, in-process guards, PHP producer kill, worker recycle | worker restart only | yes |
| `--quarantine` | `--contain` + move webshell-shaped files aside (kept, reversible) | none | yes |
| `--fix` | package/service fixes + source patches + restarts | service restart | yes |
| `--auto` | `--contain` + `--fix` + `--verify`, never prompts | service restart | yes |
| `--verify` | re-check every item: `ok` / `pending` / `unknown` | none | no |

`--dry-run` works with all of them and prints the exact commands instead of
running them.

---

## What containment actually does

Containment is not a firewall rule and not a header strip. It removes the input
the decoder needs, in every direction, and it is designed to be safe enough to
run in the middle of an incident.

| Layer | Action | File |
|---|---|---|
| nginx | `if ($http_content_encoding ~* "br") { return 415; }` included in every PHP/proxy `server` block, validated with `nginx -t`, rolled back automatically if that fails | `contain/snippets/nginx-deny-br.conf` |
| Apache | `SetEnvIf` + `RewriteRule … [R=415]` (ap_expr fallback), enabled and validated with `configtest` | `contain/snippets/apache-deny-br.conf` |
| IIS / Windows | URL Rewrite global rule, 415, written into `web.config` with a backup | `contain/windows-iis-http2shell.ps1` |
| Node / Bun | preload that refuses `br` request bodies (415) and makes `zlib.brotliDecompress*` throw — this also covers the **outbound** direction a proxy cannot see | `contain/guards/node-p2s-guard.cjs` |
| Python | import hook that fails closed in urllib3/requests, httpx, aiohttp and the `brotli` modules | `contain/guards/python-p2s-guard.py` |
| Envoy / Istio | removal instructions for the Brotli **decompressor** filter (compressor-only is not an entry point) | `contain/snippets/envoy-remove-brotli-decompressor.yaml` |
| PHP | `session.upload_progress=Off`, size/complexity bounds in `99-p2s-hardening.ini`, same values as `php_admin_value` so they apply before request parsing, worker recycling | `hardening/` |
| Evidence | webshell-shaped files moved to the backup set (never deleted) with the original path recorded | `--quarantine` |

What it does **not** do, and says so in the report: a 1 MB body cap blocks the
~23 MB known RCE payload but not the ~534-byte DoS payload; stripping a request
`Accept-Encoding` header is meaningless; and no perimeter device can see a
malicious response your service fetches from an attacker-controlled URL.

---

## What a permanent fix means here

`--fix` is ordered by how much it actually closes, and it refuses to pretend:

1. **Vendor/distro fixed packages** (best) — apt/dnf/yum/apk/pacman/zypper/brew.
2. **Official fixed release** — PHP 8.2.35+/8.3.36+/8.4.27+/8.5.12+, Node
   22.23.4+/24.22.1+/26.12.1+, Brotli 1.0.10/1.1.1/1.2.1, Bun 1.4.4,
   .NET 8.0.33+/9.0.22+/10.0.14+.
3. **Source patches**, for the builds nobody packages:
   `patches/upstream-php2shell-*.patch`, `patches/CVE-*.patch`, and
   `patches/brotli/` — a real v1.2.0→v1.2.1 diff plus a 1.0.x backport, both
   verified to apply, compile and behave (see [patches/README.md](patches/README.md)).
4. **Configuration mitigations** — containment, which buys time and is never
   described as fixed.
5. **Migration plan** for EOL branches (Node 20/23/25, PHP ≤ 8.1, Istio ≤ 1.29)
   that will never get an upstream fix.

Then the part everyone forgets: **rebuild and restart**. Cached Docker layers,
`bun build --compile` binaries, Node SEA executables and statically linked curl
keep the vulnerable copy until they are rebuilt; long-lived workers keep it
until they are recycled.

```sh
# vendored / source Brotli (Node deps, Arrow, DuckDB, ClickHouse forks, …)
./patches/apply-brotli-patch.sh --find-under /usr/src/app --verify
./patches/apply-brotli-patch.sh /usr/src/node/deps/brotli --verify --build

# a PHP tree you build yourself
./patches/apply-source-patches.sh /usr/src/php-src --rebuild
```

---

## HTTP2Shell coverage detail

`protection2shell` does not trust version strings, because they lie in both
directions (patched Node still reports `process.versions.brotli === "1.2.0"`;
Debian keeps the upstream version and appends `+deb12u1`). Every carrier is
reported with a **CERTAINTY** and, where possible, a **capability probe**: the
fix introduced the error string `BLOCK_SWITCH`, which exists in no vulnerable
build. Present ⇒ definitely fixed. Absent ⇒ unknown, never "vulnerable".

| Carrier | Detection | Direction |
|---|---|---|
| `libbrotli` | package metadata, `pkg-config`, library glob, marker probe | depends on consumer |
| Node.js / Bun | every node/bun on PATH, nvm/n/asdf layouts, `process.versions.brotli`, marker probe on the binary | both |
| Python `brotli` / `brotlicffi` | every interpreter + venv under `--scan-path`, module version, wheel `.so` marker | both (urllib3 et al. auto-decode) |
| Envoy / Istio | binary/version, decompressor presence in config | inbound |
| .NET | `dotnet --list-runtimes` | opt-in only |
| curl | `curl -V` brotli flag + linked library | outbound |
| PHP | `php -m`, linked `libbrotli` | inbound |
| Vendored trees | `**/brotli/c/common/version.h` under `--scan-path` and `/usr/src`, `/opt`, `/srv`, `/var/www`, `/home` | file-format / data pipelines |

---

## Works on most systems

| Platform | Status |
|---|---|
| Debian, Ubuntu, Mint, Kali, Raspbian (+ ESM/backports) | full support, apt |
| RHEL, CentOS, Alma, Rocky, Fedora, Oracle, Amazon Linux | full support, dnf/yum |
| Alpine (busybox `ash` users: run under `bash`) | full support, apk |
| Arch, Manjaro | full support, pacman |
| SLES, openSUSE | full support, zypper |
| macOS (bash 3.2, Homebrew) | audit/contain/fix, brew |
| Windows | detection + reports under Git-Bash; IIS containment via `contain/windows-iis-http2shell.ps1`; `%AD` mitigation kit for CVE-2024-4577 |
| Containers (no init system) | audit and `--contain` work; restart the container afterwards (`--fix` cannot restart what it cannot see) |
| EOL branches | detected, labelled, and given a migration path; the toolkit never says "unfixable" without naming the vendor channel to ask |

Bash 3.2+ is the compatibility floor (macOS ships 3.2), so no associative
arrays, no `mapfile`, no `${var,,}`. Every array expansion is guarded — bash 3.2
treats `"${EMPTY[@]}"` as an unbound variable under `set -u`, which is exactly
the "found nothing on this host" path.

---

## Migrating from php-secure-patch

The rename is not a breaking change:

| php-secure-patch (v1.x) | PROTECTION2Shell (v2.x) | Compatibility |
|---|---|---|
| `php-secure-patch` / `-rollback` / `-hunt` wrappers | `protection2shell` / `-rollback` / `-hunt` | old names installed as symlinks for one release |
| `/opt/php-secure-patch` | `/opt/protection2shell` | reinstall with `./install.sh` |
| `/var/backups/php-secure-patch/<ts>` | `/var/backups/protection2shell/<ts>` | `--rollback --list` falls back to the legacy tree, so old sets stay restorable |
| `99-pSP-hardening.ini` | `99-p2s-hardening.ini` | the legacy drop-in is detected, backed up and removed so directives are not duplicated |
| `php-secure-patch` markers in nginx/FPM blocks | `protection2shell` markers | new markers are idempotent; existing guarded blocks are left alone |

Upgrading: `git pull && sudo ./install.sh` (add `--timer` to schedule runs).
Then `sudo ./setup.sh --verify` for a per-item view of where the host stands.

---

## Automatic enforcement (so containment is not a one-off)

```sh
sudo ./install.sh --timer            # daily: contain + report (default)
sudo ./install.sh --timer audit      # daily: read-only audit
sudo ./install.sh --timer auto       # daily: contain + fix + verify (unattended)
```

That installs `protection2shell.timer` (systemd, `OnBootSec=10min`,
`Persistent=true`) or, without systemd, `/etc/cron.d/protection2shell` with a
daily entry and `@reboot`. Reports land in `/var/log/protection2shell/`.
Unattended `auto` upgrades packages — choose the mode deliberately.

---

## Flags

| Flag | Effect |
|---|---|
| `--auto` | contain + fix + verify, no prompts (root) |
| `--fix` | apply fixes (default is audit-only) |
| `--contain` | containment only — cut the exploit channel, no upgrades |
| `--quarantine` | also move webshell-shaped files out of web roots |
| `--verify` | per-item `ok` / `pending` / `unknown` verification |
| `--yes` / `-y` | never prompt |
| `--dry-run` | print planned actions, change nothing |
| `--strict` | shared-hosting grade: `display_errors=Off`, `zend.assertions=-1`, `cookie_secure` |
| `--lockdown` | `pm.max_requests=1` — no worker serves a second request, removing the cross-request requirement of CVE-2026-109619 (real performance cost; does not close CVE-2026-109618) |
| `--oom-mitigation` | write `memory_limit=-1` for vulnerable PHP runtimes (CVE-2026-109618 interim mitigation; pair it with an OS/container cap) |
| `--no-upgrade` | skip package upgrades |
| `--source-dir DIR` | also patch a php-src tree |
| `--brotli-src DIR` | also patch a Brotli source/vendored tree (repeatable) |
| `--scan-path DIR` | extra project/venv/vendored-tree root (repeatable) |
| `--json FILE` | machine-readable report |
| `--rollback [DIR]` | restore a backup set |
| `--verbose` | debug output |

**Exit codes** (cron/CI friendly): `0` = clean (or fixed), `2` = vulnerable
exposure remains, `1` = error.

---

## Memory: why `-1`, and why it needs a cgroup cap

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

---

## After patching: hunt for compromise

```sh
sudo ./protection2shell-hunt --fail-on-findings
```

Indicators (CISA/NCSC guidance plus the Brotli advisory):

* **`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` / `-17` in application logs** —
  the highest-value IOC in the set: on a patched decoder it can only appear when
  someone sent a trigger;
* unusually large or deeply nested `multipart/form-data` requests; ~23 MB
  compressed request bodies (the known HTTP2Shell RCE shape);
* Brotli decode/format errors, `SIGSEGV`/`SIGABRT`, worker restarts, 100% CPU
  spins on small inputs;
* PHP workers killed by the OOM killer or hitting `memory_limit`;
* fresh or hidden PHP files in web roots, PHP inside upload directories;
* outbound connections from `php-fpm`/`httpd` children you cannot explain.

`hunt/sigma_php2shell.yml` and `hunt/sigma_http2shell*.yml` are SIGMA rules for
your SIEM.

---

## Repository layout

```
setup.sh                     main entry (detect → audit → contain → fix → verify → report)
rollback.sh                  restore any backup set (quarantine included)
install.sh                   install wrappers + optional systemd timer / cron
lib/common.sh                logging, backups, quarantine, version math, service control
lib/detect.sh                OS / PHP / SAPI / webserver / project detection
lib/detect_brotli.sh         Brotli carrier detection (libs, runtimes, wheels, vendored trees)
lib/brotli_db.sh             HTTP2Shell knowledge base, verdicts, capability probes
lib/cve_db.sh                PHP CVE knowledge base + verdict + hardening engine
lib/fix.sh                   remediation engine (all changes backed up)
lib/contain.sh               containment engine (edge + in-process + quarantine)
lib/verify.sh                per-item ok / pending / unknown verification
lib/report.sh                human + JSON reporting
contain/snippets/            nginx, Apache, Envoy containment artifacts
contain/guards/              Node preload and Python import guards
contain/windows-iis-http2shell.ps1   IIS containment for Windows
patches/                     verified upstream PHP + Brotli patches and appliers
hardening/                   ini / FPM / nginx / Apache / Windows templates
hunt/hunt.sh                 post-patch compromise hunting (logs + web roots)
hunt/sigma_*.yml             SIEM detection rules (PHP2Shell + HTTP2Shell)
scanner/project-scanner.php  deep composer-aware project detection
tests/run-tests.sh           self-test suite (no root needed)
docs/HTTP2SHELL.md           HTTP2Shell technical dossier and its corrections
SECURITY-RESEARCH.md         PHP2Shell technical research
CHANGELOG.md                 version history, including the v2.0.0 rename
```

## Requirements

bash 3.2+ (macOS included), coreutils, awk/sed/grep. Root only for `--fix`,
`--contain` and `--quarantine` on system paths. Optional (each degrades
gracefully): `systemctl`, `nginx`/`apachectl` for config validation, `gcc` for
the Brotli patch compile-check, `python3` for JSON validation in tests.

## Disclaimer

This toolkit applies well-understood, documented mitigations and takes backups
of everything it changes — but test `--fix` in staging first, and read the
report it prints. `--strict`, `--lockdown` and `--contain` trade compatibility
for containment: a service that legitimately receives Brotli-compressed bodies
will start getting 415s, so review before production use.

Run it only on hosts you own or are authorized to administer. It upgrades
packages, rewrites ini files and FPM pools, edits nginx/Apache configuration,
and restarts services.

---

## Contributing

Contributions are welcome — read [CONTRIBUTING.md](CONTRIBUTING.md) first. The
toolkit stays dependency-free, bash 3.2 compatible, and every change `--fix`
makes stays reversible through `rollback.sh`. Behaviour changes need a case in
`tests/run-tests.sh`; new patches need provenance and a verified apply.

## Security

Found a way to make this toolkit do something harmful — a detected path reaching
a command, an unsafe temp file, a rollback that drops a file? Report it privately
through the process in [SECURITY.md](SECURITY.md), never in a public issue. This
toolkit runs as root, so its own bugs are treated as vulnerabilities.

Bugs in **PHP**, **Brotli**, **Node.js** or any other upstream belong with that
project or your distribution.

## Author

Built and maintained by **ESS KS Life Tech**.

Canonical repository: **https://github.com/esskslifetech/php-secure-patch** —
issues, releases and private security advisories live there. If you received
this as a tarball or a vendor copy, clone the repository to get fixes.

## License

MIT — see [LICENSE](LICENSE).
