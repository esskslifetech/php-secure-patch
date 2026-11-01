# Changelog

All notable changes to this project. The project is called **PROTECTION2Shell**
from v2.0.0 onward; it was **php-secure-patch** up to v1.0.0.

## [2.0.0] — 2026-10-31

**Renamed: php-secure-patch → PROTECTION2Shell**, and rescoped from PHP2Shell
alone to the whole `*2Shell` family. Nothing that worked before is broken:

| v1.x | v2.0.0 | Compatibility |
|---|---|---|
| `php-secure-patch`, `-rollback`, `-hunt` | `protection2shell`, `-rollback`, `-hunt` | legacy names installed as symlinks |
| `/opt/php-secure-patch` | `/opt/protection2shell` | reinstall via `./install.sh` |
| `/var/backups/php-secure-patch/<ts>` | `/var/backups/protection2shell/<ts>` | rollback falls back to the legacy tree, so old sets remain restorable |
| `99-pSP-hardening.ini` drop-in | `99-p2s-hardening.ini` | legacy drop-in detected, backed up and removed (no duplicated directives) |
| `PSP_*` shell variables | `P2S_*` | internal only |

### Added — HTTP2Shell (CVE-2026-111497)

* `lib/brotli_db.sh` — carrier-aware knowledge base: affected range 1.0.3–1.2.0,
  fixed releases per line (1.0.10 / 1.1.1 / 1.2.1), fixed Node 22.23.4 /
  24.22.1 / 26.12.1, Bun 1.4.4, `brotli` 1.2.1 / `brotlicffi` 1.2.1.0, Envoy
  1.40.0 / 1.39.3 / 1.38.6 / 1.37.8, .NET 8.0.33 / 9.0.22 / 10.0.14. Verdicts
  are per carrier, and every finding states the DoS-floor / per-build-RCE
  position instead of one headline score.
* `lib/detect_brotli.sh` — finds `libbrotli`, Node (PATH + nvm/n/asdf), Bun,
  Python `brotli`/`brotlicffi` across interpreters and venvs, Envoy/Istio, .NET
  runtimes, brotli-enabled curl, PHP extensions, and vendored
  `brotli/c/common/version.h` source trees.
* **Capability probes.** Version strings lie (patched Node still reports brotli
  `1.2.0`; Debian appends `+deb12u1`), so detection also looks for the
  `BLOCK_SWITCH` error string introduced by the fix. Present ⇒ fixed; absent ⇒
  `unknown`, never "vulnerable".
* `patches/brotli/` — the real v1.2.0→v1.2.1 fix (restricted to `decode.c` and
  `decode.h`) plus a 1.0.x backport, and `patches/apply-brotli-patch.sh`
  (`--find-under`, `--verify` with a gcc compile check, `--revert`, `--build`).
  Both patches were applied to pristine upstream tarballs, compiled, round-trip
  tested, and checked to return error -17 as `BLOCK_SWITCH`.

### Added — containment ("stop it spreading")

* `--contain` mode and `lib/contain.sh`: deny `Content-Encoding: br` request
  bodies at nginx (include inserted into every PHP/proxy `server` block, checked
  with `nginx -t`), Apache (`conf-available` + `configtest`) and IIS
  (`contain/windows-iis-http2shell.ps1`), each rolled back automatically when
  validation fails.
* In-process guards for the direction a proxy cannot see:
  `contain/guards/node-p2s-guard.cjs` (415 on inbound `br`, `zlib.brotliDecompress*`
  disabled) and `contain/guards/python-p2s-guard.py` (fails closed in
  urllib3/requests, httpx, aiohttp and the brotli modules).
* `--quarantine`: moves webshell-shaped files out of web roots into the backup
  set, keeping the original path so `rollback.sh` releases them again.
* Containment is re-assertable: `install.sh --timer [audit|contain|auto]`
  installs a systemd timer (or `/etc/cron.d/protection2shell` without systemd).

### Added — automation, verification, "works everywhere"

* `--auto` — contain + fix + verify, unattended; `--verify` — per-item
  `ok` / `pending` / `unknown` instead of a bare exit code.
* `--brotli-src DIR` to patch vendored Brotli trees from `--fix`.
* Machine-readable JSON now carries `tool`, `http2shell.carriers`,
  `http2shell.findings` and `verification`; `hunt.sh --app-log` scans for
  Brotli decode failures; `hunt/sigma_http2shell*.yml` added.
* `docs/HTTP2SHELL.md` — technical dossier, including the reachability dispute,
  the struct-layout reconciliation and a list of claims the public record gets
  wrong.

### Changed

* Report leads with what is actionable and states containment vs. fix
  explicitly; exit code `2` now also covers unaudited Brotli carriers.
* Tests grew from 70 to cover HTTP2Shell verdicts, carrier parsing, patch
  integrity, guard syntax and rename hygiene; CI lints the new scripts and
  validates the Brotli patch against upstream in a dedicated job.
* Legacy `php-secure-patch` markers in nginx/FPM blocks are left in place (the
  new markers are idempotent) rather than rewritten during an incident.

### Fixed

* `hunt.sh` printed `[: 0\n0: integer expression expected` when a log had no
  matches: `grep -c` already prints `0` and exits 1, so `|| echo 0` produced two
  values. Both occurrences fixed; duplicate log paths are also de-duplicated.
* Node verdicts compare per **major** line (22.22.3 is *older* than 22.23.4),
  and fixed 1.0.10 / 1.1.1 are no longer mis-reported as vulnerable.

## [1.0.0] — 2026-10-31

Initial public release as php-secure-patch: PHP2Shell (CVE-2026-109618/109619),
CVE-2026-115560, CVE-2024-4577, CVE-2019-11043 — detection, audit, package
upgrades, version-aware ini/FPM hardening, nginx/Apache guards, verified source
patches, worker restarts, full backups with one-command rollback, and a
post-patch compromise hunt.
