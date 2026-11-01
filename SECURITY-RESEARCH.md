# PHP2Shell — technical research & response (2026-10-31)

> Part of **PROTECTION2Shell**. The companion dossier for the Brotli decoder
> bug the same toolkit covers is [docs/HTTP2SHELL.md](docs/HTTP2SHELL.md).

Deep-dive on the October 2026 PHP critical RCE event and the two legacy PHP
CVEs this toolkit addresses. Everything below is grounded in public advisories
(references at the bottom); the fix mapping shows how `protection2shell`
responds to each item — detection in `lib/detect.sh`, verdicts in
`lib/cve_db.sh`, remediation in `lib/fix.sh`, containment in `lib/contain.sh`,
and verified patches in `patches/`.

---

## 1. Timeline — October 2026

| Date | Event |
|---|---|
| ~Oct 17 | Exploitation attempts observed in the wild (honeypot telemetry) |
| Oct 20 | Details of two critical PHP RCEs **leak** ahead of coordinated disclosure; PHP announces an upcoming security release |
| Oct 21, ~14:00 UTC | PHP ships emergency releases **8.5.12, 8.4.27, 8.3.36, 8.2.35** fixing both flaws; advisories GHSA-w8hw-w9fx-j79w and GHSA-6wmf-4rv5-p3rp published |
| Oct 22 | Broad scanning/exploitation begins; Wiz demonstrates unauthenticated RCE against current WordPress, Drupal and Joomla images |
| Oct 23 | PHP publishes an **informational advisory** recommending `session.upload_progress.enabled=0` until the next bugfix release (CVE-2026-115560 vector) |
| Oct 26 | **CISA adds both CVEs to the KEV catalog**; urges immediate patching or taking unpatched PHP systems offline |
| Oct 28-30 | National CSIRTs (NCSC-NL, NSA, NCSC-UK, ACSC, NCSC-NZ, CCCS) publish operational guidance; product fix-tracking (900+ products) ongoing |

Industry name: **PHP2Shell**. CVSS v4.0 **9.2** each. Discovered by Calif /
OpenAI / Wiz (with Quarkslab) using frontier-AI-assisted analysis.

---

## 2. Root causes

### CVE-2026-109618 — RCE via OOM corruption

PHP uses `longjmp()`-based bailouts to abort on fatal errors. When an
allocation fails **partway through setting up request data**, the bailout
jumps out of the initialization, leaving internal request structures
**partially initialized**. The subsequent request cleanup/shutdown code then
treats that invalid data as valid — walking half-built hash tables, object
stores and unserializer state. The result is heap use-after-free, process
memory disclosure (Heartbleed-style) and, with heap grooming, **remote code
execution as the web worker**.

* Trigger surface: attacker-steered out-of-memory conditions during request
  setup — e.g. **large or deeply nested multipart/form-data parsing**
  (`main/rfc1867.c` — the release diff shows substantial multipart hardening),
  array-fill/pad explosions, unserialize work.
* Validated **RCE over HTTP against mod_php with default input and memory
  limits**, pre-application-code. PHP-FPM exits the child when request startup
  fails, closing that exact door, but source analysis still rates FPM
  susceptible via application-level OOM paths.

### CVE-2026-109619 — RCE via stale global state

Long-lived workers (PHP-FPM, mod_php prefork children, FrankenPHP, LSAPI) keep
global state across requests: session state, error/backtrace state, unserializer
bookkeeping, OPcache slots. A fatal error (including OOM) can **skip the
per-request reset**, so the globals still point into memory freed at the end of
the request. The **next request on the same worker** consumes that freed memory
*before* normal request initialization runs — a classic use-after-free with a
clean cross-request attacker model.

Confirmed exploitation paths:

1. **`session.upload_progress`** (the workhorse): enabled **by default**, fires
   during multipart POST parsing on *any* endpoint, needs no `session_start()`.
   Session state left over from an aborted request is consumed by
   upload-progress handling in the next one. RCE validated against **both
   mod_php and PHP-FPM**. Exploit body ≈ 450 bytes — size-based WAF rules don't
   help.
2. **`fatal_error_backtraces` (PHP 8.5)**: backtrace state never correctly
   reset — the basis of the confirmed mod_php exploit.
3. **OPcache shared-memory type confusion** (tracked variant).

Wiz and PHP stress that further variants of the same pattern exist; the fix
resets the whole family of request-owned state rather than one path. The
8.3.35→8.3.36 diff confirms this: an `in_rfc1867_update` reentrancy guard in
the session module, pervasive OOM-safety hardening across Zend core
(`zend_alloc`, `zend_hash`, `zend_string`, `zend_vm`, unserializer), and dozens
of new `oom_*.phpt` regression tests.

A third issue (**CVE-2026-115560**, advisory pending) chains
`session.upload_progress` with runtime `session.serialize_handler` switching
(`php_binary`/`php_serialize` → `php` via `ini_set()` before `session_start()`).
Mitigation: keep `session.upload_progress.enabled=0`.

---

## 3. Affected / fixed versions

| Branch | PHP2Shell | Notes |
|---|---|---|
| 8.5.x | fixed in **8.5.12** | also set `fatal_error_backtraces=Off` |
| 8.4.x | fixed in **8.4.27** | |
| 8.3.x | fixed in **8.3.36** | |
| 8.2.x | fixed in **8.2.35** | 8.2 security support ends 2026-12-31 |
| 8.1 / 8.0 / 7.4 | **EOL upstream** | no supported release for the branch, but PHP publishes **minimal source backports** (`patches/legacy/`); distro/LTS backports may also exist. The backports force `session.upload_progress` off regardless of php.ini and add no hard memory limit |
| ≤ 7.3 (incl. PHP 5) | **no upstream fix** | no supported branch *and* no upstream source backport. This is **not** the same as "unfixable": vendor/LTS channels can still ship one (Ubuntu ESM publishes a fixed PHP 5 for Trusty, RHEL ELS and SUSE LTSS carry old branches, vendors ship their own builds) — ask them before concluding the host must be migrated or taken offline |

All web-serving SAPIs are at risk: **mod_php (highest risk)**, PHP-FPM, php-cgi,
FrankenPHP, LiteSpeed. CLI is not covered by the advisories but ships in the
same packages — upgrade anyway. Third-party images/appliances embedding PHP are
in scope (see NCSC-NL product tracking).

---

## 4. Official mitigations (and how this toolkit applies them)

PHP: **no configuration change fully mitigates these bugs** — update is the
only complete fix. Temporary measures (php.net, 21–23 Oct 2026):

| Mitigation | Purpose | Applied by |
|---|---|---|
| `session.upload_progress.enabled = Off` (php.ini / FPM pool / server config — **not** `.user.ini`/`ini_set()`), then restart workers | kills the CVE-2026-109619 producer + CVE-2026-115560 | `fix.sh` ini drop-in + `php_admin_value` in every FPM pool |
| PHP 8.5: `fatal_error_backtraces = Off` | kills the backtrace producer | `fix.sh` (version-aware) |
| `memory_limit = -1` **plus** an OS/container memory cap (systemd `MemoryMax=`, cgroup v2 `memory.max`, container limit) — on *vulnerable* runtimes only | removes the predictable OOM ceiling that CVE-2026-109618 steers. A tighter `memory_limit` is **the opposite** of this mitigation | `fix.sh --oom-mitigation` (opt-in; audit reports it as `H-001`). Patched runtimes keep a finite bound |
| Conservative `post_max_size` / `upload_max_filesize` / `max_multipart_body_parts`; body-size limit at the frontend proxy | shrinks the input the OOM path is steered with | `fix.sh` ini drop-in + FPM pool + nginx guidance |
| **Do not** use `RLIMIT_AS` / `RLIMIT_DATA` (`ulimit -v` / `-d`) | they surface as fatal allocation errors — the same bailout path being exploited | called out in every generated config and in the fix output |
| **Restart every PHP worker** after patching | stale state lives in workers | `fix.sh` restarts fpm/apache/nginx/litespeed/frankenphp |
| `pm.max_requests = 1` where performance allows | no worker serves a second request ⇒ the cross-request requirement of CVE-2026-109619 cannot be met. `pm.max_requests = 500` only **reduces exposure** (shorter-lived stale state) — it is not worker isolation | `--lockdown` (`pm.max_requests=1`); default is `500`, labelled as reduced exposure |
| Block multipart/form-data at frontend where unused | removes the trigger class | documented in `hardening/nginx-php-hardened.conf` |
| Eliminate attacker-reachable fatal errors/timeouts | reduces bailout triggers | documented + `request_terminate_timeout` |
| WAF rules may help until patched; EOL PHP you cannot patch → **take offline** (CISA) | damage limitation | guidance |

Compromise hunting: multipart abuse in access logs, worker crashes / OOM-killer
kills / `memory_limit` hits, new files in web roots, unexplained outbound
connections from PHP children. CISA published a SIGMA rule (alert of Oct 23/26,
2026).

---

## 5. CVE-2024-4577 — PHP-CGI argument injection (Windows)

* **CVSS 9.8**, CISA KEV, exploited in the wild (TellYouThePass ransomware).
* Windows `Best-Fit` character conversion maps e.g. soft hyphen (`%AD`) to
  `-`; a query string starting with such a byte bypasses php-cgi's
  `skip_getopt` guard (the CVE-2012-1823 fix) and injects **command-line
  arguments** (`-d allow_url_include=1 -d auto_prepend_file=php://input`).
* Affects **Windows php-cgi only**: 8.3.x < 8.3.8, 8.2.x < 8.2.20,
  8.1.x < 8.1.29, all EOL branches. **XAMPP for Windows is vulnerable by
  default.** Reported by Orange Tsai (DEVCORE), fixed 2024-06-06
  (GHSA-3qgc-jrrr-25jv).
* Fix: upgrade (8.3.8/8.2.20/8.1.29+); move off php-cgi to mod_php/FPM;
  stopgap rewrite rules rejecting `QUERY_STRING ^%ad` (and any query string
  without `=`). Note the rewrite stopgap is locale-dependent — patching is the
  only durable fix.
* **This toolkit**: version-aware verdicts (`cve_db.sh`), real upstream source
  patch (`patches/CVE-2024-4577-php-cgi-argument-injection.patch` — the exact
  `WideCharToMultiByte` best-fit check from 8.3.8), `.htaccess` rules and a
  Windows PowerShell mitigation kit.

## 6. CVE-2019-11043 — PHP-FPM env_path_info underflow

* **CVSS 9.8**, CISA KEV, famously exploited in the wild against nginx+php-fpm.
* With nginx `fastcgi_split_path_info` producing an **empty PATH_INFO**, the
  pointer math `env_path_info + pilen - slen` in `init_request_info()`
  (`sapi/fpm/fpm/fpm_main.c`) **underflows**, corrupting request setup —
  leading to RCE via crafted query strings. Reported by Orange Tsai (DEVCORE),
  fixed 2019-10-24 (7.3.11 / 7.2.24 / 7.1.33, bug #78598).
* Fix: upgrade; nginx guard `if (!-f $document_root$fastcgi_script_name) {
  return 404; }`; avoid regex `PATH_INFO` captures that can be empty.
* **This toolkit**: version-aware verdicts, the real upstream one-hunk source
  patch (`patches/CVE-2019-11043-env-path-info-underflow.patch` — verbatim from
  7.3.11), and automatic nginx guard insertion with `nginx -t` validation.

---

## 7. Response priority (what this toolkit automates)

1. Inventory every PHP runtime and web-serving SAPI (CISA action #1).
2. Patch internet-facing systems first: vendor packages → fixed releases
   (8.5.12/8.4.27/8.3.36/8.2.35) → vendor backports → source patches.
3. Apply the php.net temporary mitigations immediately, **restart workers**,
   and keep `session.upload_progress.enabled=0` after patching (CVE-2026-115560).
4. Bound the input (`post_max_size`, `max_multipart_body_parts`, frontend body
   limit); on still-vulnerable runtimes remove the PHP memory ceiling
   (`memory_limit=-1`) **and** cap memory at cgroup/systemd level — never with
   `RLIMIT_AS`/`RLIMIT_DATA`. Recycle FPM workers (`pm.max_requests=1` if you
   can afford it; `500` is only reduced exposure).
5. Fix the legacy CVE exposure in the same pass (nginx guards, Windows php-cgi).
6. Hunt for compromise using the indicators above.
7. EOL PHP you cannot patch: isolate or take offline (CISA guidance).

---

## References

* CISA Alert AA26-…: *Critical Vulnerabilities in PHP Require Immediate
  Patching* (2026-10-21, revised 10-23 & 10-26; KEV additions)
  — https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching
* PHP security releases 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 (2026-10-21) —
  https://www.php.net/ and advisories **GHSA-w8hw-w9fx-j79w** (CVE-2026-109618),
  **GHSA-6wmf-4rv5-p3rp** (CVE-2026-109619)
* PHP informational advisory *Session upload progress* (2026-10-23) —
  https://www.php.net/archive/2026.php#2026-10-23-1
* NCSC-NL operational repository (product tracking, mitigation catalogue) —
  https://github.com/NCSC-NL/php2shell
* watchTowr: PHP2Shell FAQ & in-the-wild exploitation observations —
  https://watchtowr.com/intelligence/php-remote-code-execution-php2shell/
* Huntress rapid response —
  https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities
* Wiz Research / Abstract.security technical analyses (exploitation paths) —
  https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619
* Patchstack bulletin (fixed-version matrix, timeline) —
  https://patchstack.com/articles/php-major-vulnerability-alert-10-2026/
* The Register coverage —
  https://www.theregister.com/security/2026/10/21/php-devs-publish-critical-bug-fix-as-site-owners-warned-pull-em-offline-if-youre-unpatched/
* CVE-2024-4577: DEVCORE advisory; NVD; Traceable/Altyence analyses (2024-06)
* CVE-2019-11043: PHP bug #78598; NVD; DEVCORE write-up (2019-10)
* CERT-EU Security Advisory 2026-018; NSA / NCSC-UK / ACSC / NCSC-NZ / CCCS
  alerts (Oct 2026)
