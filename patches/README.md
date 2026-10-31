# php-secure-patch — patch set

Every `.patch` file here is a **real unified diff against official PHP source
trees**, extracted from the vendor's own release tarballs and verified to apply
cleanly to the corresponding vulnerable release. Nothing here is hand-waved.

| Patch | Fixes | Extracted from | Verified against | Notes |
|---|---|---|---|---|
| `upstream-php2shell-CVE-2026-109618-109619.patch` | **CVE-2026-109618** (RCE via OOM corruption) + **CVE-2026-109619** (RCE via stale global state) | php-8.3.35 → php-8.3.36 (2026-10-21 security release), core engine files (Zend/, main/, ext/session, ext/opcache, ext/standard var, ext/spl) | php-8.3.35 — **0 failed hunks** | 5,385 lines. The complete engine-side fix: OOM-safe request cleanup, stale request-owned state reset, `in_rfc1867_update` session guard, multipart (rfc1867) hardening. For 8.2/8.4/8.5 trees it usually applies with offsets/fuzz — but **always prefer the official fixed release** (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12). |
| `CVE-2019-11043-env-path-info-underflow.patch` | **CVE-2019-11043** (PHP-FPM env_path_info underflow RCE, CVSS 9.8, CISA KEV) | php-7.3.10 → php-7.3.11 (2019-10-24, bug #78598) | php-7.3.10 — clean | The complete fix is one hunk in `sapi/fpm/fpm/fpm_main.c`: adds the `pilen > slen` bounds check so an empty `PATH_INFO` (nginx `fastcgi_split_path_info`) can no longer underflow. Same fix shipped in 7.2.24 / 7.1.33. |
| `CVE-2024-4577-php-cgi-argument-injection.patch` | **CVE-2024-4577** (PHP-CGI argument injection on Windows, CVSS 9.8, CISA KEV) | php-8.3.7 → php-8.3.8 (2024-06-06, GHSA-3qgc-jrrr-25jv) | php-8.3.7 — clean | Only the two security hunks of `sapi/cgi/cgi_main.c` (the third hunk in that release is an unrelated Windows `_read` fix): detects query-string bytes ≥ 0x80 whose Windows *Best-Fit* mapping is `-` and sets `skip_getopt`, killing the `%AD` → `-d` argument injection. Inert on non-Windows. |
| `legacy/php2shell-minimal-backport-7.4-8.1.patch` | **CVE-2026-109619 producer** (partial mitigation) for EOL branches | modeled on PHP's official *minimal source backports* for 7.4/8.0/8.1 | php-7.4.33, php-8.0.30, php-8.1.29, php-8.3.35 — clean | Forces `session.upload_progress.enabled` to default `0` **and** downgrades it to `ZEND_INI_SYSTEM` so `.user.ini` / `ini_set()` cannot re-enable it. Like the official minimal backports it does **not** fix the engine memory-safety bugs — it kills the confirmed exploit producer only. Pair with ini hardening (`memory_limit`, `post_max_size`) and migrate off EOL branches. |

## Usage

```sh
# pick and apply the right patches for a tree automatically:
./apply-source-patches.sh /usr/src/php-src            # preview
./apply-source-patches.sh /usr/src/php-src --rebuild  # patch + build + install
```

or by hand:

```sh
cd /usr/src/php-src
patch -p1 --forward --fuzz=3 < patches/upstream-php2shell-CVE-2026-109618-109619.patch
patch -p1 --forward --fuzz=3 < patches/CVE-2019-11043-env-path-info-underflow.patch   # if < 7.3.11
patch -p1 --forward --fuzz=3 < patches/CVE-2024-4577-php-cgi-argument-injection.patch # if Windows-cgi
./buildconf --force && ./configure <your flags> && make -j$(nproc) && make install
# then RESTART every worker: systemctl restart php8.x-fpm / apachectl graceful
```

## Which fix should I use? (decision tree)

1. **Fixed release exists for your branch (8.2.35+, 8.3.36+, 8.4.27+, 8.5.12+)** →
   install the vendor package. This patch set is a fallback, not a replacement.
2. **Distro/LTS vendor ships backported packages (Debian, Ubuntu LTS, RHEL, SUSE, Alpine, Chainguard…)** →
   use those first — they carry distro-specific fixes too.
3. **You build from source on 8.2–8.5** → apply `upstream-php2shell-…patch`.
4. **You are stuck on 7.4 / 8.0 / 8.1** → PHP's minimal source backports
   (mirrored by `legacy/php2shell-minimal-backport-7.4-8.1.patch`), plus the
   toolkit's configuration mitigations, plus a migration plan. CISA guidance:
   if you cannot patch EOL PHP, take the systems offline.
5. **≤ 7.3 / PHP 5** → no supported branch and no upstream source backport, so
   there is nothing in this directory for you. That is *not* the same as
   unfixable: check your vendor/LTS channel first (Debian/Ubuntu ESM, RHEL ELS,
   SUSE LTSS, vendor PHP builds — Ubuntu ESM ships a fixed PHP 5 for Trusty).
   If the vendor has no backport, migrate or take the host offline (CISA).

## Provenance / integrity

* PHP2Shell patch: `diff -ru` of the `Zend/`, `main/`, `ext/session/`,
  `ext/opcache/`, `ext/standard/` (var), `ext/spl/` directories of the official
  `php-8.3.35.tar.xz` and `php-8.3.36.tar.xz` release tarballs from
  `https://www.php.net/distributions/`, filtered to core engine files.
* CVE-2019-11043 patch: `diff -u` of `sapi/fpm/fpm/fpm_main.c` between
  `php-7.3.10.tar.xz` and `php-7.3.11.tar.xz` (the only changed hunk in that
  file — it *is* the security fix).
* CVE-2024-4577 patch: the two security hunks of `sapi/cgi/cgi_main.c` between
  `php-8.3.7.tar.xz` and `php-8.3.8.tar.xz` (NEWS: "Fixed bug GHSA-3qgc-jrrr-25jv
  (Bypass of CVE-2012-1823, Argument Injection in PHP-CGI). (CVE-2024-4577)").
* Every patch was `patch -p1 --dry-run` verified against the vulnerable tree
  before being published here.

## Advisory references

* CVE-2026-109618 — GHSA-w8hw-w9fx-j79w (RCE via OOM corruption)
* CVE-2026-109619 — GHSA-6wmf-4rv5-p3rp (RCE via stale global state)
* CVE-2026-115560 — php.net informational advisory 2026-10-23 (keep
  `session.upload_progress.enabled=0` until the next bugfix release)
* CVE-2024-4577 — GHSA-3qgc-jrrr-25jv / NVD / CISA KEV
* CVE-2019-11043 — PHP bug #78598 / NVD / CISA KEV
