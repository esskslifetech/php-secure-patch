# Security policy

`php-secure-patch` is defensive tooling that runs as root and edits system
configuration, so bugs in it can be as damaging as the flaws it repairs. Reports
are taken seriously.

## What is in scope

* the shell toolkit — `setup.sh`, `rollback.sh`, `install.sh`, `lib/*.sh`,
  `hunt/hunt.sh`, `tests/run-tests.sh`
* `patches/apply-source-patches.sh` and how it treats the target tree
* `scanner/project-scanner.php`
* the templates in `hardening/`
* anything that lets a detected value (a path, a service name, a project name,
  a log line) influence a command, a file write, or a permission change

## What is not in scope

* the PHP vulnerabilities this toolkit *documents* (CVE-2026-109618,
  CVE-2026-109619, CVE-2026-115560, CVE-2024-4577, CVE-2019-11043). Those belong
  with the PHP project, your distribution, or your vendor.
* findings that require an attacker to already hold root. If root is compromised,
  this tool offers no protection.
* hardening recommendations you disagree with — open a normal issue instead.

## Reporting privately

**Do not open a public issue for a security bug.**

1. Open a private advisory:
   `https://github.com/esskslifetech/php-secure-patch/security/advisories/new`
2. Include: the affected script and line, a reproduction (a fixture directory or
   command sequence is ideal), the impact you believe it has, and a suggested
   fix if you have one.
3. Redact credentials, tokens, customer hostnames and log lines containing them.

Expect an acknowledgement within 5 business days. Fixes ship as soon as they are
verified; actively exploitable issues are prioritised. Credit is given in the
advisory unless you prefer to stay anonymous.

## If you think you have been compromised

This project's own `hunt/hunt.sh` collects the indicators CISA and NCSC guidance
names, but patch first, then hunt, then rotate secrets. A patched worker that
still holds a stale session is a compromised host.

## Authorized use only

Run `--fix` only on systems you own or are explicitly authorized to administer.
The toolkit changes package state, ini files, FPM pools, nginx and Apache
configuration, and restarts services. Test in staging first.
