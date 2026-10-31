# Contributing

Thanks for taking the time to improve `php-secure-patch`, maintained by
**ESS KS Life Tech**.

## Ground rules

* **bash 3.2 compatible.** macOS still ships 3.2, so no associative arrays, no
  `mapfile`, no `${var,,}` / `${var^^}`, no `&>>`, no globstar `**`, no
  `readarray`. Guard array expansion with `${ARR[@]+"${ARR[@]}"}` because
  `set -u` is on.
* **No new runtime dependencies.** bash, coreutils, awk, sed and grep only.
  Anything optional must degrade gracefully when missing.
* **Every `--fix` action must be reversible.** Back the file up first, record it
  in `MANIFEST.txt`, and verify `rollback.sh` can restore it.
* **Fast failure over guessing.** If a value cannot be verified, report it as
  unknown rather than assuming the safe case.
* **Idempotent.** Running `setup.sh --fix` twice must not duplicate blocks in a
  config file or stack backups indefinitely.
* **Platform reality.** Nothing may assume GNU coreutils; `sed -i` differs
  between GNU and BSD, so use a temp file.

## Before opening a pull request

```sh
./tests/run-tests.sh                      # must stay green, no root needed
bash -n setup.sh rollback.sh install.sh lib/*.sh hunt/hunt.sh \
        tests/run-tests.sh patches/apply-source-patches.sh
shellcheck -S warning setup.sh lib/*.sh   # advisory, but do not add new findings
php -l scanner/project-scanner.php        # if you touched the PHP scanner
```

If you changed detection, verdict logic, exit codes or reporting, add a case to
`tests/run-tests.sh` using the existing `assert_eq` / `assert_contains` /
`assert_rc` helpers. A fixture directory under a `mktemp -d` temp tree is the
cleanest way to test project detection.

## Pull requests

* One logical change per PR; keep the diff reviewable.
* Describe the *user-visible* effect: what changes for someone running
  `setup.sh`, and what changes in the report.
* Say how you verified it — distro, PHP SAPI, web server, and whether you ran it
  as root or only in `--dry-run`.
* Never include production configs, credentials, hostnames or log excerpts with
  real data. Redact before pasting.

## Commit messages

Short imperative summary line, then a body that explains why the change is
needed. Reference the CVE identifier when the change is CVE-driven.

## Reporting security bugs

Do not use the issue tracker. Follow [SECURITY.md](SECURITY.md).
