# Contributing

Thanks for taking the time to improve `protection2shell`, maintained by
**ESS KS Life Tech**.

## Ground rules

* **bash 3.2 compatible.** macOS still ships 3.2, so no associative arrays, no
  `mapfile`, no `${var,,}` / `${var^^}`, no `&>>`, no globstar `**`, no
  `readarray`.
* **Never expand an array unguarded.** `set -u` is on, and bash 3.2 treats
  `"${ARR[@]}"` / `"${ARR[*]}"` on an **empty** array as an unbound variable;
  bash 4.4+ silently allows it. So a declared-but-empty array — the "scan found
  nothing" path, i.e. the case CI's clean-host run exercises and most manual
  testing does not — aborts on macOS while looking perfect on Linux. Always
  write `${ARR[@]+"${ARR[@]}"}`, `${ARR[*]+"${ARR[*]}"}` and
  `ARR=(${TMP[@]+"${TMP[@]}"})`.
* **No new runtime dependencies.** bash, coreutils, awk, sed and grep only.
  Anything optional must degrade gracefully when missing.
* **Every `--fix` action must be reversible.** Back the file up first, record it
  in `MANIFEST.txt`, and verify `rollback.sh` can restore it.
* **Fast failure over guessing.** If a value cannot be verified, report it as
  unknown rather than assuming the safe case. A capability probe may conclude
  "fixed" only from positive evidence (for Brotli: the `BLOCK_SWITCH` error
  string); absence of evidence is `unknown`, never `vulnerable` *and* never
  `fixed`.
* **Patches are generated, never written by hand.** Every `.patch` must come
  from a real upstream diff (or, for an explicit backport, be proven to compile
  and behave identically), state its provenance in the file header, and be
  verified to apply at `--fuzz=0` against the tree named in `patches/README.md`.
* **Containment must fail closed and be reversible.** A guard that lets a
  request through because a directive was misspelled is worse than no guard: it
  buys false confidence. Every containment artifact is backed up, recorded for
  removal, and validated by the target's own config test where one exists.
* **Idempotent.** Running `setup.sh --fix` twice must not duplicate blocks in a
  config file or stack backups indefinitely.
* **Platform reality.** Nothing may assume GNU coreutils; `sed -i` differs
  between GNU and BSD, so use a temp file.

## Before opening a pull request

```sh
./tests/run-tests.sh                      # must stay green, no root needed
bash -n setup.sh rollback.sh install.sh lib/*.sh hunt/hunt.sh \
        tests/run-tests.sh patches/*.sh
shellcheck -S error setup.sh lib/*.sh     # must be clean; CI blocks on this
shellcheck -S warning setup.sh lib/*.sh   # advisory — do not add new findings
node --check contain/guards/node-p2s-guard.cjs
python3 -m py_compile contain/guards/python-p2s-guard.py
php -l scanner/project-scanner.php        # if you touched the PHP scanner

# if you touched patches/brotli/ — prove it against pristine upstream:
curl -fsSL -o /tmp/b.tgz https://codeload.github.com/google/brotli/tar.gz/refs/tags/v1.2.0
tar xzf /tmp/b.tgz -C /tmp && ./patches/apply-brotli-patch.sh /tmp/brotli-1.2.0 --verify
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
