## What this changes

<!-- One or two sentences. What does a user running setup.sh see differently? -->

## Why

<!-- The bug, the CVE, the distro, the stack that motivated it. -->

## How it was verified

- [ ] `./tests/run-tests.sh` passes (new case added if behaviour changed)
- [ ] `bash -n` clean on every script I touched
- [ ] Tested on: <!-- distro + version, PHP version + SAPI, web server -->

Mode used (tick any):

- [ ] audit only
- [ ] `--dry-run`
- [ ] real `--fix` on a staging host (backup set available)
- [ ] not applicable (docs / CI only)

## Reversibility

- [ ] Every file this change writes is backed up and restorable via `rollback.sh`
- [ ] No new runtime dependency was introduced
- [ ] Still bash 3.2 compatible (no associative arrays, `mapfile`, `${var,,}`, `&>>`)

## Notes for the reviewer

<!-- Anything that needs a second pair of eyes: sed portability, FPM vs mod_php,
     distro-specific package names, detection false positives. -->
