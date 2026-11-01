# Installing PROTECTION2Shell

PROTECTION2Shell is plain Bash plus a PHP helper — nothing to compile, no
daemon, no dependencies beyond the OS tools it already uses (`bash`, `grep`,
`sed`, `awk`, `curl`/`wget`). This page exists because installing a shell
toolkit is where most "it does not work" reports come from.

- [Three ways to install](#three-ways-to-install)
- [Per-platform notes](#per-platform-notes)
- [If something fails](#if-something-fails)
- [What needs root](#what-needs-root)

## Three ways to install

### 1. From the zip (no git, no network)

```bash
unzip protection2shell-2.0.0.zip
cd protection2shell-2.0.0
bash setup.sh                 # read-only audit: works as any user, changes nothing
```

`bash setup.sh` — not `./setup.sh` — because archives lose the executable bit
when extracted by Windows Explorer, Finder's Archive Utility, or many GUI zip
tools. Running it through `bash` sidesteps that entirely. If you prefer the
short form, restore the bit once:

```bash
chmod +x setup.sh rollback.sh install.sh hunt/hunt.sh patches/*.sh
```

### 2. From git

```bash
git clone https://github.com/esskslifetech/php-secure-patch.git protection2shell
cd protection2shell
./setup.sh
```

### 3. System-wide (optional)

```bash
sudo ./install.sh                        # /opt/protection2shell + /usr/local/bin
sudo ./install.sh --timer contain        # also re-assert containment daily
protection2shell                         # audit this host
```

No root? Install into your home directory instead:

```bash
./install.sh --prefix "$HOME/.local/share/protection2shell" --bin "$HOME/.local/bin"
export PATH="$PATH:$HOME/.local/bin"
protection2shell
```

## Per-platform notes

| Host | Install | Notes |
|---|---|---|
| Debian / Ubuntu / Fedora / Arch | `bash setup.sh` | `sudo` for containment and fixes; audit needs nothing |
| RHEL / Rocky / Alma 8+ | `bash setup.sh` | `dnf` upgrades need sudo; EPEL may be required for brotli |
| macOS 12+ | `bash setup.sh` | system bash 3.2 is enough; Homebrew PHP/Brotli detected; containment needs `sudo` |
| Windows 10/11 (Git-Bash) | `bash setup.sh` | audit works; no `sudo` — apply the IIS guard with `contain/windows-iis-http2shell.ps1` from an elevated PowerShell |
| WSL2 | `bash setup.sh` | behaves like Ubuntu; Windows-side IIS needs the PowerShell guard |
| Alpine / containers | `apk add bash` then `bash setup.sh` | `bash` is not installed by default |
| Docker image build | `RUN bash setup.sh --contain --yes` | containment bakes guards into the layer; fixes belong in the base image |

Working directory matters: run the commands from the extracted directory, not
from `$HOME`, or `setup.sh` will not find `lib/`.

## If something fails

| Symptom | Cause | Fix |
|---|---|---|
| `Permission denied` | exec bit lost in the zip | `bash setup.sh` |
| `sh: 1: Syntax error: "(" unexpected` | invoked with `sh`/`dash` | `bash setup.sh` (v2.0.1+ re-execs itself under bash automatically) |
| `cannot write /opt/...` or `run as root` | root path, non-root user | add `sudo`, or use `--prefix "$HOME/..." --bin "$HOME/.local/bin"` |
| `sudo: command not found` | Windows/Git-Bash, minimal containers | run the audit; use `--dry-run` to preview; Windows guard via PowerShell |
| `bash: command not found` | Alpine/BusyBox/minimal image | `apk add bash` / `apt install bash` |
| `unzip: command not found` | minimal host | `apt install unzip`, or `python3 -m zipfile -e file.zip .` |
| Exit code **2** | exposure still present | not a failure: read the report, the exit code means "something is still exposed" |
| `No such file or directory` for `lib/common.sh` | ran from another directory | `cd` into the extracted folder first |
| Nothing detected, everything "clean" | scanning too narrow | `sudo ./setup.sh --scan-path /` |

Exit codes: `0` clean or fully fixed · `2` exposure remains · `1` error.

## What needs root

| Action | Root? |
|---|---|
| Audit (`./setup.sh`), `--json`, `--verify`, `hunt.sh` | no |
| `--contain` / `--quarantine` (writes nginx/Apache/FPM config) | yes |
| `--fix` / `--auto` (package upgrades, ini, service restarts) | yes |
| `--rollback` of system files | yes |
| `install.sh --prefix <user dir> --bin <user dir>` | no |
| `install.sh --timer` (systemd/cron) | yes |

If a step needs root and you are not root, the toolkit says exactly which step
and which command to re-run — it does not fail silently. `--dry-run` always
works without root and prints the same plan the real run would apply.
