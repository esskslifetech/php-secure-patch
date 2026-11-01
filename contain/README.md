# Containment artifacts

Everything in this directory exists to answer one question fast: **how do I stop
this being exploitable in the next ten minutes, without a change window?**

Containment is not a patch. Each file here makes the vulnerable decode path
unreachable or fails closed in front of it; none of them removes the bug. The
toolkit says so in every report, and `--verify` keeps them separate from fixes.

```sh
sudo ./setup.sh --contain --yes     # apply what can be applied safely
sudo ./setup.sh --quarantine        # also move webshell-shaped files aside
sudo ./rollback.sh                  # undo everything above
```

## What is applied automatically

| File | Target | Applied by |
|---|---|---|
| `snippets/nginx-deny-br.conf` | included inside every PHP/proxy `server` block; `nginx -t` validated, edits rolled back on failure | `--contain` |
| `snippets/apache-deny-br.conf` | `conf-available` + enable symlink, or `conf.d`; `configtest` validated | `--contain` |
| `guards/node-p2s-guard.cjs` | emitted to `<state>/contain/` with wiring instructions | `--contain` |
| `guards/python-p2s-guard.py` | emitted to `<state>/contain/` with wiring instructions | `--contain` |
| `snippets/envoy-remove-brotli-decompressor.yaml` | emitted as guidance (editing a mesh at runtime is your change) | `--contain` |
| `windows-iis-http2shell.ps1` | emitted; run it per site on Windows | `--contain` / manually |

State directory: `/etc/protection2shell/contain` as root,
`~/.protection2shell/contain` otherwise (override with `P2S_STATE_DIR`).

## Why the guards exist when there is a proxy

A reverse proxy only sees **requests**. The direction that surprises people is
**egress**: Node's `fetch()` and Python's urllib3/httpx/aiohttp decode
`Content-Encoding: br` responses automatically, before application code runs.
When your service fetches an attacker-influenced URL, the attacker is the server
and no perimeter device can see the payload.

Hence: proxy guard for inbound, process guard for outbound. Both, or the job is
half done.

## Wiring the Node guard (requires a restart)

```sh
mkdir -p /etc/systemd/system/<unit>.d
cat > /etc/systemd/system/<unit>.d/protection2shell-guard.conf <<'CONF'
[Service]
Environment=NODE_OPTIONS=--require /etc/protection2shell/contain/node-p2s-guard.cjs
CONF
systemctl daemon-reload && systemctl restart <unit>
```

Escape hatch: `P2S_DENY_BR=0` for a single process that legitimately receives
Brotli uploads on a rebuilt runtime.

## Wiring the Python guard

Install as `sitecustomize.py` on `PYTHONPATH`, or import it at the top of the
service entry point. It fails closed in urllib3 (thus requests), httpx, aiohttp
and the `brotli`/`brotlicffi` modules.

## Deliberate non-actions

* **No automatic IP blocking.** A mis-tuned block rule in the middle of an
  incident is a self-inflicted outage, and it stops one source, not the channel.
  Cut the channel instead.
* **No automatic body-cap change.** A cap below ~23 MB blocks the known RCE
  payload but not the tiny DoS payload; shrinking someone's upload limit is a
  product decision, so it is documented (commented line in the nginx snippet) and
  left to you.
* **No automatic `Content-Encoding` stripping on requests.** That header
  describes the *body you sent*; stripping it makes a Brotli body arrive
  labelled as plaintext and is not a control.
* **No process killing.** `--contain` recycles workers through the service
  manager. Killing processes on a production host during triage destroys the
  evidence you will want at 03:00.
