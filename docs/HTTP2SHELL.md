# HTTP2Shell / CVE-2026-111497 — technical dossier

**Subject:** Google Brotli decoder heap out-of-bounds write
(Node2Shell / HTTP2Shell / Broccoli2Shell / Brotli2Shell)
**Status as of:** 2026-10-31 · **Toolkit mapping:** `lib/brotli_db.sh`,
`lib/detect_brotli.sh`, `lib/contain.sh`, `patches/brotli/`

This document records what the public record supports, what it gets wrong, and
how `protection2shell` acts on each point. Where the toolkit itself verified
something — the upstream fix diff, the decoder's behaviour before and after —
that is stated as verified; everything else is attributed to the advisory or
research that reported it.

---

## 1. Identification

| Attribute | Value |
|---|---|
| CVE | CVE-2026-111497 |
| Advisories | GHSA-9v8h-qqgm-4m35 (GitHub) · PYSEC-2026-4322 (`brotli`) · PYSEC-2026-4323 (`brotlicffi`) · GHSA-663w-cv8g-jj2p (Bun) · GHSA-3wvj-j6qm-62mr (Envoy) · CVE-2026-115936 (Perl) |
| Weakness | CWE-787 out-of-bounds write, *caused by* CWE-252 unchecked return value |
| Affected | Brotli **1.0.3 → 1.0.9, 1.1.0, 1.2.0** |
| Fixed | **1.0.10 / 1.1.1 / 1.2.1** (upstream, 2026-10-21) |
| Reporter | OpenAI Codex Security (Khai Tran, Sylvie Mayer), via the Node.js project |
| Upstream fix | `google/brotli` commit `0ed4268a` ("Detect and report invalid stream earlier"), plus 50a9b70, b418fa8, da98063 |
| KEV | Added 2026-10-27, federal due date 2026-11-10, ransomware use *unknown* |
| Severity | CVSS 4.0 **9.2** (Google, CNA) · 8.1 (Microsoft, distros) · 9.8 (Singapore CSA) · "High" (Node.js) |

**One CVE, four names.** Node2Shell (Imperva) names the Node path, HTTP2Shell
(Aikido) the any-HTTP-stack path, Broccoli2Shell (Wiz) the broader decoder
surface, Brotli2Shell (JFrog) the non-HTTP paths. None of them appear in the CVE
record or the upstream release notes. They are all the same bug; treat reports
that describe them as separate vulnerabilities as noise.

**It has nothing to do with the HTTP/2 protocol.** The name is about HTTP *body*
decoding. HTTP/1.1 and HTTP/2 are equally affected, because the bug is reached
at the compression layer, beneath framing.

---

## 2. Root cause, layer 1 — an API contract that could not say "no"

The actual defect is an interface design failure, not a missing bounds check.

A streaming decompressor must distinguish two outcomes that look alike to the
caller:

1. **`NEEDS_MORE_INPUT`** — the stream is fine, it merely ran out of bytes
   mid-element. Save state, resume when more arrive. Normal, very common.
2. **`FORMAT_ERROR`** — the stream violates the specification. Nothing that
   follows can repair it. Must abort.

In `c/dec/decode.c`, `DecodeBlockTypeAndLength()` returned a plain
`BROTLI_BOOL`, and `BROTLI_FALSE` was **overloaded to mean both**:

```c
static BROTLI_INLINE BROTLI_BOOL DecodeBlockTypeAndLength(
    int safe, BrotliDecoderState* s, int tree_type) {
  ...
  if (max_block_type <= 1) {
    return BROTLI_FALSE;    /* a permanent format error ... */
  }
```

Worse, the two call sites handled that ambiguity differently. Via `BROTLI_SAFE`:

```c
#define BROTLI_SAFE(METHOD)                          \
  {                                                  \
    if (safe) {                                      \
      if (!Safe##METHOD) {                           \
        result = BROTLI_DECODER_NEEDS_MORE_INPUT;    /* false -> "need more input" */
        goto saveStateAndReturn;                     \
      }                                              \
    } else {                                         \
      METHOD;                                        /* fast path: value DISCARDED */
    }                                                \
  }
```

* **Safe path:** any `false` — including a permanent format error — was
  laundered into `NEEDS_MORE_INPUT`.
* **Fast path:** the return value was dropped entirely; the wrappers
  (`DecodeLiteralBlockSwitch`, `DecodeCommandBlockSwitch`,
  `DecodeDistanceBlockSwitch`) returned `void`, so by the time control returned
  to the call site the information no longer existed anywhere in the program.

**Verified in this repository.** The v1.2.1 source changes the return type to
`BrotliDecoderErrorCode`, adds `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH (-17)`
to `decode.h`, and adds `BROTLI_SAFE_WITH_STATUS` so both paths propagate it.
`patches/brotli/` is the actual v1.2.0→v1.2.1 diff, restricted to the functional
fix, plus a 1.0.x backport — both applied to pristine upstream tarballs,
compiled, round-trip tested, and checked to report `BLOCK_SWITCH` for error -17
where the unpatched decoder reports `INVALID`.

The framing that matters for triage: the missing bounds check is a symptom. The
disease is a **sentinel-value collapse** — one value carrying two mutually
exclusive meanings across an API boundary. That class of bug survives years of
fuzzing because each individual path "looks" handled.

---

## 3. Root cause, layer 2 — how a bad status becomes an out-of-bounds write

`BrotliDecoderState` contains a small union, `s->buffer`, **eight bytes wide**,
sized for the largest single bit-reader refill it should ever need. Its job is to
stash the unread tail of a *genuinely* truncated input so decoding can resume.

When the decoder takes the spurious `NEEDS_MORE_INPUT` exit,
`BrotliDecoderDecompressStream()` copies the unread remainder of the caller's
input into `s->buffer`. Under the intended contract that remainder can never
exceed the few bits the bit reader could not consume — so in release builds the
copy has no effective bounds check.

But the exit was spurious: plenty of input remains, and the parse can never
succeed. Attacker bytes are appended past the 8th byte, crossing into adjacent
`BrotliDecoderState` fields in order: `buffer_length`, positions/counters,
ring-buffer size and mask, the distance ring, the error code, then the
ring-buffer pointer and Huffman-table pointers. Corrupting `buffer_length`/`pos`
turns subsequent decoder indexing into an attacker-influenced write.

A second failure mode is often omitted: with other payload shapes the same
invalid state produces a **permanent 100% CPU spin** instead of a crash
(observed as an infinite loop in Apache Arrow from a **534-byte** input).
Denial of service is the floor of this bug's impact, not a footnote.

---

## 4. The reachability dispute, and how to resolve it

Within 24 hours of disclosure, an analysis argued the bug cannot fire at all: the
maximum literal count (`MLEN`, 2^24) equals `BROTLI_BLOCK_SIZE_CAP` (1<<24) by
design, so with `NBLTYPES = 1` the counter and loop index reach zero together and
the block-switch check never runs. 67 crafted payloads, 0 crashes; impact is DoS
only; 9.2 is inflated.

Two independent responses refuted it:

* the new `FORMAT_BLOCK_SWITCH` error has exactly **one producer**
  (`max_block_type <= 1`), and the *patched* decoder returns it on the canonical
  public PoC — an unreachable path could never emit it on real input;
* an independently constructed payload of **2^24 commands × 11 bits = 23,068,672
  bytes** drives vulnerable 1.2.0 to `NEEDS_MORE_INPUT` plus a 16-byte OOB write
  (or the CPU spin), while patched 1.2.1 returns -17 and stashes nothing.

The clinching detail is arithmetic: the first in-the-wild payload was
**23,069,983 bytes** — the same construction plus HTTP framing. Nobody sends a
23 MB Brotli body by accident.

The measurement half of the unreachability argument survives and matters:
**pointer control is not reachable on linux/x86-64/gcc.** The overflow tops out
at struct offset 98; the pointer that would have to be overwritten lives at 136.
Residual impact there: corruption at an attacker-chosen offset plus a hard DoS.
Meanwhile RCE *was* demonstrated on **linux/arm64**, against a single official
Node build (24.22.0), with multiple attempts, exploit unreleased.

### 4.1 The reconciliation: a struct-layout lottery

> Whether a 16-byte overflow reaches a pointer in `BrotliDecoderState` is a
> function of ABI, architecture, compiler version and how the compiler caches
> the tail-copy counter. On arm64 the layout apparently places something useful
> within reach; on x86-64/gcc it does not.

That explains every disagreement in the public record at once: the PoC scoring
0 hits in 10,000 attempts, the failed replay of the real attack (0/50 reached
`execvp`), and a third team achieving *local* code execution only with an
unfixed system library and a predictable layout.

**Practical consequences, in both directions:**

* *Against complacency:* "no working exploit yet" describes one architecture on
  one day, not a property of the bug. Crash-to-shell is already public and the
  arm64 chain proves the primitive exists.
* *Against panic:* this is not a wormable one-shot, and most internet-facing
  services decode Brotli in processes where a crash is survivable.

### 4.2 Why the severity scores disagree — and why all of them are right

| Score | Source | What it prices in |
|---|---|---|
| 9.2 Critical | Google (CNA), CVSS 4.0 | worst-case decoder impact, network-reachable, no auth |
| 8.1 | Microsoft, distros, CVSS 3.1 | attack complexity in practice; mitigations reduce reliability |
| 9.8 | Singapore CSA | standard v3.1 network-only scoring |
| High | Node.js project | vendor's judgement of realistic runtime impact |

The honest operational statement: **9.2 for prioritisation, High for expected
impact, DoS as the planning floor.** Anyone quoting a single number is doing
triage badly. `protection2shell` prints exactly that, and encodes it in the
report rather than burying it.

---

## 5. The payload-size asymmetry (a real, free control)

The trigger needs 2^24 commands at ~11 bits each, so **weaponised RCE payloads
are ~23 MB**. Trivial DoS payloads are **hundreds of bytes**.

* Request-body limits (commonly 1–10 MB at gateways) accidentally filter the
  known RCE path while leaving DoS completely open.
* Therefore: a service that never saw a 23 MB body is not safe, and a 1 MB cap
  is not a fix.
* And the 23 MB requirement is why the first in-the-wild attempt was one loud
  POST rather than a stealthy spray — which is how it got caught.

---

## 6. Why it spread everywhere

Not because "Brotli is popular" — because of how it is consumed.

1. **Vendoring with no shared-library discipline.** Brotli is C with no stable
   ABI, so consumers copy the source in: Node at `deps/brotli`, Bun, ClickHouse
   (fork pinned at 1.2.0), Apache Arrow (1.0.9), DuckDB (1.1.0), MuPDF, woff2,
   EDK II firmware, 7-Zip-zstd/p7zip/NanaZip, libjxl, PHP Windows builds,
   Electron, Kibana. Patching the OS `libbrotli` fixes almost none of them.
2. **Automatic decompression, in both directions.** Node's `fetch()`
   automatically requests *and decodes* Brotli responses — so any webhook
   consumer, link-preview service, scraper or import-from-URL feature is exposed
   with the attacker playing the *server*. Installing `brotli` or `brotlicffi`
   silently upgrades urllib3, requests, httpx, aiohttp and Scrapy to decode `br`.
   `curl --compressed` decodes if built with Brotli. Bun's advisory is blunt:
   no process-wide workaround, only per-call `decompress: false`.
   .NET is the exception: decompression is opt-in, and .NET Framework is
   unaffected.
3. **The silent-fix anti-pattern.** The fix sat in public `master` for
   **236 days** (2026-02-27 → 2026-10-21) with no advisory, no release, no
   CHANGELOG entry and no regression test. Anyone diffing upstream — human or
   automated — had eight months of head start. This is the single largest
   accelerant, and it is an upstream process failure that will recur.
4. **Version strings actively lie.** Patched Node 24.22.1 and 26.12.1 still
   report `process.versions.brotli === "1.2.0"`; Node 22.23.4 reports `"1.1.0"`
   after cherry-picking the fix; Debian keeps upstream versions with a
   `+deb12u1` suffix. Every version-string scanner is wrong in both directions.
5. **Advisory-database lag.** `pip-audit`, Dependabot and Safety were not
   flagging the vulnerable Python packages on 23 October; PYSEC-2026-4322/4323
   closed the gap later. A Thursday scan gave a false clean.
6. **CVE data-model mismatch.** The CVE names Google Brotli as the product.
   There is no CPE for "Node 24.22.0's bundled Brotli" or a vendor fork, so SBOM
   and asset-inventory tools have nothing to match on for 30+ carriers.
7. **EOL drag.** No fix, ever, for Node 20.x/23.x/25.x (the bug is present back
   to Node 12), Istio 1.29, PHP 7.x/8.0/8.1, older RHEL/Ubuntu modules, Kibana.
8. **Build artifacts freeze the bug in place.** Cached Docker layers, `bun
   build --compile` single-file executables, Node SEA binaries, statically
   linked curl, Electron ≤ 41, VS Code Server < 1.143.1. Updating source does
   nothing until you rebuild and restart.
9. **Information pollution is now part of the attack surface.** At least one
   widely syndicated explainer describes HTTP2Shell as an HPACK /
   CONTINUATION-frame desync in the HTTP/2 protocol. That mechanism is
   fabricated. Triage decisions are being made from it.

---

## 7. Exploitation dynamics (measured, not marketing)

| Interval | Duration | Event |
|---|---|---|
| Silent fix → first release carrying it | **236 days** | 2026-02-27 → 2026-10-21 |
| Disclosure → first public PoC | 1 day | 10-21 → 10-22 |
| Disclosure → RCE shown on an official build | 1 day | linux/arm64 |
| Disclosure → exposure scanning | ~4 days | `node2shell-check/1.0`, by 10-25 |
| Patch → first exploitation attempt | 5 days | 10-26 15:08 UTC, 23,069,983-byte POST |
| Disclosure → CISA KEV | 6 days | 10-27 |

Correction worth repeating: **"the 13-hour collapse" is not this CVE.** That
figure comes from a VMware Tanzu piece about LMDeploy (CVE-2026-33626). For
CVE-2026-111497 the measured numbers are the ones above: PoC in one day,
in-the-wild in five.

Other corroborating telemetry: the in-the-wild delivery copied the public PoC
byte-for-byte for the first 23,069,727 of 23,069,983 bytes (only the final ROP
stage was original, and it did not work), and the source IP had prior history of
PHP2Shell exploitation, VPN probing and Kubernetes API scanning — nobody built a
campaign, this was added to an existing target list. IPS telemetry reported 90.5%
of associated events carrying Brotli payloads, 33.8% a known automation
fingerprint, and 24.5% targeting upload/ingest endpoints.

---

## 8. Who is exposed

Priority is **reachability**, not CVE count. The only question that matters per
service: *can attacker-influenced Brotli reach a decoder in this process?*
Inbound (br request bodies) and outbound (fetched responses) are separate
questions with separate answers.

| Priority | Surface | Exposed *if* | Fix |
|---|---|---|---|
| P0 | Node.js 22/24/26 internet-facing | Express 5 + body-parser 2.x parsing `br` bodies, **or** `fetch()` on user-supplied/webhook URLs | 22.23.4 / 24.22.1 / 26.12.1, then rebuild images/SEA and restart |
| P0 | Python services | `brotli < 1.2.1` or `brotlicffi < 1.2.1.0` in the environment (scrapers, webhooks, link previews) | upgrade both, regenerate lockfiles |
| P0 | Envoy / Istio | a Brotli **decompressor** is configured | Envoy 1.40.0/1.39.3/1.38.6/1.37.8; Istio 1.31.2/1.30.6/1.29.9 |
| P1 | Bun | `fetch`/`DecompressionStream`/`node:zlib` | 1.4.4 + rebuild `--compile` outputs |
| P1 | .NET 8/9/10 | opt-in decompression, `BrotliStream` | 8.0.33 / 9.0.22 / 10.0.14 / 11 RC3 |
| P1 | Media/data pipelines | FFmpeg+libjxl (JPEG XL), Arrow/pyarrow, DuckDB, Parquet from untrusted sources | patch libbrotli beneath them; reject `br`-coded Parquet from untrusted sources |
| P2 | Desktop/embedded | 7-Zip-zstd, p7zip, NanaZip, MuPDF ≤ 1.27.x, Electron ≤ 41, firmware, woff2 | vendor updates |
| P2 | EOL estates | Node 20/23/25 and older, Istio 1.29, PHP 7.x | no fix exists — migrate or buy EOL support |
| n/a | Apache/nginx | they compress but do not decompress by default | not an entry point |

---

## 9. What protection2shell does about it

| Problem | Toolkit behaviour |
|---|---|
| Version strings lie | every carrier carries a CERTAINTY; a capability probe looks for the `BLOCK_SWITCH` error string, which exists in no vulnerable build. Present ⇒ fixed. Absent ⇒ *unknown*, never "vulnerable" |
| Vendored copies invisible | `detect_brotli_vendor` finds `brotli/c/common/version.h` trees under `--scan-path` and standard roots |
| OS package fixed, vendored copy not | `fix_upgrade_brotli_packages` handles what the package manager owns; `--brotli-src` + `patches/apply-brotli-patch.sh` patch the rest, with a compile check |
| Inbound exposure | `--contain`: nginx/Apache/IIS deny `br` request bodies (validated, auto-rolled back) |
| Outbound exposure (no proxy can see it) | `--contain` emits a Node preload and a Python import hook that fail closed on Brotli decoding |
| Patching takes a change window | containment first, in the same run (`--auto`), then patching, then verification |
| Rebuild vs restart confusion | the report and the fix engine name the artifacts that must be rebuilt, and the toolkit refuses to call a run complete before workers are recycled |
| Severity theatre | the report prints the 9.2 / High / DoS-floor position instead of a single number |
| Fabricated mechanisms | documented here, explicitly |

---

## 10. Detection after patching

| Signal | Where | Meaning |
|---|---|---|
| `BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` / `-17` | application logs on a patched runtime | **someone sent a trigger** — highest-value IOC |
| HTTP 415 immediately after a `br` body | ingress | guard rejected a probe |
| `Content-Encoding` containing `br` on JSON/API endpoints | edge/proxy with header logging | legitimate clients rarely do this |
| ~23 MB `br` request bodies | body-size logs | the known exploit shape |
| SIGSEGV/SIGABRT, worker restarts, crash during decoder cleanup | containers, ClickHouse | possible successful trigger on an unpatched host |
| 100% CPU spin on a small input | profiling, Arrow | the 534-byte DoS variant |
| Outbound fetches to new/user-supplied hosts returning `br` | egress proxy | the invisible direction |

`hunt/hunt.sh` scans for these; `hunt/sigma_http2shell*.yml` are SIGMA rules.

---

## 11. Open questions

1. Will a reliable x86-64 chain appear? The arm64 success and the x86-64 ceiling
   suggest it needs a different grooming primitive, not different offsets. If it
   lands, severity consensus collapses upward fast.
2. What evidence is behind the KEV listing? The only publicly described payload
   failed in replay. Either CISA holds private evidence, or KEV was added on
   attempt volume. That changes how much "KEV = exploited" should infer.
3. Does the layout lottery generalise? If per-build exploitability is now normal
   for vendored-C bugs, "CVSS + a PoC" is no longer sufficient triage input.
4. Will upstream change process? A security-labelled commit and a coordinated
   release on 2026-02-27 would have removed the 236-day head start. The same
   failure mode is live for every vendored C library.

---

## 12. Sources

**Primary** — Node.js October 2026 security releases (2026-10-21) · CVE-2026-111497
record (Google CNA) · GHSA-9v8h-qqgm-4m35 · `google/brotli` commit `0ed4268a` and
releases 1.0.10 / 1.1.1 / 1.2.1 · CISA KEV catalog v2026.10.27 · Microsoft .NET
advisory (2026-10-25) · Envoy GHSA-3wvj-j6qm-62mr · Bun GHSA-663w-cv8g-jj2p ·
PYSEC-2026-4322/-4323.

**Technical analysis** — Imperva, *Node2Shell: From Brotli Data to Remote Code
Execution* (2026-10-22) · JFrog, *Brotli2Shell* (10-25) · Akamai, *Inside
Node2Shell* · independent reproduction `lesterlam/node2shell` (the
offset-98-vs-136 measurement) · `ikow/brotli2crash` (unreachability argument;
trigger claim refuted, measurements useful) · `pt-act/node2shell-cve-2026-111497`
(the rebuttal) · ELLIO (first in-the-wild record and replay) · Check Point
Research IPS telemetry (10-29/30) · Wiz, *Broccoli2Shell*.

**Context** — VMware Tanzu, *The 13-Hour Collapse* (refers to LMDeploy
CVE-2026-33626, **not** this CVE) · IT Jungle / Security Boulevard / Fox News on
the "Black October" wave and PHP2Shell.

**Flagged unreliable** — the HPACK/CONTINUATION-frame desync explanation
(fabricated mechanism, unrelated to this CVE) and SEO/AI-generated CVE
summarisers repeating "9.2 + RCE everywhere" without the reachability caveat.

**Verified in this repository** — the `patches/brotli/` diff against upstream
v1.2.0/v1.2.1; the 1.0.9 backport; both compiled with gcc, round-trip tested, and
checked for error -17 behaviour (`INVALID` before, `BLOCK_SWITCH` after).
