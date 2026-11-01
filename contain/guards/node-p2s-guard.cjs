'use strict';
/* =============================================================================
 * protection2shell :: HTTP2Shell containment guard (Node.js / Bun preload)
 * CVE-2026-111497 — Brotli decoder heap out-of-bounds write (CWE-787)
 *
 * WHAT THIS DOES
 *   1. INBOUND  — refuses any request whose Content-Encoding contains "br"
 *                 with 415, before the application's handler runs, so no
 *                 Brotli decoder in this process ever sees attacker bytes.
 *   2. EXPLICIT — makes zlib.brotliDecompress* / zlib.BrotliDecompress throw
 *                 instead of decoding (fail closed for application code that
 *                 decompresses attacker data on purpose).
 *
 * WHAT THIS CANNOT DO
 *   OUTBOUND responses fetched with global fetch()/undici are decompressed
 *   inside the HTTP client before your code sees the Response object, so a
 *   preload cannot refuse them. Keep untrusted egress off the decoder:
 *     - do not fetch user-supplied URLs from a process that can decode Brotli,
 *       or front it with an egress proxy that rewrites Accept-Encoding, and
 *     - upgrade the runtime; the guard is containment, not a patch.
 *
 * WIRING (systemd — restart required):
 *   /etc/systemd/system/<unit>.d/protection2shell-guard.conf
 *     [Service]
 *     Environment=NODE_OPTIONS=--require /etc/protection2shell/contain/node-p2s-guard.cjs
 *   (Node >= 20.6 also accepts --import with an ESM equivalent; --require works
 *    for both CJS and ESM applications.)
 *
 * ESCAPE HATCH: P2S_DENY_BR=0 disables the inbound half for one process (for
 *   example a service that legitimately receives Brotli uploads and has been
 *   rebuilt against a fixed decoder).
 * ========================================================================== */

const GUARD = Symbol.for('protection2shell.guard');
if (!globalThis[GUARD]) {
  globalThis[GUARD] = { installed: true, deniedBodies: 0, blockedDecompress: 0 };
  // A preload that throws is worse than no preload: it takes the whole service
  // down on restart. Each half installs independently and failures are reported
  // on stderr without aborting the process.
  try {
    installInbound();
  } catch (e) {
    warn('inbound guard not installed: ' + e.message);
  }
  try {
    installDecompress();
  } catch (e) {
    warn('decompression guard not installed: ' + e.message);
  }
}

function warn(message) {
  try {
    process.stderr.write('protection2shell: ' + message + '\n');
  } catch (e) {
    /* nowhere left to report */
  }
}

function enabled() {
  const v = (process.env.P2S_DENY_BR || '1').toLowerCase();
  return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
}

/* True when a Content-Encoding value names brotli, including list forms such
 * as "gzip, br" and parameters such as "br;q=1". */
function isBrotli(value) {
  if (!value) return false;
  return String(value)
    .split(',')
    .some(function (token) {
      return token.trim().split(';')[0].trim().toLowerCase() === 'br';
    });
}

function installInbound() {
  let http;
  try {
    http = require('http');
  } catch (e) {
    return;
  }
  const originalEmit = http.Server.prototype.emit;
  if (typeof originalEmit !== 'function') return;

  http.Server.prototype.emit = function (event, req, res) {
    if (event === 'request' && enabled() && req && req.headers &&
        isBrotli(req.headers['content-encoding'])) {
      globalThis[GUARD].deniedBodies += 1;
      if (res && typeof res.end === 'function') {
        try {
          res.statusCode = 415;
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.setHeader('Connection', 'close');
          res.end('415 Unsupported Media Type: Brotli request bodies are refused ' +
                  'by protection2shell (CVE-2026-111497)\n');
        } catch (e) {
          /* headers already sent — nothing safe left to do */
        }
      }
      return true; /* handler chain never runs */
    }
    return originalEmit.apply(this, arguments);
  };
}

function installDecompress() {
  let zlib;
  try {
    zlib = require('zlib');
  } catch (e) {
    return;
  }

  /* Module exports are frequently accessor properties (getter-only) on modern
   * Node, so plain assignment throws. defineProperty with configurable:true
   * works on both plain and accessor-backed exports; anything that still fails
   * is skipped rather than fatal. */
  function replace(name, make) {
    if (typeof zlib[name] !== 'function') return;
    let denied;
    try {
      denied = make();
    } catch (e) {
      return;
    }
    try {
      Object.defineProperty(zlib, name, {
        value: denied,
        configurable: true,
        writable: true,
        enumerable: true
      });
      return;
    } catch (e) {
      /* fall through to plain assignment */
    }
    try {
      zlib[name] = denied;
    } catch (e) {
      warn(name + '() could not be guarded (read-only export)');
    }
  }

  ['brotliDecompress', 'brotliDecompressSync'].forEach(function (name) {
    replace(name, function () {
      return function () {
        globalThis[GUARD].blockedDecompress += 1;
        throw new Error(
          'protection2shell: ' + name + '() is disabled — Brotli decompression is ' +
          'unpatched in this runtime (CVE-2026-111497). Rebuild on a fixed release ' +
          'or set P2S_DENY_BR=0 to override.');
      };
    });
  });

  ['createBrotliDecompress', 'BrotliDecompress'].forEach(function (name) {
    replace(name, function () {
      return function () {
        globalThis[GUARD].blockedDecompress += 1;
        throw new Error(
          'protection2shell: ' + name + ' is disabled — Brotli decompression is ' +
          'unpatched in this runtime (CVE-2026-111497).');
      };
    });
  });
}
