"""protection2shell :: HTTP2Shell containment guard (Python)

CVE-2026-111497 — Google Brotli heap out-of-bounds write (CWE-787).

WHY A PYTHON GUARD IS NEEDED
    Installing `brotli` or `brotlicffi` silently upgrades urllib3, requests,
    httpx, aiohttp and Scrapy to auto-decode `Content-Encoding: br`. The
    application never imports Brotli and never asks for it — the C decoder is
    reached by the HTTP client itself, so the vulnerable code runs before any
    application-level check. This guard makes every one of those decode paths
    fail closed instead of entering the decoder.

WHAT THIS DOES
    * urllib3 (and therefore requests): refuse to initialise a Brotli decoder
      for a response whose Content-Encoding contains "br".
    * httpx: replace the Brotli decoder with one that raises.
    * aiohttp: refuse to construct its Brotli decompressor.
    * brotli / brotlicffi: replace decompress()/decompress() with a raise, so
      explicit use fails closed too.

WHAT THIS CANNOT DO
    It cannot patch the C library. Upgrade the package
    (`pip install -U "brotli>=1.2.1"` or `"brotlicffi>=1.2.1.0"`), regenerate
    lockfiles and rebuild images — that is the actual fix.

INSTALL (any one of):
    1. sitecustomize: copy this file to a directory on PYTHONPATH as
       sitecustomize.py (or import it from an existing sitecustomize).
    2. explicit: PYTHONSTARTUP is interactive-only, so for services use
       `python -c "import p2s_guard; ..."` or `import p2s_guard` at the top of
       your entry point.
    3. containers: `ENV PYTHONPATH=/etc/protection2shell/contain/guards`
       with the file named sitecustomize.py.

ESCAPE HATCH: P2S_DENY_BR=0 disables the guard for one process.
"""

import os
import sys

_ALREADY = "_protection2shell_brotli_guard"
_ERROR = (
    "protection2shell: Brotli decoding is disabled in this process because the "
    "decoder is unpatched (CVE-2026-111497). Upgrade to brotli>=1.2.1 / "
    "brotlicffi>=1.2.1.0, or set P2S_DENY_BR=0 to override."
)


def _enabled():
    return os.environ.get("P2S_DENY_BR", "1").strip().lower() not in (
        "0", "false", "off", "no")


def _is_brotli(value):
    if not value:
        return False
    if isinstance(value, bytes):
        value = value.decode("latin-1", "replace")
    return any(part.strip().split(";")[0].strip().lower() == "br"
               for part in str(value).split(","))


def _raise():
    raise RuntimeError(_ERROR)


def _patch_urllib3():
    try:
        from urllib3.response import HTTPResponse
    except Exception:
        return
    original = getattr(HTTPResponse, "_init_decoder", None)
    if original is None or getattr(original, "_p2s_guard", False):
        return

    def guarded_init_decoder(self):
        try:
            encoding = self.headers.get("content-encoding", "")
        except Exception:
            encoding = ""
        if _enabled() and _is_brotli(encoding):
            _raise()
        return original(self)

    guarded_init_decoder._p2s_guard = True
    HTTPResponse._init_decoder = guarded_init_decoder


def _patch_httpx():
    try:
        from httpx import _decoders
    except Exception:
        return
    decoder = getattr(_decoders, "BrotliDecoder", None)
    if decoder is None or getattr(decoder, "_p2s_guard", False):
        return

    class _DeniedBrotliDecoder(object):
        _p2s_guard = True

        def __init__(self, *args, **kwargs):
            _raise()

        def decode(self, data):
            _raise()

        def flush(self):
            raise RuntimeError(_ERROR)

    _decoders.BrotliDecoder = _DeniedBrotliDecoder


def _patch_aiohttp():
    try:
        from aiohttp import compression_utils
    except Exception:
        return
    klass = getattr(compression_utils, "BrotliDecompressor", None)
    if klass is None or getattr(klass, "_p2s_guard", False):
        return

    class _DeniedBrotliDecompressor(object):
        _p2s_guard = True

        def __init__(self, *args, **kwargs):
            _raise()

        def decompress(self, data):
            _raise()

        def flush(self):
            raise RuntimeError(_ERROR)

    compression_utils.BrotliDecompressor = _DeniedBrotliDecompressor


def _patch_modules():
    for name in ("brotli", "brotlicffi"):
        if name not in sys.modules and name not in ("brotli",):
            continue
        try:
            mod = __import__(name)
        except Exception:
            continue
        if getattr(mod, _ALREADY, False):
            continue
        for attr in ("decompress", "Decompressor"):
            if hasattr(mod, attr):
                try:
                    setattr(mod, attr, _raise)
                except Exception:
                    pass
        try:
            setattr(mod, _ALREADY, True)
        except Exception:
            pass


def install():
    """Idempotently install every available hook. Safe to call repeatedly."""
    if not _enabled():
        return False
    _patch_urllib3()
    _patch_httpx()
    _patch_aiohttp()
    _patch_modules()
    return True


install()
