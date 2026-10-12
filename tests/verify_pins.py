#!/usr/bin/env python3
"""Verify that every pinned download is still the artifact devstack expects.

This is the one check that needs the network, so it is not part of the unittest suite: it runs as a
scheduled CI job (and by hand before bumping a pin). It still needs no host, no root and no incus.

    python3 tests/verify_pins.py

Exit 0 = every pin matches. Exit 1 = a hash differs or a download failed, and the output says which.
A mismatch is not automatically an attack: upstream may have re-cut a release. Investigate before
changing a constant -- the point of a pin is that this fails instead of the build trusting it.
"""
from __future__ import annotations

import hashlib
import importlib.util
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("devstack_py", ROOT / "devstack.py")
ds = importlib.util.module_from_spec(spec)
sys.modules["devstack_py"] = ds
spec.loader.exec_module(ds)

TIMEOUT = 180


def fetch_sha256(url: str) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=TIMEOUT) as r:  # noqa: S310 (https URLs below)
        for chunk in iter(lambda: r.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pins() -> list[tuple[str, str, str]]:
    """(label, url, expected sha256) for everything pinned by hash."""
    out = [(
        f"nodejs/release-keys@{ds.NODE_KEYRING_COMMIT[:12]} gpg/pubring.kbx",
        f"https://github.com/nodejs/release-keys/raw/{ds.NODE_KEYRING_COMMIT}/gpg/pubring.kbx",
        ds.NODE_KEYRING_SHA256,
    )]
    for tool, ver, shas in (("syft", ds.SYFT_VERSION, ds.SYFT_SHA256),
                            ("grype", ds.GRYPE_VERSION, ds.GRYPE_SHA256)):
        for arch, sha in sorted(shas.items()):
            name = f"{tool}_{ver}_linux_{arch}.tar.gz"
            out.append((name, f"https://github.com/anchore/{tool}/releases/download/v{ver}/{name}", sha))
    for arch, sha in sorted(ds.GITLEAKS_SHA256.items()):
        name = f"gitleaks_{ds.GITLEAKS_VERSION}_linux_{ds.GITLEAKS_ARCH[arch]}.tar.gz"
        out.append((name, f"https://github.com/gitleaks/gitleaks/releases/download/v{ds.GITLEAKS_VERSION}/{name}", sha))
    return out


def main() -> int:
    bad = 0
    for label, url, expected in pins():
        try:
            got = fetch_sha256(url)
        except (urllib.error.URLError, OSError) as e:
            print(f"FAIL {label}: could not download ({e})")
            bad += 1
            continue
        if got == expected:
            print(f"ok   {label}")
        else:
            print(f"FAIL {label}\n       expected {expected}\n       got      {got}\n       {url}")
            bad += 1
    # The apt signing keys are pinned by gpg fingerprint, not by hash, and are checked inside the
    # container at install time (KEY_FPR_CHECK) where gpg is available.
    print(f"\n{'all pins match' if not bad else f'{bad} pin(s) did NOT match'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
