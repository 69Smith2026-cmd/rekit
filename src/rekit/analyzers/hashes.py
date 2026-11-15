from __future__ import annotations

import hashlib
from pathlib import Path

from rekit.analyzers.base import Analyzer, register
from rekit.models import Finding, Severity

CHUNK = 1024 * 1024


@register
class HashesAnalyzer(Analyzer):
    name = "hashes"
    description = "MD5 / SHA1 / SHA256 digests"
    tags = ("ioc",)
    streams = True

    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        digests = {a: hashlib.new(a) for a in ("md5", "sha1", "sha256")}
        size = 0
        with path.open("rb") as fh:
            while chunk := fh.read(CHUNK):
                size += len(chunk)
                for h in digests.values():
                    h.update(chunk)
        return [
            Finding(
                self.name, "File hashes", Severity.INFO,
                "Cryptographic digests for threat-intel lookup",
                {**{k: v.hexdigest() for k, v in digests.items()}, "size": size},
                [], ["ioc"],
            )
        ]
