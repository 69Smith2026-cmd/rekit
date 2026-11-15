from __future__ import annotations

import importlib
import pkgutil
from abc import ABC, abstractmethod
from pathlib import Path

from rekit.models import Finding

PACKAGE = "rekit.analyzers"
REGISTRY: dict[str, type[Analyzer]] = {}


class Analyzer(ABC):
    name: str
    description: str = ""
    tags: tuple[str, ...] = ()
    requires: tuple[str, ...] = ()
    streams: bool = False

    @abstractmethod
    def analyze(self, path: Path, data: bytes) -> list[Finding]:
        ...

    def applies_to(self, path: Path, data: bytes) -> bool:
        return True

    def missing_deps(self) -> list[str]:
        out = []
        for mod in self.requires:
            try:
                importlib.import_module(mod)
            except ImportError:
                out.append(mod)
        return out

    def __repr__(self) -> str:
        return f"<{type(self).__name__} {self.name}>"


def register(cls: type[Analyzer]) -> type[Analyzer]:
    name = getattr(cls, "name", "")
    if not name:
        raise TypeError(f"{cls.__name__} must define a non-empty name")
    if name in REGISTRY:
        raise ValueError(f"duplicate analyzer name: {name}")
    REGISTRY[name] = cls
    return cls


def discover_analyzers() -> dict[str, type[Analyzer]]:
    pkg = importlib.import_module(PACKAGE)
    for _f, mod, _p in pkgutil.iter_modules(pkg.__path__):
        importlib.import_module(f"{PACKAGE}.{mod}")
    return REGISTRY
