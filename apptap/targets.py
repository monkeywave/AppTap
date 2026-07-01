"""Value types describing *what* to capture and *how* broadly.

These are intentionally dependency-free so every module can import them.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Optional


class Tier(enum.Enum):
    """Capture mechanism.

    Request values: ``AUTO`` (probe and pick), ``NFLOG`` (force Tier 2),
    ``SOCKDIAG`` (force Tier 1).

    Result values additionally include ``WHOLE_DEVICE`` (last-resort: capture
    succeeded but could not be scoped to the app's UID).
    """

    AUTO = "auto"
    NFLOG = "nflog"          # Tier 2: in-kernel owner+CONNMARK+NFLOG pre-filter
    SOCKDIAG = "sockdiag"    # Tier 1: interface capture + socket-table UID filter
    WHOLE_DEVICE = "whole_device"  # fallback only (result-only)

    def __str__(self) -> str:  # nicer CLI/log output
        return self.value


class Breadth(enum.Enum):
    """How many UIDs the capture is scoped to."""

    APP_ONLY = "app"                       # base app UID only
    APP_ISOLATED = "app+isolated"          # + isolated/WebView child UIDs
    APP_ISOLATED_DNS = "app+isolated+dns"  # + DNS resolver UID (default)

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Target:
    """The application to scope capture to.

    Provide at least one of ``package`` (Android package name / process name) or
    ``pid``. ``package`` is preferred on Android because the UID is stable across
    restarts; ``pid`` is used on Linux or when the package isn't known.
    """

    package: Optional[str] = None
    pid: Optional[int] = None

    def __post_init__(self) -> None:
        if not self.package and self.pid is None:
            raise ValueError("Target requires at least one of `package` or `pid`")

    def describe(self) -> str:
        if self.package and self.pid is not None:
            return f"{self.package} (pid {self.pid})"
        return self.package or f"pid {self.pid}"
