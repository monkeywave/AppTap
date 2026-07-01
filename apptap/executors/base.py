"""The Executor abstraction — AppTap's seam for *where* commands run.

AppTap never calls ``subprocess`` or ``adb`` directly in its capture logic; it
runs everything through an ``Executor``. This is the Dependency-Inversion seam
that lets the same tier logic drive an Android device (``AdbExecutor``), a local
Linux host (``LocalExecutor``), or a host tool's own transport (e.g. friTap
injects an adapter around its existing ADB/root plumbing).

The Protocol mirrors friTap's ``ADB`` surface (``run``/``shell``/``push_file``/
``pull_file``/``is_rooted``) so such an adapter is near pass-through.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, Union, runtime_checkable


@dataclass
class CmdResult:
    """Result of a finished command."""

    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


@runtime_checkable
class BackgroundProc(Protocol):
    """A handle to a still-running background command (e.g. a tcpdump process).

    ``subprocess.Popen`` satisfies this Protocol as-is, so executors may return a
    Popen directly for ``shell(..., background=True)``.
    """

    def poll(self) -> Optional[int]: ...
    def wait(self, timeout: Optional[float] = None) -> int: ...
    def terminate(self) -> None: ...
    def kill(self) -> None: ...


@runtime_checkable
class Executor(Protocol):
    """Runs shell commands and transfers files on the capture target.

    Implementations must apply any privilege elevation themselves (root / ``su 0``
    / Magisk ``su -c``) inside ``run``/``shell`` so callers can pass plain
    commands. Commands are passed as one or more string args, joined with spaces
    (mirroring friTap's ``ADB.shell``).
    """

    def run(self, *args: str, timeout: Optional[float] = None) -> CmdResult:
        """Run a *transport* command (e.g. ``adb push``), without shell elevation."""
        ...

    def shell(
        self, *args: str, background: bool = False, timeout: Optional[float] = None
    ) -> Union[CmdResult, BackgroundProc]:
        """Run a command on the target shell, with elevation applied.

        Returns a :class:`CmdResult` normally, or a :class:`BackgroundProc` when
        ``background=True``.
        """
        ...

    def push_file(self, local: str, remote: str) -> CmdResult:
        """Copy a host file to the target (e.g. install the bundled tcpdump)."""
        ...

    def pull_file(self, remote: str, local: str) -> CmdResult:
        """Copy a target file back to the host (e.g. retrieve the pcap)."""
        ...

    @property
    def is_rooted(self) -> bool:
        """True when ``shell`` runs (or can elevate to) uid 0."""
        ...

    @property
    def platform(self) -> str:
        """Target platform: ``"android"`` or ``"linux"``."""
        ...
