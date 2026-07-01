"""``LocalExecutor`` — runs commands on the local Linux host.

Used for desktop (Linux) capture. Commands run through the local shell via
``subprocess``; privilege elevation is done with ``sudo -n`` (non-interactive)
when the process is not already running as root. "Pushing" and "pulling" files
on a local host is just a copy, so :meth:`push_file`/:meth:`pull_file` use
``shutil.copy``.
"""

from __future__ import annotations

import os
import shutil
import subprocess

from apptap.executors.base import BackgroundProc, CmdResult

# Default timeout (seconds) for foreground commands.
DEFAULT_TIMEOUT = 30


class LocalExecutor:
    """Execute commands and copy files on the local Linux host.

    Args:
        use_sudo: When True (default), :meth:`shell` prefixes commands with
            ``sudo -n`` if the current process is not already root. Tests pass
            ``use_sudo=False`` so they need no privileges.
    """

    def __init__(self, use_sudo: bool = True) -> None:
        self.use_sudo = use_sudo

    @property
    def platform(self) -> str:
        """Target platform — always ``"linux"`` for the local executor."""
        return "linux"

    @property
    def is_rooted(self) -> bool:
        """True when the current process runs as uid 0."""
        return os.geteuid() == 0

    def _elevate(self, argv: list[str]) -> list[str]:
        """Prefix ``argv`` with ``sudo -n`` when elevation is needed/wanted."""
        if self.use_sudo and not self.is_rooted:
            return ["sudo", "-n"] + argv
        return argv

    def shell(self, *args: str, background: bool = False, timeout: float | None = None) -> CmdResult | BackgroundProc:
        """Run a command on the local shell, elevating with ``sudo`` if needed.

        Args are joined into a single argument vector. With ``background=True``
        the running :class:`subprocess.Popen` is returned (stdout/stderr piped);
        otherwise the command runs to completion and a :class:`CmdResult` is
        returned.
        """
        argv = self._elevate(list(args))
        if background:
            return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return self._run(argv, timeout)

    def run(self, *args: str, timeout: float | None = None) -> CmdResult:
        """Run a non-elevated local command and return its :class:`CmdResult`."""
        return self._run(list(args), timeout)

    def _run(self, argv: list[str], timeout: float | None) -> CmdResult:
        """Execute ``argv`` to completion, capturing output as text."""
        effective_timeout = DEFAULT_TIMEOUT if timeout is None else timeout
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=effective_timeout,
            )
        except subprocess.TimeoutExpired as exc:
            return CmdResult(124, stdout=exc.stdout or "", stderr="timeout expired")
        except OSError as exc:
            return CmdResult(127, stderr=str(exc))
        return CmdResult(proc.returncode, stdout=proc.stdout, stderr=proc.stderr)

    def push_file(self, local: str, remote: str) -> CmdResult:
        """Copy a host file to another local path (push == copy on localhost)."""
        return self._copy(local, remote)

    def pull_file(self, remote: str, local: str) -> CmdResult:
        """Copy a local path back to the host (pull == copy on localhost)."""
        return self._copy(remote, local)

    def _copy(self, src: str, dst: str) -> CmdResult:
        """Copy ``src`` to ``dst`` returning a :class:`CmdResult`."""
        try:
            shutil.copy(src, dst)
        except OSError as exc:
            return CmdResult(1, stderr=str(exc))
        return CmdResult(0)
