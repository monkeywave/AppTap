"""``AdbExecutor`` — runs commands on an Android device over ``adb``.

Privilege elevation mirrors friTap's proven ``RootADB``/``SuADB``/``MagiskADB``
strategy. On first shell use the executor probes how to reach uid 0:

* ``root``   — ``adb shell id -u`` already returns 0; commands run as-is.
* ``su0``    — ``adb shell su 0 id -u`` returns 0; commands wrapped as ``su 0 <cmd>``.
* ``magisk`` — ``adb shell su -c 'id -u'`` returns 0; commands wrapped as
  ``su -c '<escaped>'`` (single quotes escaped ``' -> '\\''``).
* ``none``   — none of the above reached uid 0; commands run unelevated.

The detected strategy is cached, so the probe runs at most once per executor.
"""

from __future__ import annotations

import shlex
import subprocess

from apptap.executors.base import BackgroundProc, CmdResult

# Default timeout (seconds) for foreground commands.
DEFAULT_TIMEOUT = 30
# Short timeout for the elevation probe commands.
PROBE_TIMEOUT = 5

# Elevation strategy identifiers.
STRATEGY_ROOT = "root"
STRATEGY_SU0 = "su0"
STRATEGY_MAGISK = "magisk"
STRATEGY_NONE = "none"


class AdbExecutor:
    """Execute commands and transfer files on an Android device via ``adb``.

    Args:
        device_id: Optional adb device serial. When set, every adb invocation is
            scoped with ``-s <device_id>``.
    """

    def __init__(self, device_id: str | None = None) -> None:
        self.device_id = device_id
        # Lazily resolved elevation strategy; None means "not yet detected".
        self._strategy: str | None = None

    @property
    def platform(self) -> str:
        """Target platform — always ``"android"`` for the adb executor."""
        return "android"

    @property
    def adb_base(self) -> list[str]:
        """The adb command prefix, optionally pinned to a device serial."""
        if self.device_id:
            return ["adb", "-s", self.device_id]
        return ["adb"]

    @property
    def is_rooted(self) -> bool:
        """True when any elevation strategy can reach uid 0."""
        return self._ensure_strategy() != STRATEGY_NONE

    def _ensure_strategy(self) -> str:
        """Return the cached elevation strategy, detecting it on first use."""
        if self._strategy is None:
            self._strategy = self._detect_strategy()
        return self._strategy

    def _detect_strategy(self) -> str:
        """Probe the device to find how to reach uid 0 (mirrors friTap)."""
        if self._probe_uid_zero("id -u"):
            return STRATEGY_ROOT
        if self._probe_uid_zero("su 0 id -u"):
            return STRATEGY_SU0
        if self._probe_uid_zero("su -c 'id -u'"):
            return STRATEGY_MAGISK
        return STRATEGY_NONE

    def _probe_uid_zero(self, raw_shell_cmd: str) -> bool:
        """True when ``adb shell <raw_shell_cmd>`` prints uid 0."""
        result = self._run_adb(["shell", raw_shell_cmd], timeout=PROBE_TIMEOUT)
        if not result.ok:
            return False
        return result.stdout.strip() == "0"

    def _elevator(self, cmd: str) -> str:
        """Wrap ``cmd`` with the elevation prefix for the detected strategy.

        ``root``/``none`` return the command unchanged, ``su0`` prefixes
        ``su 0``, and ``magisk`` wraps in ``su -c '...'`` with single quotes in
        ``cmd`` escaped as ``' -> '\\''``.
        """
        strategy = self._ensure_strategy()
        if strategy == STRATEGY_SU0:
            return f"su 0 {cmd}"
        if strategy == STRATEGY_MAGISK:
            escaped_cmd = cmd.replace("'", "'\\''")
            return f"su -c '{escaped_cmd}'"
        # STRATEGY_ROOT and STRATEGY_NONE both run the command as-is.
        return cmd

    def shell(self, *args: str, background: bool = False, timeout: float | None = None) -> CmdResult | BackgroundProc:
        """Run a command on the device shell, with elevation applied.

        Args are quoted per-arg (so a tcpdump BPF or any arg containing spaces /
        parentheses survives the *device* shell intact), joined into one command,
        elevated per the detected strategy, and run as ``adb [-s id] shell
        <elevated>``. With ``background=True`` the :class:`subprocess.Popen` is
        returned; otherwise a :class:`CmdResult`.
        """
        cmd = " ".join(shlex.quote(a) for a in args)
        elevated_cmd = self._elevator(cmd)
        argv = self.adb_base + ["shell", elevated_cmd]
        if background:
            return subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return self._run(argv, timeout)

    def run(self, *args: str, timeout: float | None = None) -> CmdResult:
        """Run an adb transport command (e.g. ``push``), without shell elevation."""
        return self._run_adb(list(args), timeout)

    def push_file(self, local: str, remote: str) -> CmdResult:
        """Copy a host file to the device via ``adb push``."""
        return self._run_adb(["push", local, remote])

    def pull_file(self, remote: str, local: str) -> CmdResult:
        """Copy a device file back to the host via ``adb pull``."""
        return self._run_adb(["pull", remote, local])

    def _run_adb(self, args: list[str], timeout: float | None = None) -> CmdResult:
        """Run ``adb [-s id] <args>`` and return its :class:`CmdResult`."""
        return self._run(self.adb_base + args, timeout)

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
