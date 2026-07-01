"""Capture-tier abstraction and shared helpers.

A :class:`CaptureTier` is one concrete capture *mechanism* (Tier 1 SOCK_DIAG or
Tier 2 NFLOG). Each owns the full lifecycle of one capture: ``start`` begins
collecting traffic, ``stop`` finalizes an app-scoped pcap and returns a
:class:`~apptap.result.CaptureResult`, and ``teardown`` performs idempotent
cleanup of anything ``start`` installed.

The helpers below are deliberately small, pure-ish, and shared by both tiers so
the two concrete classes stay focused on their distinct capture strategy.
"""

from __future__ import annotations

import contextlib
import os
from abc import ABC, abstractmethod

from apptap.constants import DEFAULT_NFLOG_GROUP, DEVICE_TMP, INFRA_PORTS
from apptap.executors.base import BackgroundProc, Executor
from apptap.result import CaptureResult
from apptap.targets import Target, Tier


def _infra_bpf() -> str:
    """Return a tcpdump BPF excluding AppTap's own infrastructure ports.

    The interface capture (Tier 1) sees adb and frida-server control traffic on
    the same interface. Excluding their ports keeps that tooling noise out of the
    app-scoped capture. The expression is purely additive ``tcp port`` clauses so
    it stays valid even if :data:`INFRA_PORTS` changes.
    """
    ports = " or ".join(f"tcp port {p}" for p in INFRA_PORTS)
    return f"not ({ports})"


def _host_tmp_pcap(output: str) -> str:
    """Return a temp pcap path on the host beside ``output``.

    Capture writes raw (unfiltered) packets here first; ``stop`` then filters
    into ``output``. Placing it next to ``output`` keeps it on the same
    filesystem so the eventual write/move is cheap.
    """
    directory = os.path.dirname(output)
    name = os.path.basename(output)
    return os.path.join(directory, f"_{name}")


def _stop_remote_tcpdump(executor: Executor, proc: BackgroundProc | None, binname: str) -> None:
    """Gracefully stop a running tcpdump, robust to it already being gone.

    On Android the tcpdump runs on-device, so terminating the local transport
    handle does not stop it; we ``pkill -INT`` the on-device process (a clean
    SIGINT lets tcpdump flush its capture buffer) before tearing down the handle,
    falling back to ``pkill -9``. On Linux the handle *is* the process, so a
    terminate/kill suffices. Never raises.
    """
    if executor.platform == "android":
        _stop_android_tcpdump(executor, binname)
    _terminate_proc(proc)


def _stop_android_tcpdump(executor: Executor, binname: str) -> None:
    """Signal the on-device tcpdump to stop, SIGINT first then SIGKILL."""
    with contextlib.suppress(Exception):
        executor.shell("pkill", "-INT", "-f", binname)
    with contextlib.suppress(Exception):
        executor.shell("pkill", "-9", "-f", binname)


def _terminate_proc(proc: BackgroundProc | None) -> None:
    """Terminate then kill a background proc handle; ignore if already gone."""
    if proc is None:
        return
    with contextlib.suppress(Exception):
        proc.terminate()
    with contextlib.suppress(Exception):
        proc.kill()


class CaptureTier(ABC):
    """One concrete capture mechanism with a start/stop/teardown lifecycle.

    Args:
        executor: transport the capture runs on.
        target: the application being scoped to (carried for context/results).
        uids: resolved UID set the capture is scoped to.
        output: host path the finalized app-scoped pcap is written to.
        tcpdump_cmd: invocable tcpdump command on the target (from
            :class:`~apptap.tcpdump.TcpdumpProvider`).
        nflog_group: NFLOG group used by Tier 2.
        device_tmp: device-side scratch dir for on-device temp pcaps (Android).
    """

    def __init__(
        self,
        executor: Executor,
        target: Target,
        uids: set[int],
        output: str,
        *,
        tcpdump_cmd: str,
        nflog_group: int = DEFAULT_NFLOG_GROUP,
        device_tmp: str = DEVICE_TMP,
    ) -> None:
        self.executor = executor
        self.target = target
        self.uids: set[int] = set(uids)
        self.output = output
        self.tcpdump_cmd = tcpdump_cmd
        self.nflog_group = nflog_group
        self.device_tmp = device_tmp

    @property
    @abstractmethod
    def tier(self) -> Tier:
        """The :class:`~apptap.targets.Tier` this class implements."""
        raise NotImplementedError

    @abstractmethod
    def start(self) -> None:
        """Begin capturing. Returns once capture is running."""
        raise NotImplementedError

    @abstractmethod
    def stop(self) -> CaptureResult:
        """Stop capturing, finalize the app-scoped pcap, and return the result."""
        raise NotImplementedError

    def teardown(self) -> None:  # noqa: B027  (intentional concrete no-op default)
        """Idempotent cleanup of anything ``start`` installed. Never raises.

        Concrete no-op by design: Tier 1 installs no device state, so it needs no
        teardown; NflogTier overrides this to remove its netfilter rules.
        """

    # --- shared helpers exposed to subclasses --------------------------------

    @staticmethod
    def _infra_bpf() -> str:
        return _infra_bpf()

    @staticmethod
    def _host_tmp_pcap(output: str) -> str:
        return _host_tmp_pcap(output)

    @staticmethod
    def _stop_remote_tcpdump(executor: Executor, proc: BackgroundProc | None, binname: str) -> None:
        _stop_remote_tcpdump(executor, proc, binname)

    def _tcpdump_binname(self) -> str:
        """Basename of the tcpdump command, used to ``pkill`` it on-device."""
        return os.path.basename(self.tcpdump_cmd.split()[0]) if self.tcpdump_cmd else "tcpdump"


__all__: list[str] = [
    "CaptureTier",
    "_infra_bpf",
    "_host_tmp_pcap",
    "_stop_remote_tcpdump",
]
