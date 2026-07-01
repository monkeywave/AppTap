"""Tier 2 (NFLOG): in-kernel pre-filtered capture.

The kernel marks and logs only the app's connections to an NFLOG group (see
:mod:`apptap.netfilter` for the rule rationale), so ``tcpdump -i nflog:<group>``
reads an *already app-scoped* stream. No per-packet userspace filtering is needed
and the resulting pcap is the final output directly.

Tier 2 is preferred when the kernel actually delivers NFLOG packets; if it does
not (common on stock Android GKI), ``stop`` flags an empty capture so the caller
can fall back to Tier 1.
"""

from __future__ import annotations

import os
from typing import List, Optional

from apptap.executors.base import BackgroundProc
from apptap.netfilter import build_setup, build_teardown
from apptap.result import CaptureResult
from apptap.targets import Tier
from apptap.tiers.base import CaptureTier

#: libpcap DLT for NFLOG-linktype pcaps.
_LINKTYPE_NFLOG = 239

_IPT_V4 = "iptables"
_IPT_V6 = "ip6tables"


class NflogTier(CaptureTier):
    """Tier 2: install netfilter mark+log rules and capture the NFLOG group."""

    @property
    def tier(self) -> Tier:
        return Tier.NFLOG

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._proc: Optional[BackgroundProc] = None
        self._installed = False
        self._tmp_pcap = self._host_tmp_pcap(self.output)
        self._remote_pcap: Optional[str] = None
        self._warnings: List[str] = []

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Install the netfilter rules (self-healing) and start the NFLOG capture."""
        self._install_rules()
        self._start_capture()

    def stop(self) -> CaptureResult:
        """Stop capture, retrieve the app-scoped pcap, and tear rules down."""
        self._stop_remote_tcpdump(self.executor, self._proc, self._tcpdump_binname())
        self._collect_output()
        self.teardown()
        self._check_liveness()
        return CaptureResult(
            tier=Tier.NFLOG,
            uids=frozenset(self.uids),
            connections=(),
            pcap_path=self.output,
            linktype=_LINKTYPE_NFLOG,
            warnings=list(self._warnings),
        )

    def teardown(self) -> None:
        """Remove the netfilter rules for both families. Idempotent, never raises."""
        for ipt in (_IPT_V4, _IPT_V6):
            self._run_argvs(build_teardown(ipt), ignore_errors=True)
        self._installed = False

    # --- start internals -----------------------------------------------------

    def _install_rules(self) -> None:
        """Self-heal stale rules, then install v4 (required) and v6 (best-effort)."""
        # Clear any leftovers from a previous aborted run before installing.
        for ipt in (_IPT_V4, _IPT_V6):
            self._run_argvs(build_teardown(ipt), ignore_errors=True)

        uids = sorted(self.uids)
        self._run_argvs(build_setup(uids, self.nflog_group, _IPT_V4))
        try:
            self._run_argvs(build_setup(uids, self.nflog_group, _IPT_V6))
        except Exception as exc:
            self._warnings.append(
                f"Tier 2 ip6tables setup failed; IPv6 traffic may be missing: {exc}"
            )
        self._installed = True

    def _start_capture(self) -> None:
        """Start tcpdump reading the NFLOG group (already app-scoped, no BPF)."""
        if self.executor.platform == "android":
            self._remote_pcap = self.device_tmp + "_apptap_nflog.pcap"
            write_to = self._remote_pcap
        else:
            self._remote_pcap = None
            write_to = self.output
        self._proc = self.executor.shell(
            self.tcpdump_cmd,
            "-U",
            "-i",
            f"nflog:{self.nflog_group}",
            "-s",
            "0",
            "-w",
            write_to,
            background=True,
        )

    # --- stop internals ------------------------------------------------------

    def _collect_output(self) -> None:
        """Get the app-scoped pcap to ``self.output`` (pull on android, else direct)."""
        if self._remote_pcap is not None:
            self.executor.pull_file(self._remote_pcap, self.output)
        # On linux tcpdump already wrote straight to self.output.

    def _check_liveness(self) -> None:
        """Warn if the capture is missing/empty (NFLOG delivery likely unavailable)."""
        try:
            size = os.path.getsize(self.output)
        except OSError:
            size = 0
        if size == 0:
            self._warnings.append(
                "Tier 2 produced no packets — kernel NFLOG delivery may be "
                "unavailable; consider Tier 1"
            )

    # --- rule execution ------------------------------------------------------

    def _run_argvs(self, argvs, *, ignore_errors: bool = False) -> None:
        """Run each argv list through the executor; optionally swallow failures."""
        for argv in argvs:
            try:
                self.executor.shell(*argv)
            except Exception:
                if not ignore_errors:
                    raise
