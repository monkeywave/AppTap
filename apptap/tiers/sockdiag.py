"""Tier 1 (SOCK_DIAG): interface capture + socket-table UID filter.

The robust default. AppTap captures *all* traffic on the target's interfaces and
concurrently snapshots the kernel socket table (``/proc/net/*``) to learn which
5-tuples belong to the app's UID(s). On ``stop`` the raw pcap is filtered down to
exactly the app's connections.

This tier needs no special kernel features (no NFLOG, no netfilter) which is why
it is the fallback that always works on any rooted target.
"""

from __future__ import annotations

import contextlib
import threading

from apptap.executors.base import BackgroundProc
from apptap.result import CaptureResult, Connection
from apptap.socket_table import connections_for_uids
from apptap.targets import Tier
from apptap.tiers.base import CaptureTier

#: how often the snapshot thread re-reads the socket table, in seconds.
_SNAPSHOT_INTERVAL = 1.0

#: addresses that mean "unbound/wildcard" and never identify a real endpoint.
_WILDCARD_ADDRS = frozenset({"0.0.0.0", "::", ""})


def connection_endpoints(conns: set[Connection]) -> set[tuple[str, int]]:
    """Collect every concrete ``(addr, port)`` endpoint from ``conns``.

    Both the local and remote endpoint of each connection are included so a
    packet matches whether the app is the source or the destination. Wildcard
    addresses (``0.0.0.0``/``::``/empty) and port ``0`` are skipped because they
    identify no specific peer and would over-match.
    """
    endpoints: set[tuple[str, int]] = set()
    for conn in conns:
        for addr, port in ((conn.laddr, conn.lport), (conn.raddr, conn.rport)):
            if addr in _WILDCARD_ADDRS or port == 0:
                continue
            endpoints.add((addr, port))
    return endpoints


def packet_matches(
    endpoints: set[tuple[str, int]],
    src_ep: tuple[str, int],
    dst_ep: tuple[str, int],
) -> bool:
    """Return True if either packet endpoint is one of the app's endpoints."""
    return src_ep in endpoints or dst_ep in endpoints


class SockDiagTier(CaptureTier):
    """Tier 1: capture-all then filter to the app's socket-table connections."""

    @property
    def tier(self) -> Tier:
        return Tier.SOCKDIAG

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._proc: BackgroundProc | None = None
        self._conns: set[Connection] = set()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._tmp_pcap = self._host_tmp_pcap(self.output)
        self._remote_pcap: str | None = None

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Launch the interface capture and the socket-table snapshot thread."""
        self._start_capture()
        self._start_snapshot_thread()

    def stop(self) -> CaptureResult:
        """Stop capture, pull the pcap, and filter it to the app's connections."""
        self._stop_snapshot_thread()
        self._stop_remote_tcpdump(self.executor, self._proc, self._tcpdump_binname())
        if self._remote_pcap is not None:
            self.executor.pull_file(self._remote_pcap, self._tmp_pcap)
        return self._finalize()

    # --- start internals -----------------------------------------------------

    def _start_capture(self) -> None:
        """Start tcpdump on ``-i any`` writing raw packets to a temp pcap."""
        if self.executor.platform == "android":
            self._remote_pcap = self.device_tmp + "_apptap.pcap"
            write_to = self._remote_pcap
        else:
            self._remote_pcap = None
            write_to = self._tmp_pcap
        self._proc = self.executor.shell(
            self.tcpdump_cmd,
            "-U",
            "-i",
            "any",
            "-s",
            "0",
            "-w",
            write_to,
            self._infra_bpf(),
            background=True,
        )

    def _start_snapshot_thread(self) -> None:
        """Spawn the daemon thread that keeps unioning the app's connections."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._snapshot_loop, name="apptap-sockdiag-snapshot", daemon=True)
        self._thread.start()

    def _snapshot_loop(self) -> None:
        """Union the app's current connections into ``_conns`` until stopped.

        A transient read error (e.g. a ``/proc/net`` file briefly unreadable)
        must not kill the thread, so every iteration is guarded.
        """
        while not self._stop_event.is_set():
            with contextlib.suppress(Exception):
                self._conns |= connections_for_uids(self.executor, self.uids)
            self._stop_event.wait(_SNAPSHOT_INTERVAL)

    # --- stop internals ------------------------------------------------------

    def _stop_snapshot_thread(self) -> None:
        """Signal and join the snapshot thread cleanly."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def _finalize(self) -> CaptureResult:
        """Filter the temp pcap to the app's connections and build the result."""
        warnings: list[str] = []
        pcap_path: str | None = self.output
        try:
            self._filter_pcap()
        except Exception as exc:  # pragma: no cover - exercised via warnings path
            pcap_path = None
            warnings.append(f"Tier 1 could not read the capture pcap: {exc}")
        return CaptureResult(
            tier=Tier.SOCKDIAG,
            uids=frozenset(self.uids),
            connections=tuple(self._conns),
            pcap_path=pcap_path,
            linktype=None,
            warnings=warnings,
        )

    def _filter_pcap(self) -> None:
        """Write only the app's packets from the temp pcap into ``self.output``.

        Scapy is imported lazily so merely importing this module never requires
        it. Packet order is preserved.
        """
        if not self.uids:
            # Whole-device fallback: with no UID to scope to there is nothing to
            # filter against, so keep the capture as-is rather than dropping all.
            import shutil

            shutil.copyfile(self._tmp_pcap, self.output)
            return

        from scapy.layers.inet import IP, TCP, UDP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader, wrpcap

        endpoints = connection_endpoints(self._conns)
        kept = []
        with PcapReader(self._tmp_pcap) as reader:
            for pkt in reader:
                eps = self._packet_endpoints(pkt, IP, IPv6, TCP, UDP)
                if eps is None:
                    continue
                if packet_matches(endpoints, eps[0], eps[1]):
                    kept.append(pkt)
        wrpcap(self.output, kept)

    @staticmethod
    def _packet_endpoints(pkt, IP, IPv6, TCP, UDP):
        """Extract ``((src_ip, sport), (dst_ip, dport))`` for IP/IPv6+TCP/UDP."""
        if pkt.haslayer(IP):
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
        elif pkt.haslayer(IPv6):
            src_ip, dst_ip = pkt[IPv6].src, pkt[IPv6].dst
        else:
            return None
        if pkt.haslayer(TCP):
            l4 = pkt[TCP]
        elif pkt.haslayer(UDP):
            l4 = pkt[UDP]
        else:
            return None
        return (src_ip, int(l4.sport)), (dst_ip, int(l4.dport))
