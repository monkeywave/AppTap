"""Unit tests for the capture tiers (Tier 1 SOCK_DIAG, Tier 2 NFLOG).

These use a FAKE executor — canned :class:`CmdResult`s, a recorded command log,
and a fake background proc — so nothing here needs a real device or a real
tcpdump. The pure filter functions are tested directly; the scapy-dependent
filtering path is exercised only when scapy is importable.
"""

from __future__ import annotations

import os
import time

import pytest

from apptap.executors.base import CmdResult
from apptap.result import Connection
from apptap.targets import Target, Tier
from apptap.tiers.base import _host_tmp_pcap, _infra_bpf, _stop_remote_tcpdump
from apptap.tiers.nflog import NflogTier
from apptap.tiers.sockdiag import (
    SockDiagTier,
    connection_endpoints,
    packet_matches,
)

# --- fakes -------------------------------------------------------------------


class FakeProc:
    """Popen-like background proc that records terminate/kill calls."""

    def __init__(self):
        self.terminated = False
        self.killed = False
        self._rc = None

    def poll(self):
        return self._rc

    def wait(self, timeout=None):
        self._rc = 0
        return 0

    def terminate(self):
        self.terminated = True
        self._rc = 0

    def kill(self):
        self.killed = True
        self._rc = -9


class FakeExecutor:
    """Records every issued command; canned results; fake background procs."""

    def __init__(self, platform="android", proc_net=None):
        self._platform = platform
        self.commands = []  # list[tuple[str, ...]] of shell argv
        self.background_calls = []  # the argv of each background shell call
        self.pulled = []  # list[(remote, local)]
        self.pushed = []  # list[(local, remote)]
        self.procs = []  # FakeProcs handed out
        self._proc_net = proc_net or {}

    # Executor protocol ----------------------------------------------------

    def run(self, *args, timeout=None):
        self.commands.append(args)
        return CmdResult(returncode=0)

    def shell(self, *args, background=False, timeout=None):
        self.commands.append(args)
        if background:
            self.background_calls.append(args)
            proc = FakeProc()
            self.procs.append(proc)
            return proc
        # serve /proc/net reads if configured
        if len(args) == 2 and args[0] == "cat" and args[1].startswith("/proc/net/"):
            name = args[1].rsplit("/", 1)[-1]
            return CmdResult(returncode=0, stdout=self._proc_net.get(name, ""))
        return CmdResult(returncode=0)

    def push_file(self, local, remote):
        self.pushed.append((local, remote))
        return CmdResult(returncode=0)

    def pull_file(self, remote, local):
        self.pulled.append((remote, local))
        return CmdResult(returncode=0)

    @property
    def is_rooted(self):
        return True

    @property
    def platform(self):
        return self._platform


def _joined(commands):
    return [" ".join(c) for c in commands]


TARGET = Target(package="com.example.app")


# --- shared helpers ----------------------------------------------------------


def test_infra_bpf_excludes_all_infra_ports():
    bpf = _infra_bpf()
    assert bpf == ("not (tcp port 5037 or tcp port 5555 or tcp port 27042 or tcp port 27043)")


def test_host_tmp_pcap_beside_output():
    tmp = _host_tmp_pcap("/out/dir/capture.pcap")
    assert tmp == os.path.join("/out/dir", "_capture.pcap")


def test_stop_remote_tcpdump_android_signals_then_terminates():
    ex = FakeExecutor(platform="android")
    proc = FakeProc()
    _stop_remote_tcpdump(ex, proc, "tcpdump_arm64_android")
    joined = _joined(ex.commands)
    assert any("pkill -INT -f tcpdump_arm64_android" in c for c in joined)
    assert proc.terminated and proc.killed


def test_stop_remote_tcpdump_linux_no_pkill():
    ex = FakeExecutor(platform="linux")
    proc = FakeProc()
    _stop_remote_tcpdump(ex, proc, "tcpdump")
    assert not any("pkill" in " ".join(c) for c in ex.commands)
    assert proc.terminated


def test_stop_remote_tcpdump_handles_missing_proc():
    ex = FakeExecutor(platform="linux")
    _stop_remote_tcpdump(ex, None, "tcpdump")  # must not raise


# --- pure filter functions ---------------------------------------------------


def _conn(laddr, lport, raddr, rport, protocol="tcp", family=4):
    return Connection(protocol=protocol, family=family, laddr=laddr, lport=lport, raddr=raddr, rport=rport)


def test_connection_endpoints_includes_both_sides():
    conns = {_conn("10.0.0.5", 41000, "93.184.216.34", 443)}
    eps = connection_endpoints(conns)
    assert ("10.0.0.5", 41000) in eps
    assert ("93.184.216.34", 443) in eps


def test_connection_endpoints_skips_wildcard_and_zero_port():
    conns = {
        _conn("0.0.0.0", 8080, "1.2.3.4", 80),  # wildcard local addr -> skipped
        _conn("::", 9000, "2001:db8::1", 443, family=6),  # v6 wildcard -> skipped
        _conn("10.0.0.5", 0, "5.6.7.8", 0),  # zero ports -> both skipped
    }
    eps = connection_endpoints(conns)
    assert ("0.0.0.0", 8080) not in eps
    assert ("::", 9000) not in eps
    assert ("10.0.0.5", 0) not in eps
    assert ("5.6.7.8", 0) not in eps
    # the real remote endpoints survive
    assert ("1.2.3.4", 80) in eps
    assert ("2001:db8::1", 443) in eps


def test_packet_matches_true_on_src_or_dst():
    eps = {("93.184.216.34", 443)}
    assert packet_matches(eps, ("10.0.0.5", 41000), ("93.184.216.34", 443)) is True
    assert packet_matches(eps, ("93.184.216.34", 443), ("10.0.0.5", 41000)) is True


def test_packet_matches_false_when_neither_endpoint_known():
    eps = {("93.184.216.34", 443)}
    assert packet_matches(eps, ("10.0.0.5", 41000), ("8.8.8.8", 53)) is False


# --- tier properties ---------------------------------------------------------


def _mk_sockdiag(ex, output, uids=None):
    if uids is None:
        uids = {10123}
    return SockDiagTier(ex, TARGET, uids, output, tcpdump_cmd="/data/local/tmp/tcpdump_arm64_android")


def _mk_nflog(ex, output, uids=None):
    if uids is None:
        uids = {10123}
    return NflogTier(ex, TARGET, uids, output, tcpdump_cmd="/data/local/tmp/tcpdump_arm64_android")


def test_tier_properties():
    ex = FakeExecutor()
    assert _mk_sockdiag(ex, "/tmp/x.pcap").tier == Tier.SOCKDIAG
    assert _mk_nflog(ex, "/tmp/x.pcap").tier == Tier.NFLOG


# --- NflogTier ---------------------------------------------------------------


def test_nflog_start_teardown_first_then_setup_both_families(tmp_path):
    ex = FakeExecutor(platform="android")
    tier = _mk_nflog(ex, str(tmp_path / "out.pcap"))
    tier.start()
    joined = _joined(ex.commands)

    # teardown-first for BOTH families before any setup
    first_setup_idx = next(i for i, c in enumerate(joined) if "-N APPTAP_MARK" in c)
    teardown_before = [c for c in joined[:first_setup_idx]]
    assert any("iptables" in c and "-X APPTAP_MARK" in c for c in teardown_before)
    assert any("ip6tables" in c and "-X APPTAP_MARK" in c for c in teardown_before)

    # setup for BOTH families
    assert any(c.startswith("iptables") and "-N APPTAP_MARK" in c for c in joined)
    assert any(c.startswith("ip6tables") and "-N APPTAP_MARK" in c for c in joined)
    assert any("--uid-owner 10123" in c for c in joined)

    # nflog capture started in background, no BPF
    assert len(ex.background_calls) == 1
    cap = " ".join(ex.background_calls[0])
    assert "-i nflog:30" in cap
    assert "-w" in cap
    assert "not (" not in cap  # no BPF on the nflog capture
    assert tier._installed is True


def test_nflog_teardown_issues_build_teardown_both_families():
    ex = FakeExecutor(platform="android")
    tier = _mk_nflog(ex, "/tmp/out.pcap")
    tier._installed = True
    tier.teardown()
    joined = _joined(ex.commands)
    assert any(c.startswith("iptables") and "-X APPTAP_LOG" in c for c in joined)
    assert any(c.startswith("ip6tables") and "-X APPTAP_LOG" in c for c in joined)
    assert tier._installed is False


def test_nflog_teardown_idempotent_when_not_installed():
    ex = FakeExecutor(platform="android")
    tier = _mk_nflog(ex, "/tmp/out.pcap")
    # never started; teardown must be safe and never raise
    tier.teardown()
    tier.teardown()
    assert tier._installed is False


def test_nflog_teardown_never_raises_on_executor_error():
    class Boom(FakeExecutor):
        def shell(self, *args, background=False, timeout=None):
            raise RuntimeError("device gone")

    tier = _mk_nflog(Boom(platform="android"), "/tmp/out.pcap")
    tier._installed = True
    tier.teardown()  # must swallow the error
    assert tier._installed is False


def test_nflog_stop_pulls_and_warns_on_empty(tmp_path):
    out = tmp_path / "out.pcap"
    ex = FakeExecutor(platform="android")
    tier = _mk_nflog(ex, str(out))
    tier.start()
    result = tier.stop()

    # pulled the device pcap to host output
    assert ex.pulled and ex.pulled[-1][1] == str(out)
    # stopped on-device tcpdump
    assert any("pkill -INT -f tcpdump_arm64_android" in " ".join(c) for c in ex.commands)
    # output never created by fake pull -> empty -> liveness warning
    assert any("no packets" in w for w in result.warnings)
    assert result.tier == Tier.NFLOG
    assert result.linktype == 239
    assert result.connections == ()


# --- SockDiagTier ------------------------------------------------------------


def test_sockdiag_start_runs_interface_capture_with_bpf(tmp_path):
    ex = FakeExecutor(platform="android")
    tier = _mk_sockdiag(ex, str(tmp_path / "out.pcap"))
    try:
        tier.start()
        assert len(ex.background_calls) == 1
        cap = " ".join(ex.background_calls[0])
        assert "-i any" in cap
        assert "-U" in cap
        assert _infra_bpf() in cap
    finally:
        tier._stop_event.set()
        if tier._thread:
            tier._thread.join(timeout=2)


def test_sockdiag_snapshot_thread_populates_conns(tmp_path, monkeypatch):
    ex = FakeExecutor(platform="android")
    tier = _mk_sockdiag(ex, str(tmp_path / "out.pcap"))

    want = {_conn("10.0.0.5", 41000, "93.184.216.34", 443)}

    def fake_conns(executor, uids):
        assert uids == {10123}
        return want

    monkeypatch.setattr("apptap.tiers.sockdiag.connections_for_uids", fake_conns)

    tier.start()
    # give the daemon thread a moment to run at least one iteration
    deadline = time.time() + 3
    while not tier._conns and time.time() < deadline:
        time.sleep(0.05)
    tier._stop_snapshot_thread()

    assert tier._conns == want
    # thread cleanly joined
    assert tier._thread is None


def test_sockdiag_snapshot_thread_survives_transient_errors(tmp_path, monkeypatch):
    ex = FakeExecutor(platform="android")
    tier = _mk_sockdiag(ex, str(tmp_path / "out.pcap"))

    def boom(executor, uids):
        raise RuntimeError("transient /proc read error")

    monkeypatch.setattr("apptap.tiers.sockdiag.connections_for_uids", boom)
    tier.start()
    time.sleep(0.2)
    alive = tier._thread.is_alive()
    tier._stop_snapshot_thread()
    assert alive is True  # error did not kill the thread


def test_sockdiag_stop_calls_helper_and_pull(tmp_path, monkeypatch):
    ex = FakeExecutor(platform="android")
    out = tmp_path / "out.pcap"
    tier = _mk_sockdiag(ex, str(out))

    monkeypatch.setattr("apptap.tiers.sockdiag.connections_for_uids", lambda e, u: set())
    # avoid the scapy path here; assert the stop plumbing only
    monkeypatch.setattr(SockDiagTier, "_filter_pcap", lambda self: None)

    tier.start()
    result = tier.stop()

    # device temp pcap pulled to the host temp pcap
    assert ex.pulled and ex.pulled[-1] == (
        tier._remote_pcap,
        tier._host_tmp_pcap(str(out)),
    )
    # on-device tcpdump stopped via the shared helper
    assert any("pkill -INT -f tcpdump_arm64_android" in " ".join(c) for c in ex.commands)
    assert result.tier == Tier.SOCKDIAG
    assert result.uids == frozenset({10123})


def test_sockdiag_filter_pcap_keeps_only_app_packets(tmp_path):
    """Exercise the real scapy filtering path with a tiny on-disk pcap."""
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.utils import PcapReader, wrpcap

    app_pkt = IP(src="10.0.0.5", dst="93.184.216.34") / TCP(sport=41000, dport=443)
    app_reply = IP(src="93.184.216.34", dst="10.0.0.5") / TCP(sport=443, dport=41000)
    other_pkt = IP(src="10.0.0.9", dst="8.8.8.8") / UDP(sport=5000, dport=53)

    out = tmp_path / "out.pcap"
    ex = FakeExecutor(platform="linux")  # linux: temp pcap IS host-side
    tier = SockDiagTier(
        ex,
        TARGET,
        {10123},
        str(out),
        tcpdump_cmd="tcpdump",
    )
    # write a raw temp pcap where the tier expects it
    wrpcap(tier._tmp_pcap, [app_pkt, other_pkt, app_reply])
    tier._conns = {_conn("10.0.0.5", 41000, "93.184.216.34", 443)}

    tier._filter_pcap()

    kept = list(PcapReader(str(out)))
    assert len(kept) == 2  # app_pkt + app_reply, NOT other_pkt
    for pkt in kept:
        assert pkt.haslayer(TCP)


def test_sockdiag_stop_warns_when_pcap_unreadable(tmp_path, monkeypatch):
    ex = FakeExecutor(platform="linux")
    out = tmp_path / "out.pcap"
    tier = SockDiagTier(ex, TARGET, {10123}, str(out), tcpdump_cmd="tcpdump")
    monkeypatch.setattr("apptap.tiers.sockdiag.connections_for_uids", lambda e, u: set())

    def boom(self):
        raise OSError("no such pcap")

    monkeypatch.setattr(SockDiagTier, "_filter_pcap", boom)
    tier.start()
    result = tier.stop()
    assert result.pcap_path is None
    assert any("could not read" in w for w in result.warnings)
