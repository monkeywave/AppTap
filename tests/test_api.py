"""Tests for the capture orchestrator (api.py) and the CLI (cli.py).

The heavy pieces (capability probe, UID resolution, tcpdump install, the tiers
themselves) are stubbed so these tests exercise orchestration logic without a
device or a real capture.
"""

from __future__ import annotations

import pytest

from apptap import api, cli
from apptap.executors.base import CmdResult
from apptap.result import CaptureResult
from apptap.targets import Breadth, Target, Tier


class FakeExecutor:
    def __init__(self, platform="android", is_rooted=True):
        self._platform = platform
        self._rooted = is_rooted

    @property
    def platform(self):
        return self._platform

    @property
    def is_rooted(self):
        return self._rooted

    def shell(self, *args, background=False, timeout=None):
        return CmdResult(0, "", "")

    def run(self, *args, timeout=None):
        return CmdResult(0, "", "")

    def push_file(self, local, remote):
        return CmdResult(0)

    def pull_file(self, remote, local):
        return CmdResult(0)


class FakeTier:
    """Records lifecycle calls and returns a canned result of its declared tier."""

    instances = []

    def __init__(self, executor, target, uids, output, *, tcpdump_cmd, nflog_group, device_tmp=None):
        self.executor = executor
        self.target = target
        self.uids = set(uids)
        self.output = output
        self.tcpdump_cmd = tcpdump_cmd
        self.nflog_group = nflog_group
        self.started = self.stopped = self.tore_down = False
        self._tier = Tier.SOCKDIAG
        FakeTier.instances.append(self)

    def start(self):
        self.started = True

    def stop(self):
        self.stopped = True
        return CaptureResult(
            tier=self._tier,
            uids=frozenset(self.uids),
            connections=(),
            pcap_path=self.output,
            linktype=None,
            warnings=[],
        )

    def teardown(self):
        self.tore_down = True


class FakeNflogTier(FakeTier):
    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self._tier = Tier.NFLOG


class FakeProvider:
    def __init__(self, executor, override_path=None):
        pass

    def resolve(self):
        return "tcpdump"


@pytest.fixture(autouse=True)
def _stub(monkeypatch):
    FakeTier.instances = []
    monkeypatch.setattr(api, "TcpdumpProvider", FakeProvider)
    monkeypatch.setattr(api, "SockDiagTier", FakeTier)
    monkeypatch.setattr(api, "NflogTier", FakeNflogTier)
    monkeypatch.setattr(api.uid_module, "resolve_uids", lambda ex, t, b: {10123})
    monkeypatch.setattr(api.capabilities, "probe", lambda ex, group=30: object())
    monkeypatch.setattr(api.capabilities, "get_android_sdk", lambda ex: 30)
    monkeypatch.setattr(api.capabilities, "android_version_note", lambda sdk: None)
    monkeypatch.setattr(api.capabilities, "select_tier", lambda caps, req: (Tier.NFLOG, []))


def test_session_auto_picks_nflog(tmp_path):
    out = str(tmp_path / "app.pcap")
    with api.CaptureSession(Target(package="com.x"), FakeExecutor(), out) as cap:
        cap.start()
        cap.stop()
    assert cap.result.tier == Tier.NFLOG
    assert len(FakeTier.instances) == 1
    impl = FakeTier.instances[0]
    assert impl.started and impl.stopped and impl.tore_down
    assert impl.uids == {10123}


def test_capture_oneshot_with_duration(tmp_path, monkeypatch):
    monkeypatch.setattr(api.time, "sleep", lambda s: None)
    out = str(tmp_path / "app.pcap")
    result = api.capture(Target(package="com.x"), FakeExecutor(), out, duration=0.01)
    assert result.pcap_path == out
    assert result.tier == Tier.NFLOG


def test_whole_device_fallback_when_no_uids(tmp_path, monkeypatch):
    monkeypatch.setattr(api.uid_module, "resolve_uids", lambda ex, t, b: set())
    out = str(tmp_path / "app.pcap")
    sess = api.CaptureSession(Target(package="com.x"), FakeExecutor(), out)
    sess.start()
    result = sess.stop()
    assert result.tier == Tier.WHOLE_DEVICE
    assert any("whole device" in w.lower() for w in result.warnings)
    # whole-device uses the SockDiag impl (not the nflog one)
    assert FakeTier.instances[0]._tier == Tier.SOCKDIAG


def test_forced_sockdiag(tmp_path, monkeypatch):
    monkeypatch.setattr(api.capabilities, "select_tier", lambda caps, req: (Tier.SOCKDIAG, []))
    out = str(tmp_path / "app.pcap")
    sess = api.CaptureSession(Target(package="com.x"), FakeExecutor(), out, tier=Tier.SOCKDIAG)
    sess.start()
    r = sess.stop()
    assert r.tier == Tier.SOCKDIAG


def test_version_note_surfaced_when_falling_back_to_sockdiag(tmp_path, monkeypatch):
    # The SDK note claims Tier 2 is unavailable and Tier 1 is used, so it must
    # only surface when the sockdiag fallback is actually chosen.
    monkeypatch.setattr(api.capabilities, "select_tier", lambda caps, req: (Tier.SOCKDIAG, []))
    monkeypatch.setattr(api.capabilities, "get_android_sdk", lambda ex: 34)
    monkeypatch.setattr(api.capabilities, "android_version_note", lambda sdk: "note!" if sdk >= 31 else None)
    out = str(tmp_path / "app.pcap")
    sess = api.CaptureSession(Target(package="com.x"), FakeExecutor(), out)
    sess.start()
    r = sess.stop()
    assert "note!" in r.warnings


def test_version_note_suppressed_when_nflog_chosen(tmp_path, monkeypatch):
    # When Tier 2 (NFLOG) is actually selected, the "Tier 2 unavailable" note
    # would contradict reality and must not be surfaced. (select_tier -> NFLOG
    # via the autouse stub.)
    monkeypatch.setattr(api.capabilities, "get_android_sdk", lambda ex: 34)
    monkeypatch.setattr(api.capabilities, "android_version_note", lambda sdk: "note!" if sdk >= 31 else None)
    out = str(tmp_path / "app.pcap")
    sess = api.CaptureSession(Target(package="com.x"), FakeExecutor(), out)
    sess.start()
    r = sess.stop()
    assert "note!" not in r.warnings


def test_cleanup_invokes_teardown(monkeypatch):
    calls = []
    monkeypatch.setattr("apptap.netfilter.build_teardown", lambda ipt="iptables": [["x", ipt]])
    ex = FakeExecutor()
    ex.shell = lambda *a, **k: calls.append(a) or CmdResult(0)
    api.cleanup(ex)
    assert calls  # teardown commands were issued for both families


# --- CLI -------------------------------------------------------------------


def test_cli_parses_pid_target():
    assert cli._build_target("1234") == Target(pid=1234)
    assert cli._build_target("com.example.app") == Target(package="com.example.app")


def test_cli_breadth_flags():
    p = cli.build_parser()
    assert cli._breadth_from_args(p.parse_args(["x", "-o", "a.pcap"])) == Breadth.APP_ISOLATED_DNS
    assert cli._breadth_from_args(p.parse_args(["x", "-o", "a.pcap", "--strict"])) == Breadth.APP_ONLY
    assert cli._breadth_from_args(p.parse_args(["x", "-o", "a.pcap", "--no-dns"])) == Breadth.APP_ISOLATED


def test_cli_requires_target_and_output(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--local"])  # no target


def test_cli_cleanup_path(monkeypatch):
    called = {}
    monkeypatch.setattr("apptap.api.cleanup", lambda ex: called.setdefault("ran", True))
    rc = cli.main(["--local", "--cleanup"])
    assert rc == 0 and called.get("ran")
