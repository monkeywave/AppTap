"""Unit tests for capability probing and tier selection.

Uses a tiny fake :class:`~apptap.executors.base.Executor` that returns canned
:class:`CmdResult`s keyed by a substring of the command, records every command
it ran, and exposes ``platform``/``is_rooted`` attributes. No device, no root.
"""

from __future__ import annotations

from typing import Dict, List

from apptap.capabilities import (
    Capabilities,
    android_version_note,
    probe,
    select_tier,
)
from apptap.executors.base import CmdResult
from apptap.targets import Tier


class FakeExecutor:
    """Canned executor matching commands by substring.

    :param responses: ordered list of ``(substring, CmdResult)``; the first whose
        substring appears in the joined argv wins.
    :param default: result returned when nothing matches.
    """

    def __init__(self, responses, *, platform="android", is_rooted=True, default=None):
        self._responses = responses
        self._default = default if default is not None else CmdResult(1, "", "")
        self.platform = platform
        self.is_rooted = is_rooted
        self.commands: List[List[str]] = []

    def shell(self, *args, background=False, timeout=None):
        self.commands.append(list(args))
        joined = " ".join(args)
        for substring, result in self._responses:
            if substring in joined:
                return result
        return self._default

    @property
    def joined_commands(self) -> List[str]:
        return [" ".join(c) for c in self.commands]


def make_caps(**overrides) -> Capabilities:
    """An all-True Capabilities, overridable per field."""
    defaults: Dict[str, object] = dict(
        owner=True,
        connmark=True,
        nflog_target=True,
        nfnetlink_log=True,
        ip6tables=True,
        backend="nf_tables",
        sdk=34,
        is_rooted=True,
    )
    defaults.update(overrides)
    return Capabilities(**defaults)  # type: ignore[arg-type]


# --- Capabilities.nflog_usable ----------------------------------------------


def test_nflog_usable_true_when_all_four_and_rooted():
    assert make_caps().nflog_usable is True


def test_nflog_usable_false_if_any_prerequisite_missing():
    for field in ("owner", "connmark", "nflog_target", "nfnetlink_log", "is_rooted"):
        assert make_caps(**{field: False}).nflog_usable is False, field


# --- select_tier truth table -------------------------------------------------


def test_select_tier_auto_all_caps_picks_nflog():
    tier, warnings = select_tier(make_caps(), Tier.AUTO)
    assert tier is Tier.NFLOG
    assert warnings == []


def test_select_tier_auto_missing_nfnetlink_log_falls_back_with_warning():
    tier, warnings = select_tier(make_caps(nfnetlink_log=False), Tier.AUTO)
    assert tier is Tier.SOCKDIAG
    assert len(warnings) == 1
    assert "nfnetlink_log" in warnings[0]


def test_select_tier_nflog_forced_but_unusable_falls_back_with_warning():
    tier, warnings = select_tier(make_caps(nflog_target=False), Tier.NFLOG)
    assert tier is Tier.SOCKDIAG
    assert len(warnings) == 1
    assert "NFLOG target is unavailable" in warnings[0]
    assert "Tier 1" in warnings[0]


def test_select_tier_nflog_forced_reports_precise_reason():
    tier, warnings = select_tier(make_caps(is_rooted=False), Tier.NFLOG)
    assert tier is Tier.SOCKDIAG
    assert "root" in warnings[0]


def test_select_tier_sockdiag_forced_always_sockdiag():
    tier, warnings = select_tier(make_caps(), Tier.SOCKDIAG)
    assert tier is Tier.SOCKDIAG
    assert warnings == []


def test_select_tier_never_returns_whole_device():
    for requested in (Tier.AUTO, Tier.NFLOG, Tier.SOCKDIAG):
        tier, _ = select_tier(make_caps(owner=False), requested)
        assert tier is not Tier.WHOLE_DEVICE


# --- android_version_note ----------------------------------------------------


def test_android_version_note_none_for_sdk_30():
    assert android_version_note(30) is None


def test_android_version_note_message_for_sdk_31_and_34():
    for sdk in (31, 34):
        note = android_version_note(sdk)
        assert note is not None
        assert f"API {sdk}" in note
        assert "Tier 1" in note


def test_android_version_note_none_for_none():
    assert android_version_note(None) is None


# --- probe -------------------------------------------------------------------

OK = CmdResult(0, "", "")
ABSENT = CmdResult(1, "", "No chain/target/match by that name")


def _happy_responses():
    """All probe rules succeed; nfnetlink_log present; v6 + backend report."""
    return [
        ("ls /proc/net/netfilter/nfnetlink_log", OK),
        ("ip6tables --version", CmdResult(0, "ip6tables v1.8.10 (nf_tables)", "")),
        ("iptables --version", CmdResult(0, "iptables v1.8.10 (nf_tables)", "")),
        ("getprop ro.build.version.sdk", CmdResult(0, "34\n", "")),
        # any iptables -t mangle probe rule returns OK
        ("-t mangle", OK),
    ]


def test_probe_happy_path_all_true():
    ex = FakeExecutor(_happy_responses(), platform="android", is_rooted=True)
    caps = probe(ex)
    assert caps.owner and caps.connmark and caps.nflog_target
    assert caps.nfnetlink_log and caps.ip6tables
    assert caps.backend == "nf_tables"
    assert caps.sdk == 34
    assert caps.is_rooted is True
    assert caps.nflog_usable is True


def test_probe_issues_teardown_commands():
    ex = FakeExecutor(_happy_responses(), platform="android", is_rooted=True)
    probe(ex)
    joined = ex.joined_commands
    # The probe chain must always be flushed and deleted.
    assert any("-F APPTAP_PROBE" in c for c in joined)
    assert any("-X APPTAP_PROBE" in c for c in joined)


def test_probe_nflog_rule_error_and_missing_proc_makes_unusable():
    responses = [
        # NFLOG probe rule errors; the owner & CONNMARK rules still pass.
        ("-j NFLOG", ABSENT),
        # nfnetlink_log proc file is absent (both ls and cat fail).
        ("ls /proc/net/netfilter/nfnetlink_log", CmdResult(1, "", "No such file")),
        ("cat /proc/net/netfilter/nfnetlink_log", CmdResult(1, "", "No such file")),
        ("ip6tables --version", CmdResult(0, "", "")),
        ("iptables --version", CmdResult(0, "iptables v1.8.10 (legacy)", "")),
        ("getprop ro.build.version.sdk", CmdResult(0, "31\n", "")),
        ("-t mangle", OK),
    ]
    ex = FakeExecutor(responses, platform="android", is_rooted=True)
    caps = probe(ex)
    assert caps.owner is True
    assert caps.connmark is True
    assert caps.nflog_target is False
    assert caps.nfnetlink_log is False
    assert caps.nflog_usable is False
    assert caps.backend == "legacy"
    # teardown still ran
    assert any("-X APPTAP_PROBE" in c for c in ex.joined_commands)


def test_probe_linux_platform_has_no_sdk():
    responses = [
        ("ls /proc/net/netfilter/nfnetlink_log", OK),
        ("ip6tables --version", CmdResult(0, "", "")),
        ("iptables --version", CmdResult(0, "iptables v1.8.10 (legacy)", "")),
        ("-t mangle", OK),
    ]
    ex = FakeExecutor(responses, platform="linux", is_rooted=True)
    caps = probe(ex)
    assert caps.sdk is None
