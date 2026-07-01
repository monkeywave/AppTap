"""Unit tests for the Tier-2 netfilter rule builders.

Pure argv-construction and parser tests — no device, no root, no scapy.
"""

from __future__ import annotations

from apptap.netfilter import (
    build_probe,
    build_setup,
    build_teardown,
    parse_iptables_backend,
    probe_feature_present,
)

XMARK = "0x40000/0x40000"


def _joined(cmds):
    """Render argv lists as joined strings for easy substring membership tests."""
    return [" ".join(c) for c in cmds]


# --- build_setup -------------------------------------------------------------


def test_build_setup_creates_both_chains():
    cmds = build_setup([10123], 30)
    joined = _joined(cmds)
    assert any(c.endswith("-N APPTAP_MARK") for c in joined)
    assert any(c.endswith("-N APPTAP_LOG") for c in joined)


def test_build_setup_owner_rule_for_uid_with_connmark():
    cmds = build_setup([10123], 30)
    joined = _joined(cmds)
    owner = [c for c in joined if "-A APPTAP_MARK" in c and "--uid-owner 10123" in c]
    assert len(owner) == 1
    assert "-m owner" in owner[0]
    assert f"CONNMARK --set-xmark {XMARK}" in owner[0]


def test_build_setup_log_chain_restore_and_nflog():
    cmds = build_setup([10123], 30)
    joined = _joined(cmds)
    assert any("-A APPTAP_LOG" in c and "CONNMARK --restore-mark --mask 0x40000" in c for c in joined)
    nflog = [c for c in joined if "-A APPTAP_LOG" in c and "NFLOG" in c]
    assert len(nflog) == 1
    assert "--nflog-group 30" in nflog[0]
    assert "--nflog-size 0" in nflog[0]
    assert "--nflog-threshold 1" in nflog[0]


def test_build_setup_three_jumps_in_right_chains():
    cmds = build_setup([10123], 30)
    joined = _joined(cmds)
    assert any(c.endswith("-I OUTPUT 1 -j APPTAP_MARK") for c in joined)
    assert any(c.endswith("-I OUTPUT 2 -j APPTAP_LOG") for c in joined)
    assert any(c.endswith("-I PREROUTING 1 -j APPTAP_LOG") for c in joined)


def test_build_setup_uses_lock_wait_and_mangle_table():
    cmds = build_setup([10123], 30)
    for c in cmds:
        assert c[0] == "iptables"
        assert "-w" in c
        assert c[c.index("-t") + 1] == "mangle"


def test_build_setup_owner_match_only_in_mark_chain():
    cmds = build_setup([10123], 30)
    joined = _joined(cmds)
    for c in joined:
        if "-m owner" in c:
            assert "-A APPTAP_MARK" in c
            assert "APPTAP_LOG" not in c


def test_build_setup_multiple_uids_one_rule_each_single_log_pair():
    cmds = build_setup([10123, 90001, 1051], 30)
    joined = _joined(cmds)
    owner_rules = [c for c in joined if "-m owner" in c]
    assert len(owner_rules) == 3
    for uid in ("10123", "90001", "1051"):
        assert any(f"--uid-owner {uid}" in c for c in owner_rules)
    # Still a single LOG pair (restore-mark + NFLOG), regardless of uid count.
    assert len([c for c in joined if "-A APPTAP_LOG" in c and "restore-mark" in c]) == 1
    assert len([c for c in joined if "-A APPTAP_LOG" in c and "NFLOG" in c]) == 1


def test_build_setup_ip6tables_binary():
    cmds = build_setup([10123], 30, ipt="ip6tables")
    for c in cmds:
        assert c[0] == "ip6tables"


# --- build_teardown ----------------------------------------------------------


def test_build_teardown_flush_and_delete_both_chains():
    cmds = build_teardown()
    joined = _joined(cmds)
    for chain in ("APPTAP_MARK", "APPTAP_LOG"):
        assert any(c.endswith(f"-F {chain}") for c in joined)
        assert any(c.endswith(f"-X {chain}") for c in joined)


def test_build_teardown_deletes_jumps():
    joined = _joined(build_teardown())
    assert any("-D PREROUTING -j APPTAP_LOG" in c for c in joined)
    assert any("-D OUTPUT -j APPTAP_LOG" in c for c in joined)
    assert any("-D OUTPUT -j APPTAP_MARK" in c for c in joined)


def test_build_teardown_delete_after_flush_per_chain():
    joined = _joined(build_teardown())
    for chain in ("APPTAP_MARK", "APPTAP_LOG"):
        f_idx = next(i for i, c in enumerate(joined) if c.endswith(f"-F {chain}"))
        x_idx = next(i for i, c in enumerate(joined) if c.endswith(f"-X {chain}"))
        assert f_idx < x_idx


def test_build_teardown_ip6tables_binary():
    for c in build_teardown(ipt="ip6tables"):
        assert c[0] == "ip6tables"


# --- build_probe -------------------------------------------------------------


def test_build_probe_setup_and_teardown():
    probe = build_probe(group=1)
    setup = _joined(probe["setup"])
    teardown = _joined(probe["teardown"])
    assert any(c.endswith("-N APPTAP_PROBE") for c in setup)
    assert any("-m owner --uid-owner 10000 -j RETURN" in c for c in setup)
    assert any("CONNMARK --set-xmark" in c for c in setup)
    assert any("NFLOG --nflog-group 1" in c for c in setup)
    assert any(c.endswith("-F APPTAP_PROBE") for c in teardown)
    assert any(c.endswith("-X APPTAP_PROBE") for c in teardown)


# --- parse_iptables_backend --------------------------------------------------


def test_parse_iptables_backend_nf_tables():
    assert parse_iptables_backend("iptables v1.8.10 (nf_tables)") == "nf_tables"


def test_parse_iptables_backend_legacy():
    assert parse_iptables_backend("iptables v1.8.7 (legacy)") == "legacy"


def test_parse_iptables_backend_garbage():
    assert parse_iptables_backend("totally unrelated text") == "unknown"


# --- probe_feature_present ---------------------------------------------------


def test_probe_feature_present_rc_zero():
    assert probe_feature_present("", 0) is True


def test_probe_feature_present_absent_messages():
    for msg in (
        "iptables: No chain/target/match by that name.",
        "Unknown arg `--uid-owner'",
        "NFLOG: not supported",
        "Couldn't load target `CONNMARK'",
    ):
        assert probe_feature_present(msg, 1) is False


def test_probe_feature_present_unexplained_nonzero_is_absent():
    assert probe_feature_present("resource temporarily unavailable", 4) is False
