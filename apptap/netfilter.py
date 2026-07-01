"""Tier-2 netfilter (iptables/ip6tables) rule builders.

AppTap's Tier 2 scopes a capture to an app's UID(s) *entirely in-kernel*: it
stamps a conntrack-mark on the app's connections and then logs both directions
of every marked connection to NFLOG, where ``tcpdump -i nflog:<group>`` reads
them. No per-packet userspace filtering is needed.

WHY THE OWNER MATCH AND THE CONNMARK ARE SPLIT INTO TWO CHAINS
--------------------------------------------------------------
``-m owner --uid-owner`` only works on locally *generated* packets — i.e. in
the OUTPUT path. Reply traffic arriving from the network (PREROUTING) has no
owning socket the kernel can attribute, so an owner match there matches
nothing. We therefore cannot log purely off ``-m owner`` and still capture the
inbound half of a connection.

The fix is to decouple *identification* from *logging*:

* The ``APPTAP_MARK`` chain runs only on OUTPUT. It uses ``-m owner`` to spot
  the target app's outbound packets and stamps a **conntrack** mark (CONNMARK)
  on the whole connection. CONNMARK lives in the conntrack entry, so it sticks
  to *both* directions of the flow for its entire lifetime.
* The ``APPTAP_LOG`` chain runs on both OUTPUT and PREROUTING. It restores the
  connection's CONNMARK into the packet's ``skb->mark`` and logs anything
  carrying our mark bit. Because the mark is a property of the connection (not
  of who generated a given packet), the inbound reply packets — which have no
  owning UID — are logged too.

The CONNMARK bit is chosen high and applied with an explicit mask so it never
collides with Android netd's packet fwmark routing, and lives in the conntrack
namespace where Android's eBPF traffic controller never touches it.

This module is PURE argv construction plus a couple of small parsers: every
builder returns a ``list[list[str]]`` (an ordered list of argv lists) so the
caller can run each one through an Executor. Nothing here executes a command or
touches a device, which is exactly what makes it fully unit-testable.
"""

from __future__ import annotations

from typing import Dict, List

from .constants import (
    CHAIN_LOG,
    CHAIN_MARK,
    CHAIN_PROBE,
    CONNMARK_BIT,
    CONNMARK_MASK,
    NETFILTER_TABLE,
)

# iptables/ip6tables share an identical argv grammar, so every builder takes the
# binary name as a parameter and the same code emits both the v4 and v6 rule
# sets.

#: ``set-xmark`` / ``--mark`` argument expressing "our bit, masked to our bit".
_XMARK = f"{hex(CONNMARK_BIT)}/{hex(CONNMARK_MASK)}"

#: ``--mask`` argument for CONNMARK restore (just the bit, no value/mask pair).
_MASK = hex(CONNMARK_MASK)


def _base(ipt: str) -> List[str]:
    """Common prefix for every rule: binary, lock-wait, and the mangle table.

    ``-w`` makes iptables block on the xtables lock instead of failing when
    another process (e.g. Android netd) holds it.
    """
    return [ipt, "-w", "-t", NETFILTER_TABLE]


def build_setup(
    uids: List[int], group: int, ipt: str = "iptables"
) -> List[List[str]]:
    """Build the argv lists that install the Tier-2 marking + logging rules.

    The owner match appears ONLY in the MARK chain (OUTPUT-only); the LOG chain
    logs purely off the restored connmark so it catches both directions. See the
    module docstring for the full rationale.

    :param uids: app UID(s) whose connections should be marked and logged.
    :param group: NFLOG group the marked traffic is logged to.
    :param ipt: ``"iptables"`` or ``"ip6tables"``.
    :returns: ordered list of argv lists to run in sequence.
    """
    cmds: List[List[str]] = []

    # Dedicated chains so teardown is a clean flush+delete of exactly what we
    # created, never editing the device's own chains.
    cmds.append(_base(ipt) + ["-N", CHAIN_MARK])
    cmds.append(_base(ipt) + ["-N", CHAIN_LOG])

    # MARK chain: identify the app's outbound packets by owning UID and stamp the
    # connection's conntrack mark. One rule per UID (apps can span several UIDs:
    # base appId, isolated processes, the DNS resolver, ...).
    for uid in uids:
        cmds.append(
            _base(ipt)
            + [
                "-A",
                CHAIN_MARK,
                "-m",
                "owner",
                "--uid-owner",
                str(uid),
                "-j",
                "CONNMARK",
                "--set-xmark",
                _XMARK,
            ]
        )

    # LOG chain: restore the connection's connmark into skb->mark, then log
    # anything carrying our bit. No owner match here — this is what lets the
    # ownerless inbound reply packets be logged.
    cmds.append(
        _base(ipt) + ["-A", CHAIN_LOG, "-j", "CONNMARK", "--restore-mark", "--mask", _MASK]
    )
    cmds.append(
        _base(ipt)
        + [
            "-A",
            CHAIN_LOG,
            "-m",
            "mark",
            "--mark",
            _XMARK,
            "-j",
            "NFLOG",
            "--nflog-group",
            str(group),
            "--nflog-size",
            "0",
            "--nflog-threshold",
            "1",
        ]
    )

    # Jumps: MARK first on OUTPUT (so the mark exists before LOG restores it),
    # then LOG on OUTPUT, and LOG on PREROUTING for the inbound half.
    cmds.append(_base(ipt) + ["-I", "OUTPUT", "1", "-j", CHAIN_MARK])
    cmds.append(_base(ipt) + ["-I", "OUTPUT", "2", "-j", CHAIN_LOG])
    cmds.append(_base(ipt) + ["-I", "PREROUTING", "1", "-j", CHAIN_LOG])

    return cmds


def build_teardown(ipt: str = "iptables") -> List[List[str]]:
    """Build the argv lists that remove exactly what :func:`build_setup` created.

    Designed so repeated or partial application is harmless: the caller runs
    every command and ignores non-zero exit codes (rules/chains may not exist).

    Order matters: delete the jumps first (a chain can't be deleted while it is
    still referenced), then flush (``-F``) each chain, then delete (``-X``) it.

    The OUTPUT ``-D`` jumps are emitted twice each: a re-run of ``build_setup``
    would leave duplicate OUTPUT jumps, and each ``-D`` removes only one match,
    so two passes clean both up. Extra ``-D`` passes simply fail harmlessly once
    no matching rule remains (the caller ignores those failures).

    :param ipt: ``"iptables"`` or ``"ip6tables"``.
    :returns: ordered list of argv lists to run in sequence.
    """
    cmds: List[List[str]] = []

    # Delete the jumps before deleting their target chains. Emit the OUTPUT
    # deletes twice to clear duplicates left by a previous re-run.
    cmds.append(_base(ipt) + ["-D", "PREROUTING", "-j", CHAIN_LOG])
    cmds.append(_base(ipt) + ["-D", "OUTPUT", "-j", CHAIN_LOG])
    cmds.append(_base(ipt) + ["-D", "OUTPUT", "-j", CHAIN_MARK])
    cmds.append(_base(ipt) + ["-D", "PREROUTING", "-j", CHAIN_LOG])
    cmds.append(_base(ipt) + ["-D", "OUTPUT", "-j", CHAIN_LOG])
    cmds.append(_base(ipt) + ["-D", "OUTPUT", "-j", CHAIN_MARK])

    # Flush then delete each chain (-X must come after -F for that chain).
    for chain in (CHAIN_MARK, CHAIN_LOG):
        cmds.append(_base(ipt) + ["-F", chain])
    for chain in (CHAIN_MARK, CHAIN_LOG):
        cmds.append(_base(ipt) + ["-X", chain])

    return cmds


def build_probe(group: int = 1, ipt: str = "iptables") -> Dict[str, List[List[str]]]:
    """Build argv lists that probe whether the needed netfilter features exist.

    Each ``"setup"`` command appends one rule per probed feature into a throwaway
    ``APPTAP_PROBE`` chain. The caller runs each and treats a non-zero exit / a
    "No chain/target/match by that name" stderr as "feature absent". CONNMARK is
    probed as its own rule because the owner match and the CONNMARK target are
    independent kernel modules — either can be missing on stock kernels.

    :param group: NFLOG group used for the NFLOG probe rule.
    :param ipt: ``"iptables"`` or ``"ip6tables"``.
    :returns: dict with ``"setup"`` and ``"teardown"`` argv-list lists.
    """
    setup: List[List[str]] = []
    setup.append(_base(ipt) + ["-N", CHAIN_PROBE])
    # owner match available?
    setup.append(
        _base(ipt)
        + ["-A", CHAIN_PROBE, "-m", "owner", "--uid-owner", "10000", "-j", "RETURN"]
    )
    # CONNMARK target available?
    setup.append(
        _base(ipt)
        + ["-A", CHAIN_PROBE, "-j", "CONNMARK", "--set-xmark", _XMARK, "-j", "RETURN"]
    )
    # NFLOG target available?
    setup.append(
        _base(ipt) + ["-A", CHAIN_PROBE, "-j", "NFLOG", "--nflog-group", str(group)]
    )

    teardown: List[List[str]] = []
    teardown.append(_base(ipt) + ["-F", CHAIN_PROBE])
    teardown.append(_base(ipt) + ["-X", CHAIN_PROBE])

    return {"setup": setup, "teardown": teardown}


def parse_iptables_backend(version_output: str) -> str:
    """Parse the backend from ``iptables --version`` output.

    e.g. ``iptables v1.8.10 (nf_tables)`` or ``... (legacy)``.

    :returns: ``"nf_tables"``, ``"legacy"``, or ``"unknown"``.
    """
    text = version_output.lower()
    if "nf_tables" in text:
        return "nf_tables"
    if "legacy" in text:
        return "legacy"
    return "unknown"


#: stderr substrings that mean the kernel/iptables lacks a probed feature.
_ABSENT_INDICATORS = (
    "No chain/target/match by that name",
    "Unknown arg",
    "not supported",
    "Couldn't load",
)


def probe_feature_present(cmd_result_stderr: str, returncode: int) -> bool:
    """Decide whether a probed netfilter feature is present.

    :param cmd_result_stderr: stderr captured from running the probe rule.
    :param returncode: the probe command's exit code.
    :returns: ``True`` if the feature is present, ``False`` if absent.
    """
    if returncode == 0:
        return True
    for indicator in _ABSENT_INDICATORS:
        if indicator.lower() in cmd_result_stderr.lower():
            return False
    # Non-zero for some other reason (e.g. lock contention): treat as absent to
    # be safe — the feature could not be confirmed.
    return False
