"""Runtime capability probing and capture-tier selection.

AppTap supports two capture tiers and must decide between them on the live
target *before* it starts capturing:

* **Tier 2 (NFLOG pre-filter)** scopes the capture in-kernel using
  ``-m owner`` + ``CONNMARK`` + the ``NFLOG`` target. It is only usable when the
  kernel can *deliver* NFLOG packets to userspace — the ``nfnetlink_log``
  delivery module. Stock Android 12-14 GKI loads the NFLOG *target* but ships
  the delivery module disabled, so "the rule installs" is NOT sufficient; the
  decisive gate is the presence of :data:`NFNETLINK_LOG_PROC`.
* **Tier 1 (socket-table filter)** captures the interface and filters by the
  app's UID via the socket table. It is the robust default and works everywhere.

This module performs the probe (running throwaway netfilter rules through an
:class:`~apptap.executors.base.Executor` and checking the proc file) and turns
the resulting :class:`Capabilities` into a concrete :class:`~apptap.targets.Tier`
plus human-readable warnings.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass

from .constants import DEFAULT_NFLOG_GROUP, NFNETLINK_LOG_PROC
from .netfilter import build_probe, parse_iptables_backend, probe_feature_present
from .targets import Tier


@dataclass
class Capabilities:
    """What the live target can actually do for Tier-2 capture.

    Each boolean reflects a feature confirmed against the running kernel; see
    :func:`probe`. :attr:`nflog_usable` folds them into the single yes/no Tier-2
    decision.
    """

    owner: bool
    connmark: bool
    nflog_target: bool
    nfnetlink_log: bool
    ip6tables: bool
    backend: str
    sdk: int | None
    is_rooted: bool

    @property
    def nflog_usable(self) -> bool:
        """True only when every prerequisite for Tier-2 NFLOG capture holds.

        Requires the owner match, the CONNMARK target, the NFLOG target, the
        ``nfnetlink_log`` delivery module, *and* root (the rules need it).
        """
        return self.owner and self.connmark and self.nflog_target and self.nfnetlink_log and self.is_rooted


def _nfnetlink_log_present(executor) -> bool:
    """Check whether the ``nfnetlink_log`` delivery module is live on the target.

    The proc file exists only when the module is loaded and active, so either an
    ``ls`` that succeeds or a ``cat`` that returns rc 0 confirms it.
    """
    if executor.shell("ls", NFNETLINK_LOG_PROC).ok:
        return True
    return executor.shell("cat", NFNETLINK_LOG_PROC).returncode == 0


def probe(executor, group: int = DEFAULT_NFLOG_GROUP) -> Capabilities:
    """Probe the live target and return its Tier-2 :class:`Capabilities`.

    Runs the throwaway ``APPTAP_PROBE`` rules one at a time, mapping each rule to
    the feature it tests, then always tears the probe chain down (errors
    ignored). Also checks the ``nfnetlink_log`` delivery module, ip6tables, the
    iptables backend, the Android SDK level, and root.

    :param executor: the :class:`~apptap.executors.base.Executor` to run on.
    :param group: NFLOG group used by the NFLOG probe rule.
    :returns: the assembled :class:`Capabilities`.
    """
    probe_cmds = build_probe(group=group)
    owner = connmark = nflog_target = False
    try:
        # setup[0] is the chain-create (-N); the feature rules follow in order:
        # [1] owner match, [2] CONNMARK target, [3] NFLOG target.
        setup = probe_cmds["setup"]
        executor.shell(*setup[0])  # create probe chain (ignore result)

        res = executor.shell(*setup[1])
        owner = probe_feature_present(res.stderr, res.returncode)

        res = executor.shell(*setup[2])
        connmark = probe_feature_present(res.stderr, res.returncode)

        res = executor.shell(*setup[3])
        nflog_target = probe_feature_present(res.stderr, res.returncode)
    finally:
        # Always remove the probe chain, whatever happened above.
        for argv in probe_cmds["teardown"]:
            with contextlib.suppress(Exception):  # teardown must never raise
                executor.shell(*argv)

    nfnetlink_log = _nfnetlink_log_present(executor)
    ip6tables = executor.shell("ip6tables", "--version").ok
    backend = parse_iptables_backend(executor.shell("iptables", "--version").stdout)
    sdk = get_android_sdk(executor) if executor.platform == "android" else None

    return Capabilities(
        owner=owner,
        connmark=connmark,
        nflog_target=nflog_target,
        nfnetlink_log=nfnetlink_log,
        ip6tables=ip6tables,
        backend=backend,
        sdk=sdk,
        is_rooted=executor.is_rooted,
    )


def _missing_reason(caps: Capabilities) -> str:
    """Return a precise reason for why Tier-2 NFLOG is unusable.

    Names the first missing prerequisite, in the order they gate capture.
    """
    if not caps.is_rooted:
        return "root is required but not available"
    if not caps.owner:
        return "the iptables 'owner' match is unavailable"
    if not caps.connmark:
        return "the CONNMARK target is unavailable"
    if not caps.nflog_target:
        return "the NFLOG target is unavailable"
    if not caps.nfnetlink_log:
        return "the nfnetlink_log delivery module is disabled"
    return "an unknown prerequisite is missing"


def select_tier(caps: Capabilities, requested: Tier) -> tuple[Tier, list[str]]:
    """Resolve the requested tier against actual capabilities.

    Never returns :attr:`~apptap.targets.Tier.WHOLE_DEVICE` — that last-resort
    fallback is decided later, only if UID resolution fails.

    :param caps: probed target capabilities.
    :param requested: the tier the user asked for (``AUTO``/``NFLOG``/``SOCKDIAG``).
    :returns: ``(chosen_tier, warnings)`` where warnings is a list of
        human-readable strings (empty when there is nothing to report).
    """
    if requested == Tier.SOCKDIAG:
        return Tier.SOCKDIAG, []

    if requested == Tier.NFLOG:
        if caps.nflog_usable:
            return Tier.NFLOG, []
        reason = _missing_reason(caps)
        return Tier.SOCKDIAG, [f"NFLOG requested but unavailable ({reason}); using Tier 1 (socket-table)"]

    # Tier.AUTO: prefer NFLOG, fall back to the robust socket-table tier.
    if caps.nflog_usable:
        return Tier.NFLOG, []

    warnings: list[str] = []
    if caps.is_rooted and caps.owner and caps.connmark and caps.nflog_target and not caps.nfnetlink_log:
        # The common stock-GKI case: rules load but delivery is disabled.
        warnings.append(
            "in-kernel NFLOG pre-filter (Tier 2) is unavailable "
            "(nfnetlink_log delivery module is disabled); "
            "using Tier 1 (socket-table), which is still app-precise"
        )
    return Tier.SOCKDIAG, warnings


def get_android_sdk(executor) -> int | None:
    """Return ``ro.build.version.sdk`` as an int, or None on failure."""
    res = executor.shell("getprop", "ro.build.version.sdk")
    if not res.ok:
        return None
    try:
        return int(res.stdout.strip())
    except (ValueError, AttributeError):
        return None


def get_android_release(executor) -> str | None:
    """Return ``ro.build.version.release`` (e.g. ``"14"``), or None on failure."""
    res = executor.shell("getprop", "ro.build.version.release")
    if not res.ok:
        return None
    release = res.stdout.strip()
    return release or None


def android_version_note(sdk: int | None) -> str | None:
    """Advise about Tier-2 availability on newer Android, or None.

    The NFLOG delivery limitation is on *newer* Android (API 31+, stock GKI),
    not old ones, so the note is only emitted for ``sdk >= 31``.
    """
    if sdk is not None and sdk >= 31:
        return (
            f"Android API {sdk}: in-kernel NFLOG pre-filter (Tier 2) is likely "
            "unavailable (stock GKI ships nfnetlink_log disabled); AppTap will "
            "use the socket-table UID filter (Tier 1), which is still "
            "app-precise."
        )
    return None
