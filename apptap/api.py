"""High-level capture orchestration.

``capture()`` is the one-shot entry point; ``CaptureSession`` is the lifecycle
form for tools that drive the run themselves (start capture, run/instrument the
app, stop). Both:

1. resolve the target app's UID(s) (UID-scoping is the whole point),
2. probe the kernel and pick the capture tier (NFLOG vs SOCK_DIAG),
3. run the chosen tier and return an app-scoped :class:`CaptureResult`.

If the UID cannot be resolved at all, capture still proceeds whole-device
(unfiltered) so the user gets *something*, flagged via ``result.tier ==
Tier.WHOLE_DEVICE`` and a warning.
"""

from __future__ import annotations

import contextlib
import logging
import time

from apptap import capabilities
from apptap import uid as uid_module
from apptap.constants import DEFAULT_NFLOG_GROUP
from apptap.executors.base import Executor
from apptap.result import CaptureResult
from apptap.targets import Breadth, Target, Tier
from apptap.tcpdump import TcpdumpProvider
from apptap.tiers.base import CaptureTier
from apptap.tiers.nflog import NflogTier
from apptap.tiers.sockdiag import SockDiagTier

logger = logging.getLogger("apptap")


class CaptureSession:
    """Drive an app-scoped capture across an explicit start/stop lifecycle.

    Usage::

        with CaptureSession(target, executor, "app.pcap") as cap:
            cap.start()
            ...            # run / instrument the app
            cap.stop()
        result = cap.result
    """

    def __init__(
        self,
        target: Target,
        executor: Executor,
        output: str,
        *,
        breadth: Breadth = Breadth.APP_ISOLATED_DNS,
        tier: Tier = Tier.AUTO,
        nflog_group: int = DEFAULT_NFLOG_GROUP,
        tcpdump_path: str | None = None,
    ) -> None:
        self.target = target
        self.executor = executor
        self.output = output
        self.breadth = breadth
        self.requested_tier = tier
        self.nflog_group = nflog_group
        self.tcpdump_path = tcpdump_path

        self.result: CaptureResult | None = None
        self._impl: CaptureTier | None = None
        self._warnings: list[str] = []
        self._uids: set = set()
        self._chosen: Tier | None = None
        self._whole_device = False
        self._started = False

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> CaptureSession:
        """Resolve UIDs, choose a tier, and begin capturing."""
        if self._started:
            raise RuntimeError("CaptureSession already started")
        ex = self.executor

        self._note_android_version(ex)
        self._uids = self._resolve_uids(ex)
        chosen = self._choose_tier(ex)
        tcpdump_cmd = TcpdumpProvider(ex, override_path=self.tcpdump_path).resolve()

        impl_cls = NflogTier if chosen == Tier.NFLOG else SockDiagTier
        self._chosen = chosen
        self._impl = impl_cls(
            ex,
            self.target,
            self._uids,
            self.output,
            tcpdump_cmd=tcpdump_cmd,
            nflog_group=self.nflog_group,
        )
        logger.info("AppTap capture: tier=%s uids=%s", chosen, sorted(self._uids) or "(whole device)")
        self._impl.start()
        self._started = True
        return self

    def stop(self) -> CaptureResult:
        """Stop capturing, finalize the pcap, tear down, and return the result."""
        if not self._started or self._impl is None:
            raise RuntimeError("CaptureSession not started")
        try:
            result = self._impl.stop()
        finally:
            self.teardown()
        if self._whole_device:
            result.tier = Tier.WHOLE_DEVICE
        result.warnings = list(self._warnings) + list(result.warnings or [])
        self.result = result
        self._started = False
        return result

    def teardown(self) -> None:
        """Idempotent cleanup of anything the tier installed. Never raises."""
        if self._impl is not None:
            try:
                self._impl.teardown()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("teardown error (ignored): %s", exc)

    def __enter__(self) -> CaptureSession:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._started:
            try:
                self.stop()
            except Exception:
                self.teardown()
        else:
            self.teardown()
        return False

    # --- internals -----------------------------------------------------------

    def _note_android_version(self, ex: Executor) -> None:
        if ex.platform != "android":
            return
        try:
            note = capabilities.android_version_note(capabilities.get_android_sdk(ex))
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("version note failed: %s", exc)
            return
        if note:
            self._warnings.append(note)

    def _resolve_uids(self, ex: Executor) -> set:
        try:
            return uid_module.resolve_uids(ex, self.target, self.breadth)
        except Exception as exc:
            logger.debug("UID resolution failed: %s", exc)
            return set()

    def _choose_tier(self, ex: Executor) -> Tier:
        try:
            caps = capabilities.probe(ex, group=self.nflog_group)
            chosen, warns = capabilities.select_tier(caps, self.requested_tier)
            self._warnings.extend(warns)
        except Exception as exc:
            logger.debug("capability probe failed (%s); defaulting to Tier 1", exc)
            chosen = Tier.SOCKDIAG
        if not self._uids:
            self._warnings.append("Could not resolve the app UID; capturing the whole device unfiltered.")
            self._whole_device = True
            chosen = Tier.SOCKDIAG  # SockDiagTier copies through unfiltered when uids is empty
        return chosen


def capture(
    target: Target,
    executor: Executor,
    output: str,
    *,
    breadth: Breadth = Breadth.APP_ISOLATED_DNS,
    tier: Tier = Tier.AUTO,
    nflog_group: int = DEFAULT_NFLOG_GROUP,
    duration: float | None = None,
    tcpdump_path: str | None = None,
) -> CaptureResult:
    """Capture an app's traffic in one call.

    Blocks for ``duration`` seconds, or until Ctrl-C when ``duration`` is None.
    """
    session = CaptureSession(
        target,
        executor,
        output,
        breadth=breadth,
        tier=tier,
        nflog_group=nflog_group,
        tcpdump_path=tcpdump_path,
    )
    session.start()
    try:
        _block(duration)
    finally:
        result = session.stop()
    return result


def cleanup(executor: Executor) -> None:
    """Remove any leftover AppTap netfilter rules (Tier 2) from a prior run."""
    from apptap import netfilter

    for ipt in ("iptables", "ip6tables"):
        for argv in netfilter.build_teardown(ipt):
            with contextlib.suppress(Exception):
                executor.shell(*argv)


def _block(duration: float | None) -> None:
    if duration is not None:
        time.sleep(duration)
        return
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
