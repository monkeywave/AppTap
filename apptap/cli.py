"""AppTap command-line interface.

Examples::

    apptap com.example.app --device <serial> -o app.pcap
    apptap 1234 --local -o app.pcap
    apptap com.example.app --device <serial> --tier sockdiag --strict -d 30
    apptap --probe   --device <serial>
    apptap --cleanup --device <serial>
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import List, Optional

from apptap.about import __version__
from apptap.constants import DEFAULT_NFLOG_GROUP
from apptap.targets import Breadth, Target, Tier

logger = logging.getLogger("apptap")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="apptap",
        description="Application-Scoped Traffic Acquisition Pipeline — capture only one app's "
        "traffic, scoped by its Linux UID.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "target",
        nargs="?",
        metavar="TARGET",
        help="Android package name (or process name), or a numeric PID.",
    )
    p.add_argument("-o", "--output", metavar="PCAP", help="Output pcap path.")

    transport = p.add_mutually_exclusive_group()
    transport.add_argument("--device", metavar="SERIAL", help="Capture on this adb device (Android).")
    transport.add_argument("--local", action="store_true", help="Capture on the local Linux host.")

    p.add_argument(
        "--tier",
        choices=["auto", "nflog", "sockdiag"],
        default="auto",
        help="Capture mechanism (default: auto — probe and pick).",
    )

    breadth = p.add_mutually_exclusive_group()
    breadth.add_argument(
        "--strict", action="store_true", help="Scope to the app's base UID only."
    )
    breadth.add_argument(
        "--no-dns",
        action="store_true",
        help="Include isolated/WebView child UIDs but not the DNS resolver UID.",
    )

    p.add_argument(
        "--nflog-group", type=int, default=DEFAULT_NFLOG_GROUP, metavar="N", help="NFLOG group (Tier 2)."
    )
    p.add_argument("-d", "--duration", type=float, metavar="SECS", help="Capture for N seconds then stop.")
    p.add_argument("--probe", action="store_true", help="Report kernel capabilities + chosen tier, then exit.")
    p.add_argument("--cleanup", action="store_true", help="Remove any leftover AppTap netfilter rules, then exit.")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logging.")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _setup_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
        stream=sys.stderr,
    )


def _build_executor(args):
    """Construct the right Executor from the transport flags."""
    if args.local:
        from apptap.executors.local import LocalExecutor

        return LocalExecutor()
    # default to adb (a device serial is optional — adb picks the sole device)
    from apptap.executors.adb import AdbExecutor

    return AdbExecutor(device_id=args.device)


def _build_target(raw: str) -> Target:
    """A numeric TARGET is a PID; anything else is a package/process name."""
    if raw.isdigit():
        return Target(pid=int(raw))
    return Target(package=raw)


def _breadth_from_args(args) -> Breadth:
    if args.strict:
        return Breadth.APP_ONLY
    if args.no_dns:
        return Breadth.APP_ISOLATED
    return Breadth.APP_ISOLATED_DNS


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _setup_logging(args.verbose)

    executor = _build_executor(args)

    # Maintenance actions that don't capture.
    if args.cleanup:
        from apptap.api import cleanup

        cleanup(executor)
        logger.info("Removed any leftover AppTap netfilter rules.")
        return 0

    if args.probe:
        from apptap import capabilities

        caps = capabilities.probe(executor, group=args.nflog_group)
        chosen, warns = capabilities.select_tier(caps, Tier(args.tier))
        print(f"backend={caps.backend} rooted={caps.is_rooted}")
        print(
            f"owner={caps.owner} connmark={caps.connmark} nflog_target={caps.nflog_target} "
            f"nfnetlink_log={caps.nfnetlink_log} ip6tables={caps.ip6tables}"
        )
        print(f"nflog_usable={caps.nflog_usable}  ->  chosen tier: {chosen}")
        for w in warns:
            print(f"note: {w}")
        return 0

    # Capture path requires a target and an output.
    if not args.target:
        parser.error("TARGET is required for capture (or use --probe / --cleanup).")
    if not args.output:
        parser.error("-o/--output is required for capture.")

    from apptap.api import capture

    result = capture(
        target=_build_target(args.target),
        executor=executor,
        output=args.output,
        breadth=_breadth_from_args(args),
        tier=Tier(args.tier),
        nflog_group=args.nflog_group,
        duration=args.duration,
    )

    for w in result.warnings:
        logger.warning(w)
    if result.pcap_path:
        logger.info(
            "Captured %s (tier=%s, %d UID(s), %d connection(s)) -> %s",
            result.pcap_path,
            result.tier,
            len(result.uids),
            len(result.connections),
            result.pcap_path,
        )
        return 0
    logger.error("Capture failed to produce a pcap.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
