"""Resolve the set of Linux UIDs a capture should be scoped to.

AppTap scopes capture to an app's UID(s). This module turns a :class:`Target`
(package and/or pid) into the concrete set of UIDs to filter on, at a
configurable :class:`Breadth`.

The module is split into two layers:

* **Pure parsers** (``parse_*``) take raw command output and return values.
  They have no executor dependency and are unit-tested directly.
* **Resolvers** (``get_*`` / ``resolve_uids``) drive an :class:`Executor` to
  obtain that raw output and combine the parsers into a UID set.
"""

from __future__ import annotations

import re
from typing import Optional, Set

from .constants import AID_DNS, ISOLATED_UID_MAX, ISOLATED_UID_MIN
from .executors.base import Executor
from .targets import Breadth, Target

# --- Pure parsers ------------------------------------------------------------

#: Matches the ``Uid:`` line of ``/proc/<pid>/status``. The four numbers are
#: real, effective, saved-set and filesystem UID; we capture the real UID.
_PROC_STATUS_UID_RE = re.compile(r"^Uid:\s+(\d+)", re.MULTILINE)

#: Matches ``userId=<n>`` in ``dumpsys package <pkg>`` output.
_DUMPSYS_USERID_RE = re.compile(r"\buserId=(\d+)")


def parse_proc_status_uid(text: str) -> Optional[int]:
    """Return the *real* UID from ``/proc/<pid>/status`` text, or None.

    The relevant line looks like ``Uid:\\t<real>\\t<eff>\\t<saved>\\t<fs>``.
    """
    match = _PROC_STATUS_UID_RE.search(text)
    return int(match.group(1)) if match else None


def parse_dumpsys_userid(text: str) -> Optional[int]:
    """Return the ``userId=<n>`` value from ``dumpsys package`` output, or None."""
    match = _DUMPSYS_USERID_RE.search(text)
    return int(match.group(1)) if match else None


def parse_pidof(text: str) -> list:
    """Parse space-separated PIDs from ``pidof`` output into a list of ints.

    Robust to empty / whitespace-only output (returns ``[]``).
    """
    return [int(token) for token in text.split() if token.isdigit()]


# --- Resolvers ---------------------------------------------------------------


def _read_status_uid(executor: Executor, pid: int) -> Optional[int]:
    """Read ``/proc/<pid>/status`` and return its real UID, or None."""
    result = executor.shell("cat", f"/proc/{pid}/status")
    if not getattr(result, "ok", False):
        return None
    return parse_proc_status_uid(result.stdout)


def get_base_uid(executor: Executor, target: Target) -> Optional[int]:
    """Resolve the app's base (appId) UID, trying strategies in order.

    First success wins:

    1. ``target.pid`` set: read ``/proc/<pid>/status``.
    2. Android package: ``pidof -x "<pkg>"`` → status of the first pid.
    3. Android package fallback: ``dumpsys package "<pkg>"`` → ``userId=``.
    4. Android package fallback: ``stat -c %u /data/data/<pkg>``.

    Returns None if every strategy fails.
    """
    if target.pid is not None:
        uid = _read_status_uid(executor, target.pid)
        if uid is not None:
            return uid

    if target.package and executor.platform == "android":
        pkg = target.package

        pidof = executor.shell("pidof", "-x", f'"{pkg}"')
        if getattr(pidof, "ok", False):
            pids = parse_pidof(pidof.stdout)
            if pids:
                uid = _read_status_uid(executor, pids[0])
                if uid is not None:
                    return uid

        dumpsys = executor.shell("dumpsys", "package", f'"{pkg}"')
        if getattr(dumpsys, "ok", False):
            uid = parse_dumpsys_userid(dumpsys.stdout)
            if uid is not None:
                return uid

        stat = executor.shell("stat", "-c", "%u", f"/data/data/{pkg}")
        if getattr(stat, "ok", False):
            token = stat.stdout.strip()
            if token.isdigit():
                return int(token)

    return None


def get_app_uids(executor: Executor, target: Target) -> Set[int]:
    """Enumerate every UID belonging to the package, incl. isolated children.

    Approach (kept deliberately simple and robust):

    * Resolve the base UID via :func:`get_base_uid` (handles pid/package).
    * On Android with a package name, scan ``/proc`` for processes whose
      cmdline starts with the package name and collect their real UIDs. This
      catches isolated/sandboxed children (``:sandboxed_process``, WebView
      renderers) which run under their own UID in the isolated range
      (90000-99999) rather than the app's appId.

    The scan is a single shell loop the executor runs on the target::

        for d in /proc/[0-9]*; do
          c=$(cat $d/cmdline 2>/dev/null | tr "\\0" " ")
          case "$c" in <pkg>*) cat $d/status;; esac
        done

    All ``Uid:`` lines in the concatenated output are parsed and their real
    UIDs collected. The returned set is the base UID plus any matching child
    UIDs; it may be just ``{base}`` when there are no children.
    """
    uids: Set[int] = set()

    base = get_base_uid(executor, target)
    if base is not None:
        uids.add(base)

    if target.package and executor.platform == "android":
        pkg = target.package
        # Single shell loop: print the status block of every /proc entry whose
        # cmdline starts with the package name.
        script = (
            'for d in /proc/[0-9]*; do '
            'c=$(cat "$d/cmdline" 2>/dev/null | tr "\\0" " "); '
            f'case "$c" in "{pkg}"*) cat "$d/status" 2>/dev/null;; esac; '
            "done"
        )
        result = executor.shell("sh", "-c", f'"{script}"')
        if getattr(result, "ok", False):
            for line in result.stdout.splitlines():
                if line.startswith("Uid:"):
                    uid = parse_proc_status_uid(line)
                    if uid is not None:
                        uids.add(uid)

    return uids


def _is_isolated(uid: int) -> bool:
    """True if ``uid`` falls in the Android isolated-process range."""
    return ISOLATED_UID_MIN <= uid <= ISOLATED_UID_MAX


def resolve_uids(
    executor: Executor, target: Target, breadth: Breadth
) -> Set[int]:
    """Resolve the set of UIDs to scope capture to, at the given breadth.

    * ``APP_ONLY`` → ``{base_uid}``.
    * ``APP_ISOLATED`` → base UID + isolated/WebView child UIDs.
    * ``APP_ISOLATED_DNS`` → the above ∪ ``{AID_DNS}``.

    Returns an empty set if the base UID cannot be resolved at all; the caller
    treats that as a resolution failure (and decides any fallback).
    """
    if breadth is Breadth.APP_ONLY:
        base = get_base_uid(executor, target)
        return {base} if base is not None else set()

    uids = get_app_uids(executor, target)
    if not uids:
        return set()

    if breadth is Breadth.APP_ISOLATED_DNS:
        uids = uids | {AID_DNS}

    return uids
