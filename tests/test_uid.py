"""Unit tests for UID resolution.

Pure parsers are tested against in-memory fixtures. Resolvers are tested with a
tiny fake :class:`~apptap.executors.base.Executor` whose ``shell`` returns canned
:class:`~apptap.executors.base.CmdResult`s keyed by the command being run. No
device, root, or ADB required.
"""

from __future__ import annotations

from apptap.executors.base import CmdResult
from apptap.targets import Breadth, Target
from apptap.uid import (
    get_app_uids,
    get_base_uid,
    parse_dumpsys_userid,
    parse_pidof,
    parse_proc_status_uid,
    resolve_uids,
)

# --- Fixtures ----------------------------------------------------------------

# Realistic /proc/<pid>/status excerpt; Uid line is real/eff/saved/fs.
STATUS_BASE = """\
Name:\tcom.example.app
Umask:\t0077
State:\tS (sleeping)
Tgid:\t4242
Pid:\t4242
Uid:\t10123\t10123\t10123\t10123
Gid:\t10123\t10123\t10123\t10123
"""

# An isolated/sandboxed child process running under an isolated-range UID.
STATUS_ISOLATED_CHILD = """\
Name:\tsandboxed_process0
Pid:\t4300
Uid:\t90123\t90123\t90123\t90123
Gid:\t90123\t90123\t90123\t90123
"""

STATUS_NO_UID = """\
Name:\tcom.example.app
State:\tS (sleeping)
Pid:\t4242
"""

DUMPSYS_FIXTURE = """\
Packages:
  Package [com.example.app] (a1b2c3):
    userId=10123
    pkg=Package{...}
    flags=[ HAS_CODE ALLOW_BACKUP ]
"""

DUMPSYS_NO_USERID = """\
Packages:
  Package [com.example.app] (a1b2c3):
    flags=[ HAS_CODE ]
"""


# --- Fake executor -----------------------------------------------------------


class FakeExecutor:
    """Minimal Executor stand-in for tests.

    ``shell`` joins its args into a single command string and looks the result
    up in ``responses``. Lookup is exact-match first, then substring, so tests
    can key on a distinctive fragment (e.g. a pid or package name) rather than
    the full command line. Unmatched commands return a non-zero CmdResult.
    """

    def __init__(self, responses: dict[str, CmdResult], platform: str = "android"):
        self.responses = responses
        self._platform = platform
        self.calls: list = []

    @property
    def platform(self) -> str:
        return self._platform

    @property
    def is_rooted(self) -> bool:
        return True

    def shell(self, *args: str, background: bool = False, timeout: float | None = None):
        cmd = " ".join(args)
        self.calls.append(cmd)
        if cmd in self.responses:
            return self.responses[cmd]
        for key, result in self.responses.items():
            if key in cmd:
                return result
        return CmdResult(returncode=1, stderr="not found")

    def run(self, *args: str, timeout: float | None = None) -> CmdResult:
        return self.shell(*args)

    def push_file(self, local: str, remote: str) -> CmdResult:  # pragma: no cover
        return CmdResult(returncode=0)

    def pull_file(self, remote: str, local: str) -> CmdResult:  # pragma: no cover
        return CmdResult(returncode=0)


def ok(stdout: str) -> CmdResult:
    return CmdResult(returncode=0, stdout=stdout)


# --- Pure parser tests -------------------------------------------------------


def test_parse_proc_status_uid_real_uid():
    assert parse_proc_status_uid(STATUS_BASE) == 10123


def test_parse_proc_status_uid_missing_returns_none():
    assert parse_proc_status_uid(STATUS_NO_UID) is None


def test_parse_dumpsys_userid_found():
    assert parse_dumpsys_userid(DUMPSYS_FIXTURE) == 10123


def test_parse_dumpsys_userid_absent_returns_none():
    assert parse_dumpsys_userid(DUMPSYS_NO_USERID) is None


def test_parse_pidof_multiple():
    assert parse_pidof("1234 5678") == [1234, 5678]


def test_parse_pidof_empty():
    assert parse_pidof("") == []


def test_parse_pidof_whitespace_only():
    assert parse_pidof("  \n ") == []


# --- get_base_uid ------------------------------------------------------------


def test_get_base_uid_via_pid_status():
    ex = FakeExecutor({"/proc/4242/status": ok(STATUS_BASE)})
    target = Target(pid=4242)
    assert get_base_uid(ex, target) == 10123


def test_get_base_uid_via_pidof_then_status():
    ex = FakeExecutor(
        {
            "pidof": ok("4242 4300"),
            "/proc/4242/status": ok(STATUS_BASE),
        }
    )
    target = Target(package="com.example.app")
    assert get_base_uid(ex, target) == 10123


def test_get_base_uid_falls_back_to_dumpsys():
    # pidof returns nothing usable; resolution must fall through to dumpsys.
    ex = FakeExecutor(
        {
            "pidof": ok(""),
            "dumpsys": ok(DUMPSYS_FIXTURE),
        }
    )
    target = Target(package="com.example.app")
    assert get_base_uid(ex, target) == 10123


def test_get_base_uid_falls_back_to_stat():
    ex = FakeExecutor(
        {
            "pidof": ok(""),
            "dumpsys": ok(DUMPSYS_NO_USERID),
            "stat": ok("10123\n"),
        }
    )
    target = Target(package="com.example.app")
    assert get_base_uid(ex, target) == 10123


def test_get_base_uid_unresolved_returns_none():
    ex = FakeExecutor({})
    target = Target(package="com.example.app")
    assert get_base_uid(ex, target) is None


# --- get_app_uids ------------------------------------------------------------


def _app_uids_executor() -> FakeExecutor:
    """Executor where the base resolves via pidof/status and the /proc scan
    surfaces an isolated child UID."""
    proc_scan = STATUS_BASE + STATUS_ISOLATED_CHILD
    return FakeExecutor(
        {
            "pidof": ok("4242"),
            "/proc/4242/status": ok(STATUS_BASE),
            "for d in /proc": ok(proc_scan),
        }
    )


def test_get_app_uids_includes_isolated_child():
    ex = _app_uids_executor()
    target = Target(package="com.example.app")
    assert get_app_uids(ex, target) == {10123, 90123}


def test_get_app_uids_base_only_when_no_children():
    ex = FakeExecutor(
        {
            "pidof": ok("4242"),
            "/proc/4242/status": ok(STATUS_BASE),
            "for d in /proc": ok(STATUS_BASE),
        }
    )
    target = Target(package="com.example.app")
    assert get_app_uids(ex, target) == {10123}


# --- resolve_uids ------------------------------------------------------------


def test_resolve_uids_app_only():
    ex = _app_uids_executor()
    target = Target(package="com.example.app")
    assert resolve_uids(ex, target, Breadth.APP_ONLY) == {10123}


def test_resolve_uids_app_isolated():
    ex = _app_uids_executor()
    target = Target(package="com.example.app")
    assert resolve_uids(ex, target, Breadth.APP_ISOLATED) == {10123, 90123}


def test_resolve_uids_app_isolated_dns_includes_aid_dns():
    ex = _app_uids_executor()
    target = Target(package="com.example.app")
    result = resolve_uids(ex, target, Breadth.APP_ISOLATED_DNS)
    assert result == {10123, 90123, 1051}


def test_resolve_uids_empty_when_base_unresolved():
    ex = FakeExecutor({})
    target = Target(package="com.example.app")
    assert resolve_uids(ex, target, Breadth.APP_ONLY) == set()
    assert resolve_uids(ex, target, Breadth.APP_ISOLATED_DNS) == set()
