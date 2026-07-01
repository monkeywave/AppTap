"""Tests for the concrete Executor implementations.

``LocalExecutor`` is exercised against real harmless local commands (with
``use_sudo=False`` so no privileges are needed). ``AdbExecutor`` is tested
without any device by checking the pure pieces: adb base command construction and
the ``_elevator`` escaping for each detected strategy.
"""

from __future__ import annotations

import os

import pytest

from apptap.executors.adb import (
    STRATEGY_MAGISK,
    STRATEGY_NONE,
    STRATEGY_ROOT,
    STRATEGY_SU0,
    AdbExecutor,
)
from apptap.executors.local import LocalExecutor


# --------------------------------------------------------------------------- #
# LocalExecutor
# --------------------------------------------------------------------------- #


def test_local_platform_is_linux():
    assert LocalExecutor(use_sudo=False).platform == "linux"


def test_local_shell_echo_ok_and_stdout():
    result = LocalExecutor(use_sudo=False).shell("echo", "hello")
    assert result.ok
    assert "hello" in result.stdout


def test_local_shell_true_succeeds():
    assert LocalExecutor(use_sudo=False).shell("true").returncode == 0


def test_local_shell_false_fails():
    assert LocalExecutor(use_sudo=False).shell("false").returncode != 0


def test_local_run_echo():
    result = LocalExecutor(use_sudo=False).run("echo", "x")
    assert result.ok
    assert "x" in result.stdout


def test_local_shell_background_returns_proc():
    proc = LocalExecutor(use_sudo=False).shell("echo", "bg", background=True)
    assert hasattr(proc, "poll")
    assert hasattr(proc, "wait")
    assert proc.wait(timeout=10) == 0


def test_local_push_file_copies(tmp_path):
    src = tmp_path / "src.txt"
    dst = tmp_path / "dst.txt"
    src.write_text("payload")
    result = LocalExecutor(use_sudo=False).push_file(str(src), str(dst))
    assert result.ok
    assert dst.read_text() == "payload"


def test_local_pull_file_copies(tmp_path):
    src = tmp_path / "remote.txt"
    dst = tmp_path / "host.txt"
    src.write_text("payload")
    result = LocalExecutor(use_sudo=False).pull_file(str(src), str(dst))
    assert result.ok
    assert dst.read_text() == "payload"


def test_local_copy_failure_returns_nonzero(tmp_path):
    missing = tmp_path / "does-not-exist.txt"
    dst = tmp_path / "dst.txt"
    result = LocalExecutor(use_sudo=False).push_file(str(missing), str(dst))
    assert not result.ok
    assert result.stderr


def test_local_is_rooted_matches_geteuid():
    assert LocalExecutor(use_sudo=False).is_rooted == (os.geteuid() == 0)


# --------------------------------------------------------------------------- #
# AdbExecutor — pure pieces, no device required
# --------------------------------------------------------------------------- #


def _executor_with_strategy(strategy: str, device_id=None) -> AdbExecutor:
    """Build an AdbExecutor with the elevation strategy pinned (no probing)."""
    executor = AdbExecutor(device_id=device_id)
    executor._strategy = strategy
    return executor


def test_adb_platform_is_android():
    assert AdbExecutor().platform == "android"


def test_adb_base_without_device():
    assert AdbExecutor().adb_base == ["adb"]


def test_adb_base_with_device():
    assert AdbExecutor(device_id="emulator-5554").adb_base == [
        "adb",
        "-s",
        "emulator-5554",
    ]


def test_elevator_root_unchanged():
    executor = _executor_with_strategy(STRATEGY_ROOT)
    assert executor._elevator("id -u") == "id -u"


def test_elevator_none_unchanged():
    executor = _executor_with_strategy(STRATEGY_NONE)
    assert executor._elevator("id -u") == "id -u"


def test_elevator_su0_prefix():
    executor = _executor_with_strategy(STRATEGY_SU0)
    assert executor._elevator("id -u") == "su 0 id -u"


def test_elevator_magisk_wraps():
    executor = _executor_with_strategy(STRATEGY_MAGISK)
    assert executor._elevator("id -u") == "su -c 'id -u'"


def test_elevator_magisk_escapes_single_quotes():
    executor = _executor_with_strategy(STRATEGY_MAGISK)
    # A command containing a single quote must be escaped as ' -> '\''
    assert executor._elevator("echo 'hi'") == "su -c 'echo '\\''hi'\\'''"


def test_is_rooted_true_for_elevated_strategies():
    assert _executor_with_strategy(STRATEGY_ROOT).is_rooted is True
    assert _executor_with_strategy(STRATEGY_SU0).is_rooted is True
    assert _executor_with_strategy(STRATEGY_MAGISK).is_rooted is True


def test_is_rooted_false_for_none_strategy():
    assert _executor_with_strategy(STRATEGY_NONE).is_rooted is False


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
