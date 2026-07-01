"""Locate / install the tcpdump binary used for capture.

AppTap bundles arch-specific static tcpdump binaries (the same set friTap ships)
so the standalone tool is self-contained. On Android it detects the device ABI,
pushes the matching binary to a scratch dir, and makes it executable. A native
on-device/on-host tcpdump is preferred when present; a consumer may also inject
an explicit path.

These bundled binaries' libpcap is built with NFLOG support (`-i nflog:<group>`),
which Tier 2 relies on.
"""

from __future__ import annotations

import os
from typing import Optional

from apptap.constants import DEVICE_TMP, TCPDUMP_ARCH_MAP

#: maps `getprop ro.product.cpu.abi` / `uname -m` values to the bundled binary's
#: arch key in TCPDUMP_ARCH_MAP.
_ABI_TO_ARCH = {
    "arm64-v8a": "arm64",
    "aarch64": "arm64",
    "armv8l": "arm",
    "armeabi-v7a": "arm",
    "armeabi": "arm",
    "armv7l": "arm",
    "x86_64": "x64",
    "x86": "ia32",
    "i686": "ia32",
    "i386": "ia32",
}


def assets_dir() -> str:
    """Absolute path to the bundled tcpdump binaries directory."""
    return os.path.join(os.path.dirname(__file__), "assets", "tcpdump_binaries")


def bundled_binary_path(arch: str) -> Optional[str]:
    """Host path to the bundled tcpdump binary for an arch key, or None."""
    name = TCPDUMP_ARCH_MAP.get(arch)
    if not name:
        return None
    path = os.path.join(assets_dir(), name)
    return path if os.path.exists(path) else None


class TcpdumpProvider:
    """Resolves an invocable tcpdump command on the capture target.

    Args:
        executor: the transport to probe/install on.
        override_path: if given, used verbatim (skip detection/install).
        device_tmp: device-side scratch dir for the pushed binary (Android).
    """

    def __init__(self, executor, override_path: Optional[str] = None, device_tmp: str = DEVICE_TMP):
        self._executor = executor
        self._override = override_path
        self._device_tmp = device_tmp
        self._resolved: Optional[str] = None

    def resolve(self) -> str:
        """Return the command string used to invoke tcpdump, installing if needed."""
        if self._resolved:
            return self._resolved
        if self._override:
            self._resolved = self._override
        elif self._native_available():
            self._resolved = "tcpdump"
        elif self._executor.platform == "android":
            self._resolved = self._install_bundled_android()
        else:
            # Linux without a native tcpdump: nothing to install; surface clearly.
            raise RuntimeError(
                "tcpdump not found on the host; install it (e.g. `apt install tcpdump`) "
                "or pass an explicit path."
            )
        return self._resolved

    # --- internals -----------------------------------------------------------

    def _native_available(self) -> bool:
        try:
            res = self._executor.shell("tcpdump", "--version", timeout=8)
        except Exception:
            return False
        return getattr(res, "ok", False) or "tcpdump version" in (res.stdout + res.stderr).lower()

    def _detect_android_arch(self) -> Optional[str]:
        for cmd in (("getprop", "ro.product.cpu.abi"), ("uname", "-m")):
            try:
                res = self._executor.shell(*cmd, timeout=8)
            except Exception:
                continue
            token = (res.stdout or "").strip().splitlines()[0].strip() if res.stdout else ""
            arch = _ABI_TO_ARCH.get(token)
            if arch:
                return arch
        return None

    def _install_bundled_android(self) -> str:
        arch = self._detect_android_arch() or "arm64"  # arm64 is the safe default
        host_path = bundled_binary_path(arch)
        if not host_path:
            raise RuntimeError(f"no bundled tcpdump for arch {arch!r}")
        name = os.path.basename(host_path)
        remote = self._device_tmp + name
        push = self._executor.push_file(host_path, remote)
        if not getattr(push, "ok", False):
            raise RuntimeError(f"failed to push tcpdump to device: {push.stderr or push.stdout}")
        self._executor.shell("chmod", "755", remote, timeout=8)
        return remote
