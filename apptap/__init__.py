"""AppTap - Application-Scoped Traffic Acquisition Pipeline.

Capture only a single application's network traffic, scoped by its Linux UID,
using the kernel's authoritative knowledge of which UID owns each socket.

AppTap works both as an importable library and as a standalone CLI tool. It
acquires an *app-scoped pcap* (plus the matching connection set); it deliberately
does NOT touch TLS keys or decryption — that is the consumer's job (e.g. friTap).

Library usage::

    import apptap

    result = apptap.capture(
        target=apptap.Target(package="com.example.app"),
        executor=apptap.AdbExecutor(device_id="..."),   # or apptap.LocalExecutor()
        output="app.pcap",
    )
    print(result.tier, result.uids, result.pcap_path)

Or drive the lifecycle yourself (capture while you run the app)::

    with apptap.CaptureSession(target=..., executor=..., output="app.pcap") as cap:
        cap.start()
        ...            # run the app / instrument it
        cap.stop()
    result = cap.result
"""

from apptap.about import __author__, __license__, __version__
from apptap.result import CaptureResult, Connection
from apptap.targets import Breadth, Target, Tier

__all__ = [
    # high-level API (lazy-loaded below)
    "capture",
    "CaptureSession",
    # value types
    "Target",
    "Breadth",
    "Tier",
    "CaptureResult",
    "Connection",
    # executor interface + implementations (lazy-loaded below)
    "Executor",
    "CmdResult",
    "LocalExecutor",
    "AdbExecutor",
    # metadata
    "__version__",
    "__author__",
    "__license__",
]


def __getattr__(name):
    # Lazy imports keep `import apptap` cheap and avoid importing scapy/subprocess
    # machinery unless the high-level API or executors are actually used.
    if name in ("capture", "CaptureSession"):
        from apptap import api

        return getattr(api, name)
    if name in ("Executor", "CmdResult"):
        from apptap.executors import base

        return getattr(base, name)
    if name == "LocalExecutor":
        from apptap.executors.local import LocalExecutor

        return LocalExecutor
    if name == "AdbExecutor":
        from apptap.executors.adb import AdbExecutor

        return AdbExecutor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
