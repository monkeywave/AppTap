<div align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/monkeywave/AppTap/main/misc/apptap-lockup-dark.png">
        <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/monkeywave/AppTap/main/misc/apptap-lockup-light.png">
        <img src="https://raw.githubusercontent.com/monkeywave/AppTap/main/misc/apptap-lockup-light.png" alt="AppTap Logo" width="360"/>
    </picture>
    <p></p><strong>Application-Scoped Traffic Acquisition Pipeline</strong>
    <p><em>Capture only one app's network traffic — scoped by its Linux UID.</em></p>
</div>


# AppTap
![version](https://img.shields.io/badge/version-0.3.0-blue) [![PyPI version](https://badge.fury.io/py/apptap.svg)](https://badge.fury.io/py/apptap) [![Publish status](https://github.com/monkeywave/AppTap/actions/workflows/publish.yml/badge.svg?branch=main)](https://github.com/monkeywave/AppTap/actions/workflows/publish.yml)
[![Lint](https://github.com/monkeywave/AppTap/actions/workflows/lint.yml/badge.svg)](https://github.com/monkeywave/AppTap/actions/workflows/lint.yml)

Capture **only one application's** network traffic, scoped by its **Linux UID**, using the kernel's
authoritative knowledge of which UID owns each socket — something `tcpdump`/BPF alone cannot do (UID
is a socket property, absent from the wire).

AppTap is both an importable **library** and a standalone **CLI tool**. It acquires an *app-scoped
pcap* (plus the matching connection set). It deliberately does **not** decrypt TLS or handle keys —
that is the consumer's job (e.g. [friTap](https://github.com/fkie-cad/friTap), which embeds decryption
keys onto AppTap's pcap).

## How it works — two tiers, auto-selected

Two kernel mechanisms can scope capture by UID, and neither is universally available, so AppTap
probes and picks the best one at runtime:

- **Tier 1 — interface capture + kernel socket-table UID filter (robust default).** Capture on the
  interface, then keep only packets whose 5-tuple belongs to the target UID(s), resolved from the
  kernel's authoritative socket→UID table (`SOCK_DIAG` / `/proc/net/{tcp,tcp6,udp,udp6}`). Works on
  **every** Android/Linux version.
- **Tier 2 — `iptables` owner + CONNMARK + NFLOG in-kernel pre-filter (opportunistic).** The kernel
  selects only the app's packets and copies them to userspace. Cleanest and most private, but depends
  on the kernel's `nfnetlink_log` delivery, which is disabled on most stock Android 12–14 GKI kernels.
  Used only where a capability probe (plus a delivery liveness check) confirms it works.

Requires **root** on the target (Android: rooted device + `adb`; Linux: root/sudo).

## Install

```
pip install AppTap
```

## CLI

```
apptap com.example.app --device <serial> -o app.pcap        # Android (adb)
apptap 1234 --local -o app.pcap                             # Linux (pid)
apptap com.example.app --device <serial> --tier sockdiag --strict -d 30
apptap --probe   --device <serial>                          # report capabilities + chosen tier
apptap --cleanup --device <serial>                          # remove any leftover APPTAP_* rules
```

## Library

```python
import apptap

result = apptap.capture(
    target=apptap.Target(package="com.example.app"),
    executor=apptap.AdbExecutor(device_id="<serial>"),   # or apptap.LocalExecutor()
    output="app.pcap",
    breadth=apptap.Breadth.APP_ISOLATED_DNS,             # default
    tier=apptap.Tier.AUTO,
)
print(result.tier, result.uids, result.pcap_path)
```

Drive the lifecycle yourself (capture while you run/instrument the app):

```python
with apptap.CaptureSession(target=..., executor=..., output="app.pcap") as cap:
    cap.start()
    ...            # launch the app / attach your instrumentation
    cap.stop()
result = cap.result
```

Bring your own transport by implementing the `apptap.Executor` protocol (or wrapping an existing one):
AppTap runs every command through it, so it can reuse a host tool's adb/root plumbing.

## License

MIT © Daniel Baier
