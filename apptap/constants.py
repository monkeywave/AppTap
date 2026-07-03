"""Shared constants for AppTap.

Centralizes the magic numbers and names used across the capture tiers so the
netfilter rules, capability probe, and teardown all agree.
"""

from __future__ import annotations

# --- Tier 2 (netfilter / NFLOG) ---------------------------------------------

#: conntrack-mark bit AppTap stamps on the target app's connections. Chosen high
#: and applied with an explicit mask so it never collides with Android netd's
#: packet fwmark routing (netId/permission bits live in the low bits). Living in
#: the conntrack-mark namespace (not skb->mark) also makes it immune to Android's
#: eBPF traffic controller, which never touches conntrack marks.
CONNMARK_BIT = 0x40000
CONNMARK_MASK = 0x40000

#: dedicated netfilter chains so teardown is a clean flush+delete of exactly what
#: we created (never editing the device's own chains).
CHAIN_MARK = "APPTAP_MARK"
CHAIN_LOG = "APPTAP_LOG"
CHAIN_PROBE = "APPTAP_PROBE"

#: default NFLOG group used for the in-kernel pre-filtered capture.
DEFAULT_NFLOG_GROUP = 30

#: bytes of each matched packet the kernel copies to userspace over NFLOG.
#: This is a copy *length*, not a "0 == whole packet" range: with the xt_NFLOG
#: F_COPY_LEN flag (which `--nflog-size` sets), a value of 0 makes the kernel
#: strip the payload and deliver header-only records, so the pcap is unusable
#: for traffic analysis. 65535 copies the full packet for any normal MTU while
#: staying safe on every kernel (packets never exceed it).
NFLOG_COPY_SIZE = 65535

#: netfilter table the rules live in.
NETFILTER_TABLE = "mangle"

#: file that exists only when the kernel's nfnetlink_log delivery module is live.
#: Its presence is the decisive Tier-2 gate (stock Android 12-14 GKI ships the
#: NFLOG *target* but not this delivery module).
NFNETLINK_LOG_PROC = "/proc/net/netfilter/nfnetlink_log"


# --- UID ranges (Android) ----------------------------------------------------

#: Android isolated-process UID range (WebView renderers, isolatedProcess=true).
#: These run under a different UID than the app's base appId.
ISOLATED_UID_MIN = 90000
ISOLATED_UID_MAX = 99999

#: Default DNS resolver UID (AID_DNS) — DNS often leaves under this UID, not the
#: app's, so the broad capture breadth includes it.
AID_DNS = 1051

#: Normal app appId range (10000-19999, offset per Android user by *100000).
APP_UID_MIN = 10000


# --- Capture / tcpdump -------------------------------------------------------

#: device-side scratch dir where the bundled tcpdump and temp pcaps are staged.
DEVICE_TMP = "/data/local/tmp/"

#: arch (frida `query_system_parameters` arch value) -> bundled tcpdump binary.
TCPDUMP_ARCH_MAP = {
    "arm64": "tcpdump_arm64_android",
    "arm": "tcpdump_arm32_android",
    "ia32": "tcpdump_x86_android",
    "x64": "tcpdump_x86_64_android",
}

#: infrastructure ports excluded from the interface capture (adb + frida-server).
INFRA_PORTS = (5037, 5555, 27042, 27043)
