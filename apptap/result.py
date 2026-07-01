"""Result and connection value types returned by a capture.

The ``CaptureResult`` is the contract between AppTap and its consumers: an
app-scoped pcap plus the connection set and metadata. AppTap never returns keys
or decrypted data — only acquisition results.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from apptap.targets import Tier


@dataclass(frozen=True)
class Connection:
    """A network 5-tuple owned by the target during capture.

    ``family`` is 4 or 6. Addresses are human-readable strings (e.g.
    "10.0.2.16", "2001:db8::1"). A listening/unconnected socket may have an empty
    or zero remote endpoint.
    """

    protocol: str  # "tcp" | "udp"
    family: int    # 4 | 6
    laddr: str
    lport: int
    raddr: str
    rport: int

    def key(self) -> tuple:
        """Order-independent identity for dedup across snapshots."""
        a = (self.laddr, self.lport)
        b = (self.raddr, self.rport)
        lo, hi = sorted((a, b))
        return (self.protocol, self.family, lo, hi)


@dataclass
class CaptureResult:
    """Outcome of a capture.

    Attributes:
        tier: the mechanism actually used (``NFLOG``/``SOCKDIAG``/``WHOLE_DEVICE``).
        uids: the resolved UID set the capture was scoped to.
        connections: the app's observed 5-tuples (Tier 1 derives these from the
            kernel socket table; Tier 2 may leave this empty since the kernel
            already filtered).
        pcap_path: path to the app-scoped pcap on the host (None if capture failed).
        linktype: libpcap DLT of ``pcap_path`` (276=LINUX_SLL2 for Tier 1,
            239=NFLOG for Tier 2) when known.
        warnings: human-readable advisories (e.g. the Android version note,
            "demoted to Tier 1", "DNS may include other apps").
    """

    tier: Tier
    uids: frozenset = frozenset()
    connections: tuple = ()
    pcap_path: Optional[str] = None
    linktype: Optional[int] = None
    warnings: list = field(default_factory=list)
