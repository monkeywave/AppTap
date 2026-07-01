"""Tier-1 kernel socket-table parser and UID filter.

AppTap's Tier 1 scopes a capture to an app's UID(s). The kernel exposes every
open socket — together with the owning UID — through ``/proc/net/{tcp,tcp6,udp,
udp6}``. This module parses those files into :class:`~apptap.result.Connection`
value objects paired with their owning UID, then filters down to the target
UID set.

The ``/proc/net`` address encoding is the fiddly part: ports are big-endian hex,
but addresses are little-endian (per 32-bit word). The decoders here are pure
functions so they can be unit-tested without a device.
"""

from __future__ import annotations

import socket
from typing import List, Set, Tuple

from apptap.result import Connection

#: index of each field in a parsed ``/proc/net/*`` data row.
_F_LOCAL = 1
_F_REMOTE = 2
_F_UID = 7

#: minimum number of whitespace-split fields a valid data row must have.
_MIN_FIELDS = 8


def _decode_ipv4(addr_hex: str) -> str:
    """Decode an 8-char little-endian hex IPv4 address to a dotted quad.

    ``/proc`` stores the address as a 32-bit little-endian word, so the byte
    order is reversed relative to dotted notation: ``0100007F`` -> ``127.0.0.1``.
    """
    if len(addr_hex) != 8:
        raise ValueError(f"bad IPv4 hex address: {addr_hex!r}")
    raw = bytes.fromhex(addr_hex)
    return socket.inet_ntop(socket.AF_INET, raw[::-1])


def _decode_ipv6(addr_hex: str) -> str:
    """Decode a 32-char ``/proc`` hex IPv6 address to a standard string.

    ``/proc`` encodes the 16 bytes as four 32-bit little-endian words. Each
    4-byte group is therefore byte-reversed; the order of the groups is kept.
    """
    if len(addr_hex) != 32:
        raise ValueError(f"bad IPv6 hex address: {addr_hex!r}")
    packed = b"".join(
        bytes.fromhex(addr_hex[i : i + 8])[::-1] for i in range(0, 32, 8)
    )
    return socket.inet_ntop(socket.AF_INET6, packed)


def _decode_endpoint(token: str, family: int) -> Tuple[str, int]:
    """Decode a ``HEXADDR:HEXPORT`` token into ``(addr, port)``."""
    addr_hex, _, port_hex = token.partition(":")
    if not port_hex:
        raise ValueError(f"missing port in endpoint: {token!r}")
    port = int(port_hex, 16)
    addr = _decode_ipv4(addr_hex) if family == 4 else _decode_ipv6(addr_hex)
    return addr, port


def parse_proc_net(
    text: str, protocol: str, family: int
) -> List[Tuple[Connection, int]]:
    """Parse one ``/proc/net/{tcp,tcp6,udp,udp6}`` file.

    Args:
        text: full file contents.
        protocol: ``"tcp"`` or ``"udp"`` (the file itself doesn't record this).
        family: ``4`` or ``6``.

    Returns:
        A list of ``(Connection, uid)`` pairs, one per well-formed data row.
        Malformed or short lines are skipped silently.
    """
    rows: List[Tuple[Connection, int]] = []
    lines = text.splitlines()
    for line in lines[1:]:  # drop header
        fields = line.split()
        if len(fields) < _MIN_FIELDS:
            continue
        try:
            laddr, lport = _decode_endpoint(fields[_F_LOCAL], family)
            raddr, rport = _decode_endpoint(fields[_F_REMOTE], family)
            uid = int(fields[_F_UID])
        except (ValueError, IndexError):
            continue
        conn = Connection(
            protocol=protocol,
            family=family,
            laddr=laddr,
            lport=lport,
            raddr=raddr,
            rport=rport,
        )
        rows.append((conn, uid))
    return rows


def filter_conns_by_uid(
    rows: List[Tuple[Connection, int]], uids: Set[int]
) -> Set[Connection]:
    """Keep only the connections whose owning UID is in ``uids``."""
    return {conn for conn, uid in rows if uid in uids}


#: the four ``/proc/net`` sources, as ``(filename, protocol, family)``.
_PROC_NET_SOURCES = (
    ("tcp", "tcp", 4),
    ("tcp6", "tcp", 6),
    ("udp", "udp", 4),
    ("udp6", "udp", 6),
)


def connections_for_uids(executor, uids: Set[int]) -> Set[Connection]:
    """Read every ``/proc/net`` socket table and return the target's 5-tuples.

    Each of ``tcp``/``tcp6``/``udp``/``udp6`` is read via the executor and
    parsed; sockets owned by a UID in ``uids`` are collected into a de-duplicated
    set. Files that cannot be read (e.g. a device without ``udp6``) are ignored.
    """
    conns: Set[Connection] = set()
    for name, protocol, family in _PROC_NET_SOURCES:
        result = executor.shell("cat", f"/proc/net/{name}")
        if not getattr(result, "ok", False):
            continue
        rows = parse_proc_net(result.stdout, protocol, family)
        conns |= filter_conns_by_uid(rows, uids)
    return conns
