"""Unit tests for the Tier-1 ``/proc/net`` socket-table parser.

No device, root, or scapy required — every test runs against in-memory fixtures.
"""

from __future__ import annotations

from apptap.result import Connection
from apptap.socket_table import (
    connections_for_uids,
    filter_conns_by_uid,
    parse_proc_net,
)

# --- Fixtures ----------------------------------------------------------------
#
# Real /proc/net layouts. Columns (after sl):
#   local_address rem_address st tx:rx tr:tm->when retrnsmt uid timeout inode ...
#
# Local address 0100007F = 127.0.0.1, remote 08080808 = 8.8.8.8, etc.
# uid sits in fields[7].

TCP_FIXTURE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 54321 1 ffff
   1: 0100007F:CF52 08080808:01BB 01 00000000:00000000 00:00000000 00000000 10123        0 54322 1 ffff
   2: 0100007F:1234 09090909:0050 01 00000000:00000000 00:00000000 00000000  1051        0 54323 1 ffff
"""

TCP6_FIXTURE = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 10123        0 60001 1 ffff
   1: 00000000000000000000000001000000:9C40 60480120000060480000000088880000:01BB 01 00000000:00000000 00:00000000 00000000 10123        0 60002 1 ffff
"""

UDP_FIXTURE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000  1051        0 70001 2 ffff 0
   1: 0100007F:E1F4 08080404:0035 01 00000000:00000000 00:00000000 00000000 10123        0 70002 2 ffff 0
"""

UDP6_FIXTURE = """\
  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
   0: 00000000000000000000000001000000:14E9 00000000000000000000000000000000:0000 07 00000000:00000000 00:00000000 00000000 10123        0 80001 2 ffff 0
"""


# --- IPv4 decoding -----------------------------------------------------------


def test_ipv4_local_loopback_decode():
    rows = parse_proc_net(TCP_FIXTURE, "tcp", 4)
    conn, uid = rows[0]
    assert conn.laddr == "127.0.0.1"
    assert conn.lport == 80  # 0x0050
    assert conn.protocol == "tcp"
    assert conn.family == 4


def test_ipv4_remote_google_dns_decode():
    rows = parse_proc_net(TCP_FIXTURE, "tcp", 4)
    conn, uid = rows[1]  # 08080808:01BB
    assert conn.raddr == "8.8.8.8"
    assert conn.rport == 443  # 0x01BB


# --- IPv6 decoding -----------------------------------------------------------


def test_ipv6_loopback_decode():
    rows = parse_proc_net(TCP6_FIXTURE, "tcp", 6)
    # row 1 has local = ::1
    conn, uid = rows[1]
    assert conn.laddr == "::1"
    assert conn.family == 6
    assert conn.protocol == "tcp"


def test_ipv6_global_unicast_decode():
    rows = parse_proc_net(TCP6_FIXTURE, "tcp", 6)
    conn, uid = rows[1]  # remote = 2001:4860:4860::8888
    assert conn.raddr == "2001:4860:4860::8888"
    assert conn.rport == 443  # 0x01BB


# --- UID extraction ----------------------------------------------------------


def test_uid_extracted_from_field_seven():
    rows = parse_proc_net(TCP_FIXTURE, "tcp", 4)
    uids = [uid for _, uid in rows]
    assert uids == [10123, 10123, 1051]


# --- Filtering ---------------------------------------------------------------


def test_filter_keeps_only_target_uids():
    rows = parse_proc_net(TCP_FIXTURE, "tcp", 4)
    conns = filter_conns_by_uid(rows, {10123})
    # the uid-1051 row (raddr 9.9.9.9) must be excluded
    raddrs = {c.raddr for c in conns}
    assert "9.9.9.9" not in raddrs
    assert "8.8.8.8" in raddrs
    assert len(conns) == 2


def test_filter_empty_uid_set_returns_nothing():
    rows = parse_proc_net(TCP_FIXTURE, "tcp", 4)
    assert filter_conns_by_uid(rows, set()) == set()


# --- Robustness --------------------------------------------------------------


def test_malformed_and_short_lines_are_skipped():
    text = (
        "  sl  local_address rem_address st ...\n"
        "   0: garbage\n"  # too few fields
        "   1: NOTHEX:XXXX 00000000:0000 0A 0 0 0 10123 0 1\n"  # bad hex
        "   2: 0100007F:0050 00000000:0000 0A 0 0 0 10123 0 1\n"  # valid
        "\n"  # blank line
        "   3: 0100007F:0050 00000000:0000 0A 0 0 0 notanint 0 1\n"  # bad uid
    )
    rows = parse_proc_net(text, "tcp", 4)
    assert len(rows) == 1
    conn, uid = rows[0]
    assert conn.laddr == "127.0.0.1"
    assert uid == 10123


def test_header_only_file_yields_no_rows():
    assert parse_proc_net("  sl  local_address rem_address\n", "tcp", 4) == []


def test_empty_text_yields_no_rows():
    assert parse_proc_net("", "tcp", 4) == []


# --- connections_for_uids end-to-end (fake executor) -------------------------


class _FakeResult:
    def __init__(self, returncode, stdout=""):
        self.returncode = returncode
        self.stdout = stdout

    @property
    def ok(self):
        return self.returncode == 0


class _FakeExecutor:
    """Serves the four fixtures; udp6 read 'fails' to exercise the skip path."""

    def __init__(self, fail_udp6=False):
        self._fail_udp6 = fail_udp6
        self._map = {
            "/proc/net/tcp": TCP_FIXTURE,
            "/proc/net/tcp6": TCP6_FIXTURE,
            "/proc/net/udp": UDP_FIXTURE,
            "/proc/net/udp6": UDP6_FIXTURE,
        }

    def shell(self, *args, background=False, timeout=None):
        path = args[-1]
        if path == "/proc/net/udp6" and self._fail_udp6:
            return _FakeResult(1, "")
        return _FakeResult(0, self._map[path])


def test_connections_for_uids_collects_across_all_files():
    conns = connections_for_uids(_FakeExecutor(), {10123})
    # tcp: 2 rows for 10123; tcp6: 1; udp: 1; udp6: 1 -> all distinct keys.
    assert all(isinstance(c, Connection) for c in conns)
    # the 1051-owned tcp/udp sockets must not appear
    assert all(c.raddr not in ("9.9.9.9",) for c in conns)
    # at least one connection from each family/protocol mix
    protos_families = {(c.protocol, c.family) for c in conns}
    assert ("tcp", 4) in protos_families
    assert ("tcp", 6) in protos_families
    assert ("udp", 4) in protos_families
    assert ("udp", 6) in protos_families


def test_connections_for_uids_ignores_unreadable_file():
    conns = connections_for_uids(_FakeExecutor(fail_udp6=True), {10123})
    # udp6 (the only ('udp',6) source) is gone, others remain.
    protos_families = {(c.protocol, c.family) for c in conns}
    assert ("udp", 6) not in protos_families
    assert ("tcp", 4) in protos_families
