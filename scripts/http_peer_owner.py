"""Best-effort Windows PID attribution for an accepted loopback TCP socket.

Reads GetExtendedTcpTable's OWNER_PID_ALL snapshot, never process memory.
The client's row reverses the accepted server socket's local/peer endpoints.
No match is normal if a connection closes before the snapshot is collected.
Layouts: Microsoft MIB_TCPROW_OWNER_PID / MIB_TCP6ROW_OWNER_PID (tcpmib.h).
"""
import ctypes
import ipaddress
import os
import socket
import struct
from functools import lru_cache

_MAX_TABLE_BYTES = 16 * 1024 * 1024
_MAX_ROWS = 200_000
_OWNER_PID_ALL = 5
_INSUFFICIENT_BUFFER = 122


def _endpoint(value, family):
    address = ipaddress.ip_address(value[0])
    port = value[1]
    if not isinstance(port, int) or not 0 < port <= 65535:
        raise ValueError("invalid port")
    if family == socket.AF_INET:
        if address.version != 4 or not address.is_loopback:
            raise ValueError("not IPv4 loopback")
    elif family == socket.AF_INET6:
        if address.version != 6 or not (
            address.is_loopback or (address.ipv4_mapped and address.ipv4_mapped.is_loopback)
        ):
            raise ValueError("not IPv6 loopback")
        # Loopback needs no interface scope. Do not guess at scoped addresses.
        if "%" in value[0] or (len(value) > 3 and value[3] != 0):
            raise ValueError("scoped loopback")
    else:
        raise ValueError("unsupported address family")
    return address.packed, port


def owner_from_table(table, family, peer, local):
    """Decode a bounded native table; return the reverse-tuple owner or None.

    ``peer`` and ``local`` are the accepted socket's getpeername/getsockname.
    This pure decoder also rejects malformed snapshots and ambiguous owners.
    """
    try:
        client, client_port = _endpoint(peer, family)
        server, server_port = _endpoint(local, family)
        row_size = 24 if family == socket.AF_INET else 56
        if len(table) < 4 or len(table) > _MAX_TABLE_BYTES:
            return None
        count = struct.unpack_from("<I", table)[0]
        if count > _MAX_ROWS or count > (len(table) - 4) // row_size:
            return None
        owners = set()
        for index in range(count):
            offset = 4 + index * row_size
            if family == socket.AF_INET:
                state = struct.unpack_from("<I", table, offset)[0]
                addr_a = table[offset + 4:offset + 8]
                port_a = struct.unpack_from("!H", table, offset + 8)[0]
                addr_b = table[offset + 12:offset + 16]
                port_b = struct.unpack_from("!H", table, offset + 16)[0]
                pid = struct.unpack_from("<I", table, offset + 20)[0]
            else:
                addr_a = table[offset:offset + 16]
                scope_a = struct.unpack_from("<I", table, offset + 16)[0]
                port_a = struct.unpack_from("!H", table, offset + 20)[0]
                addr_b = table[offset + 24:offset + 40]
                scope_b = struct.unpack_from("<I", table, offset + 40)[0]
                port_b = struct.unpack_from("!H", table, offset + 44)[0]
                state, pid = struct.unpack_from("<II", table, offset + 48)
                if scope_a or scope_b:
                    continue
            if (5 <= state <= 10 and pid and addr_a == client and port_a == client_port
                    and addr_b == server and port_b == server_port):
                owners.add(pid)
        return next(iter(owners)) if len(owners) == 1 else None
    except (ValueError, TypeError, IndexError, struct.error, OverflowError):
        return None


@lru_cache(maxsize=1)
def _tcp_reader():
    if os.name != "nt":
        return None
    try:
        function = ctypes.WinDLL("iphlpapi.dll").GetExtendedTcpTable
        function.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
                             ctypes.c_int, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        function.restype = ctypes.c_uint32
        return function
    except (OSError, AttributeError):
        return None


def _read_table(family):
    function = _tcp_reader()
    if function is None:
        return None
    size = ctypes.c_uint32(0)
    result = function(None, ctypes.byref(size), False, family, _OWNER_PID_ALL, 0)
    if result != _INSUFFICIENT_BUFFER:
        return None
    # The connection set can grow between calls; bound both retries and memory.
    for _ in range(3):
        if not 4 <= size.value <= _MAX_TABLE_BYTES:
            return None
        capacity = size.value
        buffer = ctypes.create_string_buffer(capacity)
        result = function(buffer, ctypes.byref(size), False, family, _OWNER_PID_ALL, 0)
        if result == 0:
            return buffer.raw[:size.value] if size.value <= capacity else None
        if result != _INSUFFICIENT_BUFFER:
            return None
    return None


def owner_for_connection(connection):
    """Return a loopback client's PID, or None on unavailable/racing evidence."""
    try:
        family = connection.family
        peer, local = connection.getpeername(), connection.getsockname()
        _endpoint(peer, family)
        _endpoint(local, family)
        table = _read_table(family)
        return owner_from_table(table, family, peer, local) if table is not None else None
    except (OSError, ValueError, TypeError, AttributeError, IndexError, OverflowError):
        return None
