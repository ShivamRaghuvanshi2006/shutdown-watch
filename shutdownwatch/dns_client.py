"""A tiny hand-rolled DNS client (A records over UDP, RFC 1035).

Written from scratch on purpose: it lets us ask a specific resolver directly and
compare its answer with the one the operating system gives us.
"""
import random
import socket
import struct


def build_query(host, qid=None):
    """Return (query_id, packet_bytes) for an A-record question."""
    if qid is None:
        qid = random.randint(0, 0xFFFF)
    # flags 0x0100 = standard query, recursion desired; 1 question
    header = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.strip(".").split(".")) + b"\x00"
    return qid, header + qname + struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN


def _skip_name(data, off):
    while True:
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:  # compression pointer is 2 bytes
            return off + 2
        off += 1 + length


def parse_response(data, qid):
    """Return (rcode, [ipv4 strings]). Raises ValueError on a bad packet."""
    if len(data) < 12:
        raise ValueError("short DNS packet")
    rid, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if rid != qid:
        raise ValueError("DNS id mismatch")
    rcode = flags & 0x000F
    off = 12
    for _ in range(qd):
        off = _skip_name(data, off) + 4
    ips = []
    for _ in range(an):
        off = _skip_name(data, off)
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
        off += 10
        if rtype == 1 and rdlen == 4:
            ips.append(socket.inet_ntoa(data[off:off + 4]))
        off += rdlen
    return rcode, ips


def query(host, server="8.8.8.8", timeout=3.0):
    """Ask `server` directly for the A records of `host`."""
    qid, packet = build_query(host)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(packet, (server, 53))
        data, _ = s.recvfrom(2048)
    return parse_response(data, qid)
