"""Layer-by-layer probes: DNS -> TCP -> TLS -> HTTP.

Each step records timing and the error (if any), so a failure can be pinned to
the layer where it happened.
"""
import http.client
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import List, Optional

from . import dns_client


@dataclass
class ProbeResult:
    host: str
    sys_dns_ips: List[str] = field(default_factory=list)
    sys_dns_error: Optional[str] = None
    ctl_dns_ips: List[str] = field(default_factory=list)
    ctl_dns_rcode: Optional[int] = None
    ctl_dns_error: Optional[str] = None
    tcp_ok: Optional[bool] = None
    tcp_ms: Optional[float] = None
    tcp_error: Optional[str] = None
    tls_ok: Optional[bool] = None
    tls_ms: Optional[float] = None
    tls_error: Optional[str] = None
    http_status: Optional[int] = None
    http_ms: Optional[float] = None
    http_error: Optional[str] = None


def _ms(start):
    return round((time.monotonic() - start) * 1000, 1)


def probe(host, control_dns="8.8.8.8", timeout=5.0):
    r = ProbeResult(host=host)

    # 1. DNS via the OS resolver (what the user's network actually hands out)
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_INET, socket.SOCK_STREAM)
        r.sys_dns_ips = sorted({i[4][0] for i in infos})
    except OSError as e:
        r.sys_dns_error = type(e).__name__

    # 2. DNS via a control resolver, asked directly
    try:
        r.ctl_dns_rcode, r.ctl_dns_ips = dns_client.query(host, control_dns, timeout)
        r.ctl_dns_ips = sorted(r.ctl_dns_ips)
    except (OSError, ValueError) as e:
        r.ctl_dns_error = type(e).__name__

    ip = (r.sys_dns_ips or r.ctl_dns_ips or [None])[0]
    if ip is None:
        return r

    # 3. TCP handshake
    sock = None
    t = time.monotonic()
    try:
        sock = socket.create_connection((ip, 443), timeout=timeout)
        r.tcp_ok, r.tcp_ms = True, _ms(t)
    except OSError as e:
        r.tcp_ok, r.tcp_error = False, type(e).__name__
        return r

    # 4. TLS handshake (SNI = hostname, so SNI-based filtering would show up here)
    t = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        tls = ctx.wrap_socket(sock, server_hostname=host)
        r.tls_ok, r.tls_ms = True, _ms(t)
    except (OSError, ssl.SSLError) as e:
        r.tls_ok, r.tls_error = False, type(e).__name__
        sock.close()
        return r

    # 5. HTTP request over the already-open TLS socket
    t = time.monotonic()
    try:
        conn = http.client.HTTPSConnection(host, timeout=timeout)
        conn.sock = tls
        conn.request("HEAD", "/", headers={"User-Agent": "shutdown-watch/0.1 (CN course project)"})
        r.http_status = conn.getresponse().status
        r.http_ms = _ms(t)
        conn.close()
    except (OSError, http.client.HTTPException) as e:
        r.http_error = type(e).__name__
    return r
