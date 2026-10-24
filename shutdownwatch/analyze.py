"""Turn raw probe results into a verdict. Pure functions, easy to unit test."""
import ipaddress

OK = "ok"
DNS_TAMPERING = "dns_tampering"
DNS_FAILURE = "dns_failure"
TCP_BLOCKED = "tcp_blocked"
TLS_INTERFERENCE = "tls_interference"
HTTP_BLOCKED = "http_blocked"
UNREACHABLE = "unreachable_everywhere"
OUTAGE = "likely_outage"


def _is_bogus(ip):
    a = ipaddress.ip_address(ip)
    return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved


def classify(r):
    """Verdict for one site, based on where in the stack it first breaks."""
    sys_ips, ctl_ips = set(r.sys_dns_ips), set(r.ctl_dns_ips)

    if not sys_ips and not ctl_ips:
        return UNREACHABLE  # nobody can resolve it: probably just a dead domain
    if ctl_ips and not sys_ips:
        return DNS_TAMPERING if r.sys_dns_error else DNS_FAILURE
    if sys_ips and ctl_ips and any(_is_bogus(i) for i in sys_ips) and not any(_is_bogus(i) for i in ctl_ips):
        return DNS_TAMPERING  # local resolver points a public name at a private address
    if r.tcp_ok is False:
        return TCP_BLOCKED
    if r.tls_ok is False:
        return TLS_INTERFERENCE
    if r.http_status == 451 or (r.http_error and r.tls_ok):
        return HTTP_BLOCKED
    return OK


def summarize(results):
    """Add a network-wide verdict: if almost nothing works, that's an outage,
    not selective blocking."""
    verdicts = {r.host: classify(r) for r in results}
    working = sum(v == OK for v in verdicts.values())
    failing_low = sum(v in (DNS_FAILURE, TCP_BLOCKED, UNREACHABLE) for v in verdicts.values())
    overall = OUTAGE if results and working == 0 and failing_low >= max(1, int(0.8 * len(results))) else (
        OK if working == len(results) else "partial_blocking")
    return overall, verdicts
