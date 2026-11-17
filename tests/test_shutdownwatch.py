import struct
import unittest

from shutdownwatch import analyze, dns_client, mesh_sim
from shutdownwatch.probes import ProbeResult


def fake_dns_reply(qid, ip_bytes):
    header = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + ip_bytes
    return header + question + answer


class DnsTests(unittest.TestCase):
    def test_query_has_header_and_question(self):
        qid, pkt = dns_client.build_query("example.com", qid=42)
        self.assertEqual(struct.unpack("!H", pkt[:2])[0], 42)
        self.assertIn(b"\x07example\x03com\x00", pkt)

    def test_parse_a_record_with_compression(self):
        rcode, ips = dns_client.parse_response(fake_dns_reply(7, bytes([93, 184, 216, 34])), 7)
        self.assertEqual((rcode, ips), (0, ["93.184.216.34"]))

    def test_id_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            dns_client.parse_response(fake_dns_reply(7, bytes(4)), 8)

    def test_truncated_compression_pointer_rejected(self):
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xc0"
        with self.assertRaisesRegex(ValueError, "compression pointer"):
            dns_client.parse_response(packet, 7)

    def test_out_of_bounds_compression_pointer_rejected(self):
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xff\xff"
        with self.assertRaisesRegex(ValueError, "out of bounds"):
            dns_client.parse_response(packet, 7)

    def test_truncated_question_label_rejected(self):
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\x05ab"
        with self.assertRaisesRegex(ValueError, "truncated DNS label"):
            dns_client.parse_response(packet, 7)

    def test_truncated_resource_record_header_rejected(self):
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c\x00\x01"
        with self.assertRaisesRegex(ValueError, "resource record"):
            dns_client.parse_response(packet, 7)

    def test_truncated_resource_record_data_rejected(self):
        question = b"\x07example\x03com\x00" + struct.pack("!HH", 1, 1)
        record = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + b"\x5d\xb8"
        packet = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + record
        with self.assertRaisesRegex(ValueError, "resource-record data"):
            dns_client.parse_response(packet, 7)

    def test_query_packet_is_not_accepted_as_response(self):
        packet = struct.pack("!HHHHHH", 7, 0x0100, 0, 0, 0, 0)
        with self.assertRaisesRegex(ValueError, "not a response"):
            dns_client.parse_response(packet, 7)


class ClassifyTests(unittest.TestCase):
    def mk(self, **kw):
        base = dict(host="x.com", sys_dns_ips=["1.2.3.4"], ctl_dns_ips=["1.2.3.4"],
                    tcp_ok=True, tls_ok=True, http_status=200)
        base.update(kw)
        return ProbeResult(**base)

    def test_ok(self):
        self.assertEqual(analyze.classify(self.mk()), analyze.OK)

    def test_dns_tampering_bogus_ip(self):
        self.assertEqual(analyze.classify(self.mk(sys_dns_ips=["10.0.0.1"])), analyze.DNS_TAMPERING)

    def test_dns_nxdomain_locally(self):
        r = self.mk(sys_dns_ips=[], sys_dns_error="gaierror")
        self.assertEqual(analyze.classify(r), analyze.DNS_TAMPERING)

    def test_tcp_blocked(self):
        self.assertEqual(analyze.classify(self.mk(tcp_ok=False)), analyze.TCP_BLOCKED)

    def test_tls_interference(self):
        self.assertEqual(analyze.classify(self.mk(tls_ok=False)), analyze.TLS_INTERFERENCE)

    def test_http_451(self):
        self.assertEqual(analyze.classify(self.mk(http_status=451)), analyze.HTTP_BLOCKED)

    def test_outage_vs_selective(self):
        dead = [self.mk(host=f"{i}.com", tcp_ok=False) for i in range(5)]
        self.assertEqual(analyze.summarize(dead)[0], analyze.OUTAGE)
        mixed = [self.mk(), self.mk(host="b.com", tcp_ok=False)]
        self.assertEqual(analyze.summarize(mixed)[0], "partial_blocking")


class MeshTests(unittest.TestCase):
    def test_relaying_beats_direct(self):
        d = mesh_sim.simulate(mode="direct", seed=3)
        e = mesh_sim.simulate(mode="epidemic", seed=3)
        self.assertGreaterEqual(e["delivery_ratio"], d["delivery_ratio"])

    def test_deterministic_with_seed(self):
        self.assertEqual(mesh_sim.simulate(seed=5), mesh_sim.simulate(seed=5))


if __name__ == "__main__":
    unittest.main()
