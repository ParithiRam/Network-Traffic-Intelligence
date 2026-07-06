"""Parser tests use Scapy to build synthetic packets, so they assert the same
code path that runs against a real PCAP file."""
import time

import pytest

scapy = pytest.importorskip("scapy.all")

from app.ingest.parser import parse_scapy


def test_parse_tcp_http_extracts_host():
    pkt = scapy.IP(src="10.0.1.5", dst="10.0.1.6") / scapy.TCP(sport=44321, dport=80) / scapy.Raw(
        load=b"GET / HTTP/1.1\r\nHost: api.internal\r\nUser-Agent: x\r\n\r\n"
    )
    event = parse_scapy(pkt, ts=time.time())
    assert event is not None
    assert event.proto == "HTTP"
    assert event.http_host == "api.internal"
    assert event.dst_port == 80


def test_parse_udp_dns():
    pkt = scapy.IP(src="10.0.1.5", dst="8.8.8.8") / scapy.UDP(sport=44321, dport=53)
    event = parse_scapy(pkt, ts=time.time())
    assert event is not None
    assert event.proto == "DNS"
    assert event.dst_port == 53


def test_parse_returns_none_without_ip():
    pkt = scapy.Ether()
    assert parse_scapy(pkt, ts=time.time()) is None
