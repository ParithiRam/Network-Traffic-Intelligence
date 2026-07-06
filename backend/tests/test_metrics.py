import time

from app.analytics.metrics import MetricsStore
from app.models import PacketEvent


def _pkt(**kw) -> PacketEvent:
    base = dict(ts=time.time(), src_ip="10.0.1.5", dst_ip="8.8.8.8", proto="TLS", bytes=100)
    base.update(kw)
    return PacketEvent(**base)


def test_totals_and_top_talkers():
    s = MetricsStore(window_s=60)
    s.record_packet(_pkt(src_ip="10.0.1.5", bytes=500))
    s.record_packet(_pkt(src_ip="10.0.1.5", bytes=500))
    s.record_packet(_pkt(src_ip="10.0.1.6", bytes=200))
    snap = s.snapshot()
    assert snap.total_packets == 3
    assert snap.total_bytes == 1200
    assert snap.top_talkers[0].ip == "10.0.1.5"
    assert snap.top_talkers[0].bytes == 1000


def test_protocol_distribution():
    s = MetricsStore()
    s.record_packet(_pkt(proto="TLS", bytes=300))
    s.record_packet(_pkt(proto="DNS", bytes=100))
    s.record_packet(_pkt(proto="TLS", bytes=500))
    protos = {p.proto: p.bytes for p in s.snapshot().protocols}
    assert protos == {"TLS": 800, "DNS": 100}


def test_drops_and_alerts_counters():
    s = MetricsStore()
    s.record_drop()
    s.record_drop()
    s.record_alert()
    assert s.snapshot().dropped_packets == 2
    assert s.snapshot().alerts_count == 1
