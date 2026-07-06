import time

from app.analytics.anomaly import BandwidthSpikeDetector, PortScanDetector
from app.models import PacketEvent


def _pkt(ts: float, dst_port: int = 0, bytes_: int = 100) -> PacketEvent:
    return PacketEvent(
        ts=ts,
        src_ip="10.0.1.5",
        dst_ip="10.0.1.6",
        src_port=12345,
        dst_port=dst_port,
        proto="TCP",
        bytes=bytes_,
    )


def test_port_scan_fires_after_threshold():
    det = PortScanDetector(threshold=10, window_s=5.0, cooldown_s=30)
    now = time.time()
    alerts = []
    for port in range(20):
        a = det.observe(_pkt(now + port * 0.1, dst_port=port))
        if a:
            alerts.append(a)
    assert len(alerts) >= 1
    assert alerts[0].rule == "anomaly:port_scan"


def test_port_scan_window_expires():
    det = PortScanDetector(threshold=5, window_s=1.0, cooldown_s=0.0)
    now = time.time()
    # First batch — old, will fall outside the window.
    for port in range(3):
        det.observe(_pkt(now, dst_port=port))
    # Second batch 5s later, only 3 ports — should not trigger.
    later = now + 5
    a = None
    for port in range(3, 6):
        a = det.observe(_pkt(later + port * 0.01, dst_port=port)) or a
    assert a is None


def test_bandwidth_spike_detects():
    det = BandwidthSpikeDetector(z=2.0, baseline_window=30, cooldown_s=0.0)
    base = time.time()
    # Baseline with realistic noise so stddev > 0.
    for i in range(30):
        det.observe(_pkt(base + i, bytes_=100 + (i % 5) * 10))
    # Now a massive spike one second later.
    alert = det.observe(_pkt(base + 31, bytes_=500_000))
    assert alert is not None
    assert alert.rule == "anomaly:bandwidth_spike"


def test_bandwidth_spike_quiet_traffic_is_silent():
    det = BandwidthSpikeDetector(z=3.0, baseline_window=30, cooldown_s=0.0)
    base = time.time()
    last = None
    for i in range(60):
        last = det.observe(_pkt(base + i, bytes_=100 + (i % 7) * 5)) or last
    assert last is None
