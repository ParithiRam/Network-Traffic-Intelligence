"""Convert Scapy packets into normalized PacketEvent objects.

The parser is best-effort: anything it can't decode collapses into a generic
TCP/UDP/OTHER record so the rest of the pipeline still gets coverage.
"""
from __future__ import annotations

import struct
from typing import Optional

from ..models import PacketEvent


def _extract_sni(payload: bytes) -> Optional[str]:
    # Minimal TLS ClientHello SNI parser. Returns the first server_name found,
    # or None on any structural mismatch — we never raise from here.
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        i = 5
        if len(payload) < i + 4 or payload[i] != 0x01:
            return None
        i += 4 + 2 + 32
        if len(payload) < i + 1:
            return None
        sid_len = payload[i]
        i += 1 + sid_len
        if len(payload) < i + 2:
            return None
        cs_len = struct.unpack(">H", payload[i : i + 2])[0]
        i += 2 + cs_len
        if len(payload) < i + 1:
            return None
        cm_len = payload[i]
        i += 1 + cm_len
        if len(payload) < i + 2:
            return None
        ext_total = struct.unpack(">H", payload[i : i + 2])[0]
        i += 2
        end = i + ext_total
        while i + 4 <= end and i + 4 <= len(payload):
            etype = struct.unpack(">H", payload[i : i + 2])[0]
            elen = struct.unpack(">H", payload[i + 2 : i + 4])[0]
            i += 4
            if etype == 0x00:
                # server_name extension
                j = i + 2
                if j + 3 > len(payload):
                    return None
                name_len = struct.unpack(">H", payload[j + 1 : j + 3])[0]
                name = payload[j + 3 : j + 3 + name_len]
                return name.decode("ascii", errors="ignore") or None
            i += elen
    except Exception:
        return None
    return None


def _extract_http_host(payload: bytes) -> Optional[str]:
    try:
        head = payload[:512].decode("latin-1", errors="ignore")
        if not head.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ")):
            return None
        for line in head.split("\r\n")[1:]:
            if not line:
                break
            if line.lower().startswith("host:"):
                return line.split(":", 1)[1].strip().split(":")[0] or None
    except Exception:
        return None
    return None


def parse_scapy(pkt, ts: float) -> Optional[PacketEvent]:
    """Convert a Scapy packet into a PacketEvent, or None if no L3/L4 headers."""
    try:
        from scapy.all import IP, IPv6, TCP, UDP, DNS, Raw
    except Exception:
        return None

    ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip_layer is None:
        return None

    src_ip = getattr(ip_layer, "src", "0.0.0.0")
    dst_ip = getattr(ip_layer, "dst", "0.0.0.0")
    nbytes = len(bytes(pkt))
    proto = "OTHER"
    src_port = dst_port = 0
    sni = host = None

    if pkt.haslayer(TCP):
        tcp = pkt.getlayer(TCP)
        src_port, dst_port = int(tcp.sport), int(tcp.dport)
        proto = "TCP"
        if pkt.haslayer(Raw):
            payload = bytes(pkt.getlayer(Raw).load)
            if dst_port == 443 or src_port == 443:
                sni = _extract_sni(payload)
                proto = "TLS" if sni else "TCP"
            if dst_port == 80 or src_port == 80:
                host = _extract_http_host(payload)
                if host:
                    proto = "HTTP"
    elif pkt.haslayer(UDP):
        udp = pkt.getlayer(UDP)
        src_port, dst_port = int(udp.sport), int(udp.dport)
        proto = "UDP"
        if pkt.haslayer(DNS) or dst_port == 53 or src_port == 53:
            proto = "DNS"

    return PacketEvent(
        ts=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        proto=proto,
        bytes=nbytes,
        tls_sni=sni,
        http_host=host,
    )
