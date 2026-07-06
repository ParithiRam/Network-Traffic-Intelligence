"""YAML-driven rule engine for traffic shaping and alerting.

Rules evaluate top-to-bottom. The first match wins and dictates the action:
allow lets the packet flow into analytics, drop discards it, alert keeps it
flowing but emits an Alert. Packets with no match default to allow.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import yaml

from ..models import Action, Alert, PacketEvent, Rule, RuleMatch


_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETS)


def _direction(src: str, dst: str) -> str:
    s, d = _is_private(src), _is_private(dst)
    if s and d:
        return "internal"
    if not s and not d:
        return "external"
    return "outbound" if s else "inbound"


def _cidr_match(ip: str, cidr: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _match(pkt: PacketEvent, m: RuleMatch) -> bool:
    if m.src_cidr and not _cidr_match(pkt.src_ip, m.src_cidr):
        return False
    if m.dst_cidr and not _cidr_match(pkt.dst_ip, m.dst_cidr):
        return False
    if m.src_port is not None and pkt.src_port != m.src_port:
        return False
    if m.dst_port is not None and pkt.dst_port != m.dst_port:
        return False
    if m.proto and pkt.proto.upper() != m.proto.upper():
        return False
    if m.sni_regex:
        if not pkt.tls_sni or not re.search(m.sni_regex, pkt.tls_sni):
            return False
    if m.host_regex:
        if not pkt.http_host or not re.search(m.host_regex, pkt.http_host):
            return False
    if m.direction and _direction(pkt.src_ip, pkt.dst_ip) != m.direction:
        return False
    return True


@dataclass
class Decision:
    action: Action
    rule: Optional[Rule]


class RuleEngine:
    def __init__(self, rules: Iterable[Rule] | None = None) -> None:
        self._rules: list[Rule] = list(rules or [])

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def replace(self, rules: Iterable[Rule]) -> None:
        self._rules = list(rules)

    def add(self, rule: Rule) -> None:
        # Replace by name if it already exists.
        self._rules = [r for r in self._rules if r.name != rule.name] + [rule]

    def remove(self, name: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.name != name]
        return len(self._rules) != before

    def evaluate(self, pkt: PacketEvent) -> Decision:
        for rule in self._rules:
            if not rule.enabled:
                continue
            if _match(pkt, rule.match):
                return Decision(action=rule.action, rule=rule)
        return Decision(action="allow", rule=None)

    def make_alert(self, pkt: PacketEvent, rule: Rule) -> Alert:
        detail = (
            f"sport={pkt.src_port} dport={pkt.dst_port} bytes={pkt.bytes}"
            f"{' sni=' + pkt.tls_sni if pkt.tls_sni else ''}"
            f"{' host=' + pkt.http_host if pkt.http_host else ''}"
        )
        return Alert(
            ts=pkt.ts,
            rule=rule.name,
            severity=rule.severity,
            src_ip=pkt.src_ip,
            dst_ip=pkt.dst_ip,
            proto=pkt.proto,
            detail=detail.strip(),
        )

    def to_yaml(self) -> str:
        return yaml.safe_dump(
            {"rules": [r.model_dump(exclude_none=False) for r in self._rules]},
            sort_keys=False,
        )

    @classmethod
    def from_yaml(cls, text: str) -> "RuleEngine":
        data = yaml.safe_load(text) or {}
        rules = [Rule.model_validate(r) for r in data.get("rules", [])]
        return cls(rules)

    @classmethod
    def from_file(cls, path: str | Path) -> "RuleEngine":
        p = Path(path)
        if not p.exists():
            return cls([])
        return cls.from_yaml(p.read_text(encoding="utf-8"))

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.to_yaml(), encoding="utf-8")
