from app.filters.engine import RuleEngine
from app.models import PacketEvent, Rule, RuleMatch


def _pkt(**overrides) -> PacketEvent:
    base = dict(
        ts=1.0,
        src_ip="10.0.1.5",
        dst_ip="8.8.8.8",
        src_port=44321,
        dst_port=443,
        proto="TLS",
        bytes=512,
        tls_sni="example.com",
    )
    base.update(overrides)
    return PacketEvent(**base)


def test_default_action_is_allow():
    engine = RuleEngine([])
    assert engine.evaluate(_pkt()).action == "allow"


def test_first_match_wins():
    engine = RuleEngine(
        [
            Rule(name="alert-tls", action="alert", match=RuleMatch(proto="TLS")),
            Rule(name="drop-everything", action="drop", match=RuleMatch()),
        ]
    )
    decision = engine.evaluate(_pkt())
    assert decision.action == "alert"
    assert decision.rule is not None and decision.rule.name == "alert-tls"


def test_cidr_and_port_match():
    engine = RuleEngine(
        [Rule(name="r", action="drop", match=RuleMatch(src_cidr="10.0.0.0/8", dst_port=443))]
    )
    assert engine.evaluate(_pkt()).action == "drop"
    assert engine.evaluate(_pkt(dst_port=80)).action == "allow"
    assert engine.evaluate(_pkt(src_ip="172.16.0.1")).action == "allow"


def test_sni_regex():
    engine = RuleEngine(
        [Rule(name="block-evil", action="drop", match=RuleMatch(sni_regex=r"evil\.com$"))]
    )
    assert engine.evaluate(_pkt(tls_sni="evil.com")).action == "drop"
    assert engine.evaluate(_pkt(tls_sni="good.com")).action == "allow"


def test_direction_match():
    engine = RuleEngine(
        [Rule(name="ext-only", action="alert", match=RuleMatch(direction="outbound"))]
    )
    # 10.x.x.x -> 8.8.8.8 = outbound
    assert engine.evaluate(_pkt()).action == "alert"
    # 10.x -> 10.x = internal, should not match
    assert engine.evaluate(_pkt(dst_ip="10.0.1.10")).action == "allow"


def test_disabled_rule_is_skipped():
    engine = RuleEngine(
        [Rule(name="r", action="drop", match=RuleMatch(), enabled=False)]
    )
    assert engine.evaluate(_pkt()).action == "allow"


def test_yaml_round_trip():
    engine = RuleEngine(
        [Rule(name="r", action="alert", match=RuleMatch(proto="TLS"))]
    )
    text = engine.to_yaml()
    rebuilt = RuleEngine.from_yaml(text)
    assert [r.name for r in rebuilt.rules] == ["r"]
    assert rebuilt.evaluate(_pkt()).action == "alert"
