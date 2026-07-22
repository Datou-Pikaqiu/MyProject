"""verifier 快速验证脚本 —— 测试正常 evidence + 幻觉检测。"""

from datetime import datetime

from ai_agent.consumer.models import (
    AlertContextBundle,
    AlertSnapshot,
    DeviceRole,
    Severity,
)
from ai_agent.llm.models import (
    AttackType,
    RecommendedAction,
    TriageClassification,
    TriageReport,
)
from ai_agent.verifier.verifier import Verifier


def make_test_bundle() -> AlertContextBundle:
    """构造一个模拟的风暴 Bundle（类似 Day 4 的 Bundle #41）。"""
    alert = AlertSnapshot(
        alert_id="alert-storm-0001",
        timestamp=datetime.now().astimezone(),
        source_ip="10.0.0.66",
        dest_ip="192.168.2.10",
        port=502,
        protocol="Modbus",
        severity=Severity.CRITICAL,
        raw_message="检测到端口扫描：顺序探测大量端口 1-1024",
        failed_connections_5m=340,
        abnormal_payload_len=0,
        packet_rate=5000.0,
        source_role=DeviceRole.UNKNOWN,
        dest_role=DeviceRole.HMI,
        node_id="EWS-001",
        subnet="192.168.2.0/24",
    )
    return AlertContextBundle(
        bundle_id="bundle-test-storm",
        window_start=datetime.now().astimezone(),
        window_end=datetime.now().astimezone(),
        alert_count=10,
        alerts=[alert],
        source_ips=["10.0.0.66", "10.0.0.99", "172.16.5.100", "203.0.113.50"],
        dest_ips=["192.168.1.100", "192.168.2.10"],
        protocols=["Modbus"],
        max_severity=Severity.CRITICAL,
        avg_packet_rate=4645.56,
        total_failed_conn=2910,
        is_alert_storm=True,
        storm_node_id="EWS-001",
        subnet="192.168.2.0/24",
    )


def test_normal_evidence():
    """测试 1：所有 evidence 都真实 → 应该全部匹配，is_valid=True。"""
    print("=" * 60)
    print("测试 1：正常 evidence（全部真实）")
    print("=" * 60)

    bundle = make_test_bundle()
    report = TriageReport(
        bundle_id="bundle-test-storm",
        classification=TriageClassification.MALICIOUS,
        confidence=0.95,
        attack_type=AttackType.DDOS,
        reasoning="告警风暴，DDoS 攻击",
        evidence=[
            "is_alert_storm=true",
            "alert_count=10",
            "max_severity=critical",
            "total_failed_conn=2910",
            "avg_packet_rate=4645.56",
            'source_ips=["10.0.0.66","10.0.0.99"]',
            "failed_connections_5m=340",
            "dest_role=HMI",
        ],
        recommended_action=RecommendedAction.BLOCK,
    )

    verifier = Verifier()
    result = verifier.verify(report, bundle)

    print(f"  is_valid:     {result.is_valid}")
    print(f"  matched:      {len(result.matched)}/{result.total_evidence}")
    print(f"  mismatched:   {len(result.mismatched)}")
    print(f"  match_rate:   {result.match_rate:.2f}")
    for m in result.matched:
        print(f"    [OK] {m}")
    if result.mismatched:
        for m in result.mismatched:
            print(f"    [!] {m}")

    assert result.is_valid, "正常 evidence 应该全部匹配！"
    assert len(result.mismatched) == 0
    print("\n  [PASS] 测试 1 通过\n")


def test_hallucination():
    """测试 2：故意构造幻觉 evidence → 应该检测到，is_valid=False。"""
    print("=" * 60)
    print("测试 2：幻觉 evidence（故意编造）")
    print("=" * 60)

    bundle = make_test_bundle()
    report = TriageReport(
        bundle_id="bundle-test-storm",
        classification=TriageClassification.MALICIOUS,
        confidence=0.95,
        attack_type=AttackType.DDOS,
        reasoning="告警风暴",
        evidence=[
            "is_alert_storm=true",          # 真实
            "alert_count=10",               # 真实
            "total_failed_conn=99999",      # 幻觉！实际是 2910
            "max_severity=low",             # 幻觉！实际是 critical
            "nonexistent_field=abc",        # 幻觉！字段不存在
            'source_ips=["999.999.999.999"]',  # 幻觉！IP 不在列表里
        ],
        recommended_action=RecommendedAction.BLOCK,
    )

    verifier = Verifier()
    result = verifier.verify(report, bundle)

    print(f"  is_valid:     {result.is_valid}")
    print(f"  matched:      {len(result.matched)}/{result.total_evidence}")
    print(f"  mismatched:   {len(result.mismatched)}")
    print(f"  match_rate:   {result.match_rate:.2f}")
    for m in result.matched:
        print(f"    [OK] {m}")
    for m in result.mismatched:
        print(f"    [!] 幻觉: {m}")

    assert not result.is_valid, "有幻觉 evidence 不应该通过验证！"
    assert len(result.mismatched) == 4, f"应该有 4 个幻觉，实际 {len(result.mismatched)}"
    print("\n  [PASS] 测试 2 通过\n")


def test_edge_cases():
    """测试 3：边缘情况。"""
    print("=" * 60)
    print("测试 3：边缘情况")
    print("=" * 60)

    bundle = make_test_bundle()
    verifier = Verifier()

    # 空 evidence
    report_empty = TriageReport(
        bundle_id="bundle-test-storm",
        classification=TriageClassification.BENIGN,
        confidence=0.9,
        attack_type=AttackType.NONE,
        reasoning="无威胁",
        evidence=[],
        recommended_action=RecommendedAction.IGNORE,
    )
    result_empty = verifier.verify(report_empty, bundle)
    print(f"  空 evidence: is_valid={result_empty.is_valid}, total={result_empty.total_evidence}")
    assert result_empty.is_valid, "空 evidence 应该通过（没有幻觉）"

    # 格式错误的 evidence
    report_bad = TriageReport(
        bundle_id="bundle-test-storm",
        classification=TriageClassification.BENIGN,
        confidence=0.9,
        attack_type=AttackType.NONE,
        reasoning="无威胁",
        evidence=["没有等号的evidence", "alert_count=10"],
        recommended_action=RecommendedAction.IGNORE,
    )
    result_bad = verifier.verify(report_bad, bundle)
    print(f"  格式错误: is_valid={result_bad.is_valid}, mismatched={result_bad.mismatched}")
    assert not result_bad.is_valid, "格式错误的 evidence 不应该通过"

    print("\n  [PASS] 测试 3 通过\n")


if __name__ == "__main__":
    test_normal_evidence()
    test_hallucination()
    test_edge_cases()
    print("=" * 60)
    print("所有测试通过！verifier 核心逻辑验证成功。")
    print("=" * 60)
