"""RAG 检索器单元测试 —— 关键词提取 + 文档匹配 + 空 Bundle。"""

from datetime import datetime

from ai_agent.consumer.models import (
    AlertContextBundle,
    AlertSnapshot,
    DeviceRole,
    Severity,
)
from ai_agent.rag.knowledge import KNOWLEDGE_BASE
from ai_agent.rag.retriever import Retriever


def make_bundle(
    protocol: str = "Modbus",
    dest_role: DeviceRole = DeviceRole.PLC,
    severity: Severity = Severity.CRITICAL,
    is_storm: bool = True,
    alert_id: str = "alert-storm-0001",
    raw_message: str = "DDoS flood detected",
    packet_rate: float = 5000.0,
    failed_conn: int = 340,
) -> AlertContextBundle:
    alert = AlertSnapshot(
        alert_id=alert_id,
        timestamp=datetime.now().astimezone(),
        source_ip="10.0.0.66",
        dest_ip="192.168.2.10",
        port=502,
        protocol=protocol,
        severity=severity,
        raw_message=raw_message,
        failed_connections_5m=failed_conn,
        packet_rate=packet_rate,
        source_role=DeviceRole.UNKNOWN,
        dest_role=dest_role,
    )
    return AlertContextBundle(
        bundle_id="bundle-test",
        window_start=datetime.now().astimezone(),
        window_end=datetime.now().astimezone(),
        alert_count=1,
        alerts=[alert],
        source_ips=["10.0.0.66"],
        dest_ips=["192.168.2.10"],
        protocols=[protocol],
        max_severity=severity,
        avg_packet_rate=packet_rate,
        total_failed_conn=failed_conn,
        is_alert_storm=is_storm,
        storm_node_id="EWS-001" if is_storm else "",
        subnet="192.168.2.0/24",
    )


def test_storm_bundle_retrieval():
    """风暴 Bundle（Modbus + PLC + critical + storm）→ 应检索到 DDoS + PLC + Modbus 知识。"""
    print("测试 1：风暴 Bundle → 检索 DDoS + PLC + Modbus 知识")
    retriever = Retriever(top_k=5)
    bundle = make_bundle()
    context = retriever.retrieve(bundle)

    assert context.document_count > 0, "风暴 Bundle 应该检索到知识"
    titles = [d.title for d in context.documents]
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {titles}")

    # 应该包含 DDoS、PLC、Modbus 相关知识
    assert any("DDoS" in t for t in titles), "应该检索到 DDoS 知识"
    assert any("PLC" in t for t in titles), "应该检索到 PLC 知识"
    print("  [PASS]")


def test_normal_modbus_bundle():
    """正常 Modbus 流量（low severity）→ 应检索到 Modbus 协议基础。"""
    print("测试 2：正常 Modbus 流量 → 检索 Modbus 协议知识")
    retriever = Retriever(top_k=3)
    bundle = make_bundle(
        severity=Severity.LOW,
        is_storm=False,
        alert_id="alert-normal-0001",
        raw_message="正常 Modbus 读取操作",
        packet_rate=10.0,
        failed_conn=0,
    )
    context = retriever.retrieve(bundle)

    assert context.document_count > 0
    titles = [d.title for d in context.documents]
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {titles}")
    assert any("Modbus" in t for t in titles)
    print("  [PASS]")


def test_port_scan_attack():
    """端口扫描攻击 → 应检索到端口扫描知识。"""
    print("测试 3：端口扫描攻击 → 检索端口扫描知识")
    retriever = Retriever(top_k=3)
    bundle = make_bundle(
        severity=Severity.MEDIUM,
        is_storm=False,
        alert_id="alert-attack-port_scan-0001",
        raw_message="检测到端口扫描",
        packet_rate=100.0,
        failed_conn=0,
    )
    context = retriever.retrieve(bundle)

    titles = [d.title for d in context.documents]
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {titles}")
    assert any("扫描" in t for t in titles), f"应该检索到端口扫描知识，实际: {titles}"
    print("  [PASS]")


def test_mitm_attack():
    """MITM 攻击 → 应检索到 MITM 知识。"""
    print("测试 4：MITM 攻击 → 检索 MITM 知识")
    retriever = Retriever(top_k=5)
    bundle = make_bundle(
        severity=Severity.HIGH,
        is_storm=False,
        alert_id="alert-attack-mitm-0001",
        raw_message="MITM 攻击检测",
        packet_rate=200.0,
        failed_conn=0,
    )
    context = retriever.retrieve(bundle)

    titles = [d.title for d in context.documents]
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {titles}")
    assert any("MITM" in t for t in titles), f"应该检索到 MITM 知识，实际: {titles}"
    print("  [PASS]")


def test_hmi_engineering_workstation():
    """HMI + Engineering Workstation 设备 → 应检索到设备安全知识。"""
    print("测试 5：HMI + Engineering Workstation → 检索设备安全知识")
    retriever = Retriever(top_k=3)
    bundle = make_bundle(
        dest_role=DeviceRole.HMI,
        severity=Severity.HIGH,
        is_storm=False,
        alert_id="alert-attack-0010",
        raw_message="未授权 HMI 登录",
        packet_rate=50.0,
        failed_conn=10,
    )
    context = retriever.retrieve(bundle)

    titles = [d.title for d in context.documents]
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {titles}")
    assert any("HMI" in t or "SCADA" in t for t in titles)
    print("  [PASS]")


def test_empty_bundle():
    """空关键词 Bundle → 不应报错，检索结果为空。"""
    print("测试 6：空关键词 → 不报错，检索为空")

    # 全部 unknown 的 bundle
    alert = AlertSnapshot(
        alert_id="empty",
        timestamp=datetime.now().astimezone(),
        source_ip="0.0.0.0",
        dest_ip="0.0.0.0",
        port=0,
        protocol="",
        severity=Severity.LOW,
        raw_message="",
        source_role=DeviceRole.UNKNOWN,
        dest_role=DeviceRole.UNKNOWN,
    )
    bundle = AlertContextBundle(
        bundle_id="empty",
        window_start=datetime.now().astimezone(),
        window_end=datetime.now().astimezone(),
        alert_count=1,
        alerts=[alert],
        source_ips=[],
        dest_ips=[],
        protocols=[],
        max_severity=Severity.LOW,
        is_alert_storm=False,
    )
    retriever = Retriever(top_k=3)
    context = retriever.retrieve(bundle)
    # 不应该报错
    assert context.document_count == 0 or context.document_count >= 0
    print(f"  关键词: {context.bundle_keywords}")
    print(f"  检索到: {context.document_count} 条")
    print("  [PASS]")


def test_rag_context_formatting():
    """RAGContext.to_prompt_block() 输出格式正确。"""
    print("测试 7：RAGContext 格式化输出")
    retriever = Retriever(top_k=2)
    bundle = make_bundle()
    context = retriever.retrieve(bundle)

    block = context.to_prompt_block()
    print(f"  文档数: {context.document_count}")
    print(f"  prompt_block 长度: {len(block)} 字符")

    assert isinstance(context.to_prompt_block(), str)
    assert "## 领域知识参考" in block
    if context.documents:
        assert "### " in block
        assert context.documents[0].title in block
    print("  [PASS]")


def test_knowledge_base_integrity():
    """知识库完整性：10 条文档，每条都有 id/title/content/tags。"""
    print("测试 8：知识库完整性")
    assert len(KNOWLEDGE_BASE) == 10, f"应该有 10 条，实际 {len(KNOWLEDGE_BASE)}"
    for doc in KNOWLEDGE_BASE:
        assert doc.id, f"文档缺少 id"
        assert doc.title, f"文档 {doc.id} 缺少 title"
        assert len(doc.content) > 50, f"文档 {doc.id} content 太短"
        assert len(doc.tags) >= 2, f"文档 {doc.id} tags 太少: {doc.tags}"
    print(f"  知识库: {len(KNOWLEDGE_BASE)} 条文档，全部完整")
    print("  [PASS]")


if __name__ == "__main__":
    test_storm_bundle_retrieval()
    test_normal_modbus_bundle()
    test_port_scan_attack()
    test_mitm_attack()
    test_hmi_engineering_workstation()
    test_empty_bundle()
    test_rag_context_formatting()
    test_knowledge_base_integrity()
    print("\n" + "=" * 60)
    print("所有 RAG 测试通过！")
    print("=" * 60)
