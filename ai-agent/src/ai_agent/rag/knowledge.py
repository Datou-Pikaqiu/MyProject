"""RAG 知识库 —— 电网安全运营领域知识文档。

每条文档含领域知识 + 标签（用于关键词匹配检索）。
后续可扩展：嵌入向量 + ChromaDB 替代简单标签匹配。
"""

from __future__ import annotations

from ai_agent.rag.models import KnowledgeDocument

# ============================================================
# 知识库（10 条，覆盖协议/设备/攻击/处置四大类）
# ============================================================

KNOWLEDGE_BASE: list[KnowledgeDocument] = [
    # === 工业协议 ===
    KnowledgeDocument(
        id="modbus_basics",
        title="Modbus 协议基础",
        content=(
            "Modbus 是工业控制系统（ICS）中最广泛使用的串行通信协议，"
            "默认端口 502。它采用主从架构，主站（master）向从站（slave）"
            "发送请求，从站响应。Modbus 没有内置认证和加密——任何连接到"
            "网络的设备都可以读写寄存器。因此，未授权的 Modbus 写入操作"
            "（如修改线圈状态或保持寄存器）是严重的安全事件，可能导致"
            "PLC 执行恶意指令、设备停机或物理损坏。"
        ),
        tags=["modbus", "protocol", "port_502", "plc", "ics"],
    ),
    KnowledgeDocument(
        id="dnp3_basics",
        title="DNP3 协议基础",
        content=(
            "DNP3（分布式网络协议 3）是电力行业专用的 SCADA 通信协议，"
            "默认端口 20000。相比 Modbus，DNP3 支持时间戳、数据分级和"
            "主动上报（unsolicited response）。但 DNP3 同样缺乏强认证——"
            "攻击者可以通过伪造 DNP3 报文实现对变电站 RTU 的远程控制。"
            "DNP3 的 secure authentication 扩展（SAv5）提供了挑战-响应"
            "认证，但实际部署率很低。"
        ),
        tags=["dnp3", "protocol", "scada", "substation", "rtu"],
    ),
    KnowledgeDocument(
        id="iec104_basics",
        title="IEC 60870-5-104 协议基础",
        content=(
            "IEC 60870-5-104（IEC104）是电力远动通信的国际标准，"
            "运行在 TCP/IP 上，默认端口 2404。广泛用于调度中心和变电站"
            "之间的遥测、遥信数据传输。IEC104 协议本身不提供加密和认证，"
            "明文传输控制指令。攻击者可以通过中间人攻击（MITM）拦截和"
            "篡改 IEC104 报文，伪造遥控命令导致断路器误动作。"
        ),
        tags=["iec104", "protocol", "scada", "substation", "telecontrol"],
    ),

    # === 设备安全 ===
    KnowledgeDocument(
        id="plc_security",
        title="PLC 安全防护",
        content=(
            "PLC（可编程逻辑控制器）是工业控制系统的核心执行设备，"
            "直接控制物理过程（如电机启停、阀门开关、泵速调节）。"
            "PLC 被攻击的后果极其严重——可能导致设备损坏、生产停产、"
            "甚至人员伤亡。电网场景中，PLC 控制断路器、变压器分接头、"
            "电容器组等关键设备。对 PLC 的任何可疑操作（特别是未授权的"
            "Modbus 写入）应视为 critical 级别，立即隔离并升级到人工。"
        ),
        tags=["plc", "device", "critical", "isolate", "escalate"],
    ),
    KnowledgeDocument(
        id="scada_hmi_security",
        title="SCADA 与 HMI 安全",
        content=(
            "SCADA（数据采集与监控系统）和 HMI（人机界面）是电网监控"
            "的核心。SCADA 负责数据汇聚和远程控制，HMI 是操作员的人机"
            "接口。HMI 通常运行 Windows 系统，是常见的攻击入口点——"
            "攻击者通过钓鱼或漏洞利用获取 HMI 控制权后，可以通过 SCADA"
            "向下游 PLC/RTU 发送恶意指令。HMI 的异常登录、进程创建或"
            "网络连接应引起高度警惕。"
        ),
        tags=["scada", "hmi", "device", "workstation", "phishing"],
    ),
    KnowledgeDocument(
        id="engineering_workstation",
        title="工程工作站安全",
        content=(
            "Engineering Workstation（工程站）是用于 PLC 编程、组态"
            "配置、固件更新的专用工作站。它通常拥有对 PLC 的最高权限"
            "（可直接修改控制逻辑）。如果工程站被攻破，攻击者可以向"
            "PLC 注入恶意梯形图逻辑，实现隐蔽的长期控制。工程站的任何"
            "异常行为（如非工作时间的网络活动、未知进程）都应升级。"
        ),
        tags=["engineering_workstation", "device", "plc", "escalate", "insider"],
    ),

    # === 攻击模式 ===
    KnowledgeDocument(
        id="port_scan_ics",
        title="ICS 端口扫描检测",
        content=(
            "端口扫描是攻击者侦察阶段的第一步——探测网络中有哪些设备"
            "和服务。在 ICS 环境中，端口扫描尤其危险因为：1) 部分老旧"
            "PLC 对异常流量极其敏感，扫描本身可能导致设备重启或通信中断；"
            "2) 扫描揭示的开放端口（如 502 Modbus, 20000 DNP3, 2404 IEC104）"
            "直接暴露了工业协议的接入点。短时间内对多个端口或多个 IP 的"
            "扫描行为应归类为 suspicious 或 malicious，不应视为误报。"
        ),
        tags=["port_scan", "attack", "scanning", "reconnaissance"],
    ),
    KnowledgeDocument(
        id="ddos_ics",
        title="ICS DDoS 攻击模式",
        content=(
            "针对 ICS 的 DDoS（分布式拒绝服务）攻击通常表现为短时间内"
            "大量连接请求涌向工业协议端口（Modbus 502、DNP3 20000 等）。"
            "由于 PLC/RTU 的处理能力有限（远低于 IT 服务器），即使是"
            "中等规模的 DDoS 也能导致设备响应超时、通信中断甚至宕机。"
            "告警风暴（同一设备短时间内收到大量 critical 告警）是 DDoS 的"
            "典型特征。处置建议：立即封锁攻击源 IP，必要时隔离受影响设备。"
            "注意区分真实 DDoS 和正常的主站轮询——正常轮询是有规律的"
            "周期性请求，DDoS 是无规律的大量并发请求。"
        ),
        tags=["ddos", "attack", "storm", "flood", "critical", "block"],
    ),
    KnowledgeDocument(
        id="mitm_ics",
        title="工业协议 MITM 攻击",
        content=(
            "中间人攻击（MITM）在 ICS 中表现为攻击者在主站和从站之间"
            "拦截并篡改通信报文。由于 Modbus、DNP3、IEC104 等协议缺"
            "乏加密和认证，MITM 攻击的门槛很低。攻击者可以：1) 篡改"
            "传感器读数，欺骗操作员；2) 修改控制指令，使设备执行危险"
            "操作；3) 注入虚假告警，制造混乱。检测 MITM 的关键特征是"
            "同一连接上出现了矛盾的报文（如同一个 transaction ID 的"
            "请求和响应内容不匹配）。"
        ),
        tags=["mitm", "attack", "protocol", "spoofing", "modbus", "dnp3", "iec104", "critical"],
    ),

    # === 分诊 + 处置 ===
    KnowledgeDocument(
        id="alert_storm_triage",
        title="告警风暴分诊指南",
        content=(
            "告警风暴（Alert Storm）是安全运营中的常见挑战——短时间内"
            "大量告警涌入，可能淹没真正的攻击信号。分诊策略：\n"
            "1. 首先判断是真实攻击还是设备故障——设备故障通常只有一类"
            "告警（如全部是连接超时），攻击通常有多类告警（扫描+暴力"
            "破解+DDoS）；\n"
            "2. 检查告警的源 IP 分布——单一源 IP 可能是误配置，多源 IP"
            "更可能是协同攻击；\n"
            "3. 优先处理涉及 PLC 和安全区 1 设备的告警——这些设备直接"
            "控制物理过程，影响最大；\n"
            "4. 风暴窗口内的告警应聚合分析，不要逐条处理——逐条处理"
            "会浪费分析资源，且看不到攻击全貌。"
        ),
        tags=["storm", "alert_storm", "triage", "ddos", "critical"],
    ),
]

# 标签 → 文档 索引（加速检索，O(1) 查找替代 O(n) 扫描所有文档）
_TAG_INDEX: dict[str, list[KnowledgeDocument]] = {}
for _doc in KNOWLEDGE_BASE:
    for _tag in _doc.tags:
        _TAG_INDEX.setdefault(_tag, []).append(_doc)


def get_by_id(doc_id: str) -> KnowledgeDocument | None:
    """按 ID 获取知识文档。"""
    for doc in KNOWLEDGE_BASE:
        if doc.id == doc_id:
            return doc
    return None


def get_by_tags(tags: list[str]) -> list[KnowledgeDocument]:
    """按标签检索文档（去重，按标签命中数排序）。"""
    scored: dict[str, tuple[KnowledgeDocument, int]] = {}
    for tag in tags:
        for doc in _TAG_INDEX.get(tag, []):
            if doc.id not in scored:
                scored[doc.id] = (doc, 0)
            _, count = scored[doc.id]
            scored[doc.id] = (doc, count + 1)

    # 按命中数降序排列
    sorted_docs = sorted(scored.values(), key=lambda x: x[1], reverse=True)
    return [doc for doc, _ in sorted_docs]
