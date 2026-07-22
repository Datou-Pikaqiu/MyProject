"""RAG 检索器 —— 从 Bundle 提取关键词，匹配知识库文档。

检索策略：关键词标签匹配（轻量级，无需向量数据库）
1. 从 Bundle 提取关键词（协议/设备角色/严重度/攻击类型/风暴等）
2. 用标签索引 O(1) 查找匹配文档
3. 按标签命中数降序排列
4. 返回 Top-K 文档
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ai_agent.rag.knowledge import get_by_tags
from ai_agent.rag.models import RAGContext

if TYPE_CHECKING:
    from ai_agent.consumer.models import AlertContextBundle

DEFAULT_TOP_K = 3


class Retriever:
    """RAG 知识检索器。

    用法：
        retriever = Retriever()
        context = retriever.retrieve(bundle)
        if context.documents:
            print(context)  # "[RAG] 检索到 3 条 (...)"
            print(context.to_prompt_block())  # 注入 prompt 的文本
    """

    def __init__(self, top_k: int = DEFAULT_TOP_K) -> None:
        self.top_k = top_k

    def retrieve(self, bundle: "AlertContextBundle") -> RAGContext:
        """从 Bundle 提取关键词并检索相关知识文档。

        Args:
            bundle: 告警上下文包

        Returns:
            RAGContext（含检索到的文档 + 诊断信息）
        """
        keywords = self._extract_keywords(bundle)

        if not keywords:
            return RAGContext(bundle_keywords=list(keywords), document_count=0)

        # 按标签命中数排序
        all_docs = get_by_tags(sorted(keywords))
        top_docs = all_docs[: self.top_k]

        return RAGContext(
            documents=top_docs,
            bundle_keywords=sorted(keywords),
            document_count=len(top_docs),
        )

    def _extract_keywords(self, bundle: "AlertContextBundle") -> set[str]:
        """从 Bundle 中提取检索关键词。

        提取来源（优先级从高到低）：
        1. 协议（protocols）—— 直接映射到协议知识文档
        2. 风暴检测 —— is_alert_storm → "storm", "ddos"
        3. 设备角色 —— dest_role, source_role（去重）
        4. 严重度 —— max_severity（high/critical 更倾向检索攻击知识）
        5. 攻击类型推断 —— 从 alert_id 模式推断
        6. 告警数量特征 —— high packet_rate → "flood"
        """
        keywords: set[str] = set()

        # 1. 协议（如 "modbus", "dnp3", "iec104"）
        for protocol in bundle.protocols:
            proto_lower = protocol.lower().strip()
            if proto_lower:
                keywords.add(proto_lower)

        # 2. 告警风暴 → "storm", "ddos"
        if bundle.is_alert_storm:
            keywords.add("storm")
            keywords.add("ddos")
            keywords.add("alert_storm")

        # 3. 设备角色（从 alerts 提取，去重）
        for alert in bundle.alerts:
            role = alert.dest_role.value.lower().replace(" ", "_")
            keywords.add(role)
            role_src = alert.source_role.value.lower().replace(" ", "_")
            keywords.add(role_src)

        # 4. 严重度
        sev = bundle.max_severity.value
        keywords.add(sev)
        if sev in ("critical", "high"):
            keywords.add("escalate")

        # 5. 攻击类型推断（从 alert_id 模式）
        for alert in bundle.alerts:
            aid = alert.alert_id.lower()
            if "port_scan" in aid or "scan" in aid:
                keywords.add("port_scan")
                keywords.add("scanning")
            if "ddos" in aid or "flood" in aid:
                keywords.add("ddos")
                keywords.add("flood")
            if "mitm" in aid:
                keywords.add("mitm")
            if "brute_force" in aid or "credential" in aid:
                keywords.add("brute_force")
                keywords.add("credential_stuffing")
            if "malware" in aid:
                keywords.add("malware")

        # 6. 高包速率 → "flood"
        if bundle.avg_packet_rate > 1000:
            keywords.add("flood")
        if bundle.total_failed_conn > 100:
            keywords.add("critical")

        return keywords
