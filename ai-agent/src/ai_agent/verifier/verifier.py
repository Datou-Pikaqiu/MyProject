"""声明验证器 —— 论文核心创新点1（双重校验）。

第二层校验：用硬编码强匹配验证 LLM evidence 的真实性。

验证流程：
1. LLM 输出 TriageReport，其中 evidence 列表每条格式 "字段名=值"
2. verifier 逐条解析 evidence
3. 先查 Bundle 顶层字段（如 alert_count, is_alert_storm）
4. 如果顶层没有，查 Alert 子字段（如 failed_connections_5m, raw_message）
5. 值匹配支持 6 种类型：bool / int / float / str Enum / list / str
6. 全部匹配 → is_valid=True；有不匹配 → is_valid=False（弃权）

为什么叫"硬编码强匹配"：
- 不是语义相似度匹配（LLM 可能说"大概相等"）
- 是精确的值比较（"10" == 10, "true" == True）
- LLM 编造的值（如 total_failed_conn=99999）会被精确检测到

这是论文区别于普通 LLM 应用的核心差异点：
- 传统 LLM 应用：直接信任输出
- 本系统：LLM 输出 + verifier 硬编码验证 = 双重校验
- 不匹配则弃权 = 0 幻觉机制
"""

from __future__ import annotations

import json
from enum import Enum
from typing import TYPE_CHECKING, Any

from ai_agent.verifier.models import VerificationResult

if TYPE_CHECKING:
    from ai_agent.consumer.models import AlertContextBundle
    from ai_agent.llm.models import TriageReport


# float 比较容差（LLM 可能输出略有精度损失的浮点数）
FLOAT_TOLERANCE = 0.01


class Verifier:
    """声明验证器 —— 硬编码强匹配 LLM evidence。

    用法：
        verifier = Verifier()
        result = verifier.verify(report, bundle)
        if result.is_valid:
            print("报告可信，输出")
        else:
            print(f"检测到幻觉，弃权: {result.mismatched}")
    """

    def verify(
        self, report: "TriageReport", bundle: "AlertContextBundle"
    ) -> VerificationResult:
        """验证 TriageReport 的 evidence 是否真实存在于 AlertContextBundle 中。

        Args:
            report: LLM 输出的分诊报告
            bundle: 对应的告警上下文包（真相来源）

        Returns:
            VerificationResult：包含 is_valid / matched / mismatched
        """
        matched: list[str] = []
        mismatched: list[str] = []

        for evidence_str in report.evidence:
            if self._verify_evidence(evidence_str, bundle):
                matched.append(evidence_str)
            else:
                mismatched.append(evidence_str)

        total = len(report.evidence)
        match_rate = len(matched) / total if total > 0 else 0.0

        return VerificationResult(
            is_valid=len(mismatched) == 0,
            matched=matched,
            mismatched=mismatched,
            bundle_id=bundle.bundle_id,
            total_evidence=total,
            match_rate=match_rate,
        )

    def _verify_evidence(
        self, evidence: str, bundle: "AlertContextBundle"
    ) -> bool:
        """验证单条 evidence 字符串。

        evidence 格式："字段名=值"
        查找顺序：
        1. Bundle 顶层字段（alert_count, is_alert_storm, source_ips 等）
        2. Alert 子字段（failed_connections_5m, raw_message 等）
           —— 遍历 alerts 列表，任一条匹配即可

        Args:
            evidence: evidence 字符串，如 "total_failed_conn=2910"
            bundle: 告警上下文包

        Returns:
            True=匹配，False=不匹配或格式错误
        """
        # 解析 "字段名=值"（只分割第一个 =，值可能包含 =）
        parts = evidence.split("=", 1)
        if len(parts) != 2:
            return False  # 格式不对（没有 =）

        field_name = parts[0].strip()
        expected_str = parts[1].strip()

        if not field_name or not expected_str:
            return False  # 空字段名或空值

        # 1. 尝试 Bundle 顶层字段
        if hasattr(bundle, field_name):
            actual = getattr(bundle, field_name)
            return self._match_value(expected_str, actual)

        # 2. 尝试 Alert 子字段（检查 alerts 列表里是否有任何一条匹配）
        for alert in bundle.alerts:
            if hasattr(alert, field_name):
                actual = getattr(alert, field_name)
                if self._match_value(expected_str, actual):
                    return True

        # 3. 字段名在 Bundle 和 Alert 中都不存在
        return False

    def _match_value(self, expected_str: str, actual: Any) -> bool:
        """匹配期望值字符串和实际值。

        支持 6 种类型：
        - bool: "true" → True（必须先检查，因为 bool 是 int 的子类）
        - str Enum: "critical" → Severity.CRITICAL（取 .value 比较）
        - int: "10" → 10
        - float: "4645.55" → 4645.55（容差比较）
        - list: '["10.0.0.66"]' → ["10.0.0.66", ...]（子集匹配）
        - str: "正常 Modbus" → "正常 Modbus 读取操作"（包含匹配）

        Args:
            expected_str: evidence 里的值字符串
            actual: Bundle/Alert 里的实际值

        Returns:
            True=匹配，False=不匹配
        """
        # 1. bool（必须先检查，因为 bool 是 int 的子类）
        if isinstance(actual, bool):
            return expected_str.lower() == str(actual).lower()

        # 2. str Enum（Severity, DeviceRole 等）
        if isinstance(actual, Enum):
            return expected_str == str(actual.value)

        # 3. int
        if isinstance(actual, int):
            try:
                return int(expected_str) == actual
            except ValueError:
                return False

        # 4. float
        if isinstance(actual, float):
            try:
                return abs(float(expected_str) - actual) < FLOAT_TOLERANCE
            except ValueError:
                return False

        # 5. list（如 source_ips, dest_ips）
        if isinstance(actual, list):
            try:
                expected_list = json.loads(expected_str)
                if isinstance(expected_list, list):
                    # 检查 expected_list 是否是 actual 的子集
                    # （LLM 可能只列出部分 IP，不需要完全匹配）
                    return all(item in actual for item in expected_list)
            except (json.JSONDecodeError, TypeError):
                return False

        # 6. str（如 raw_message, protocol, subnet）
        if isinstance(actual, str):
            # 精确匹配 或 包含关系（LLM 可能截断长文本）
            return expected_str == actual or expected_str in actual

        # 其他类型（datetime 等）—— 用字符串比较
        return expected_str == str(actual)
