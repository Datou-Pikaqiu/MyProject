"""LLM 分诊报告模型 —— DeepSeek API 的结构化输出契约。

对应提案第5节"证据接地的 LLM 分诊"。
LLM 接收 AlertContextBundle，输出 TriageReport（JSON）。

这是论文创新点1（双重校验）的基础：
- LLM 输出 JSON（这里定义的结构）
- Python verifier 用硬编码强匹配验证 evidence 的真实性（Sprint 3 实现）
- 不匹配则弃权（0 幻觉机制）

设计原则：
1. 所有字段都是枚举或基本类型 —— LLM 容易遵守，Pydantic 严格校验
2. evidence 要求引用 Bundle 里的具体字段值 —— verifier 能硬编码匹配
3. confidence 限制 0.0-1.0 —— 防止 LLM 输出 95% 这种百分比
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class TriageClassification(str, Enum):
    """分诊分类 —— LLM 对 Bundle 的总体判断。

    从 false_positive 到 malicious 是递进的严重程度。
    """

    FALSE_POSITIVE = "false_positive"  # 误报：正常流量被误判为告警
    BENIGN = "benign"  # 良性：真实告警但无威胁（如计划内维护）
    SUSPICIOUS = "suspicious"  # 可疑：异常行为，但不足以确认攻击
    MALICIOUS = "malicious"  # 恶意：确认是攻击


class AttackType(str, Enum):
    """攻击类型 —— 当 classification 为 suspicious/malicious 时填写。

    覆盖提案第3节提到的5种攻击 + 扩展类型。
    非攻击场景填 none。
    """

    PORT_SCAN = "port_scan"  # 端口扫描（合成数据里的 port_scan_*）
    DDOS = "ddos"  # 分布式拒绝服务（告警风暴的典型成因）
    MITM = "mitm"  # 中间人攻击
    CREDENTIAL_STUFFING = "credential_stuffing"  # 凭证填充
    BRUTE_FORCE = "brute_force"  # 暴力破解
    MALWARE = "malware"  # 恶意软件
    INSIDER = "insider"  # 内部威胁
    UNKNOWN = "unknown"  # 未知攻击（无法归类）
    NONE = "none"  # 非攻击（classification 为 false_positive/benign 时）


class RecommendedAction(str, Enum):
    """处置建议 —— LLM 推荐的响应动作。

    从 ignore 到 escalate 是递进的响应强度。
    """

    IGNORE = "ignore"  # 忽略（确认误报或良性）
    MONITOR = "monitor"  # 持续监控（可疑但不紧急）
    ISOLATE = "isolate"  # 隔离设备（断网但不关机，保留取证）
    BLOCK = "block"  # 封锁源 IP（防火墙规则）
    ESCALATE = "escalate"  # 升级到人工处理（需 SOC 分析师介入）


class TriageReport(BaseModel):
    """LLM 分诊报告 —— DeepSeek API 的 JSON Mode 输出结构。

    LLM 接收 AlertContextBundle，返回此结构。
    后续 verifier 会用硬编码规则验证 evidence 的真实性（Sprint 3）。

    字段说明：
    - bundle_id：用于追溯，verifier 会检查是否和输入 Bundle 一致
    - evidence：必须引用 Bundle 里的具体字段值，如 "source_ip=10.0.0.66 出现 4 次"
      verifier 会检查这些值是否真的在 Bundle 里出现过（防幻觉）
    - severity_override：null 表示认可 Bundle 的 max_severity；
      非 null 表示 LLM 认为严重度判断不准，给出建议值
    """

    bundle_id: str = Field(description="对应的 Bundle ID，用于追溯")
    classification: TriageClassification = Field(description="总体分类判断")
    confidence: float = Field(
        ge=0.0, le=1.0, description="置信度，范围 0.0-1.0（不是百分比）"
    )
    attack_type: AttackType = Field(
        description="攻击类型；非攻击场景填 none"
    )
    reasoning: str = Field(
        description="推理链：为什么这么判断（2-3 句话，说明关键依据）"
    )
    evidence: list[str] = Field(
        description=(
            "证据列表，每条引用 Bundle 里的具体字段值，"
            "如 'source_ip=10.0.0.66 出现 4 次' 或 'total_failed_conn=2910'"
        )
    )
    recommended_action: RecommendedAction = Field(description="推荐处置动作")
    severity_override: str | None = Field(
        default=None,
        description=(
            "如果 LLM 认为 Bundle 的 max_severity 不准确，给出覆盖建议值"
            "（low/medium/high/critical）；否则 null"
        ),
    )
