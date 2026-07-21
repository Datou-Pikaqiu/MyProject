"""消费者数据模型 —— Go/Python 共享契约的 Python 侧定义。

对应 Go 端 go-telemetry/pkg/contract/alert.go。
修改本文件必须同步修改 Go 端的 AlertSnapshot struct。

用 Pydantic v2 而不是 dataclass，原因：
1. 自动 JSON 序列化/反序列化（NATS 收到的字节直接 parse）
2. 类型校验（防止 Go 端传错字段类型）
3. 后续 LLM JSON Mode 输出可直接用 Pydantic 校验（verifier 层会用到）
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """告警严重度。用 Enum 防止拼写错误，str Enum 让 JSON 序列化为字符串。"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeviceRole(str, Enum):
    """电网设备角色（提案第4节"设备状态"）。

    影响分诊优先级：攻击 PLC 比攻击普通 workstation 严重得多。
    """

    PLC = "PLC"                        # 可编程逻辑控制器——直接控制物理设备，最高优先级
    HMI = "HMI"                        # 人机交互界面
    SCADA = "SCADA"                    # 数据采集与监控系统
    ENGINEERING_WORKSTATION = "Engineering Workstation"  # 工程师站
    UNKNOWN = "Unknown"


class AlertSnapshot(BaseModel):
    """告警上下文快照——Go 端发给 Python 端的核心数据契约。

    对应提案第4节"可供 LLM 使用的网络和设备证据"。
    字段分四组：基础元数据 / 上下文特征 / 设备状态 / 拓扑信息。
    """

    # === 基础元数据 ===
    alert_id: str
    timestamp: datetime
    source_ip: str
    dest_ip: str
    port: int
    protocol: str = Field(description="工业协议：Modbus / DNP3 / IEC104 等")
    severity: Severity
    raw_message: str = Field(description="原始告警文本，后续 sanitizer 要做注入防护")

    # === 上下文特征 ===
    failed_connections_5m: int = Field(default=0, description="过去5分钟连接失败次数")
    abnormal_payload_len: int = Field(default=0, description="异常载荷长度（字节），0 表示无异常")
    packet_rate: float = Field(default=0.0, description="当前包速率（pps）")

    # === 设备状态 ===
    source_role: DeviceRole = Field(default=DeviceRole.UNKNOWN)
    dest_role: DeviceRole = Field(default=DeviceRole.UNKNOWN)

    # === 拓扑信息 ===
    node_id: str = Field(default="", description="节点唯一标识")
    subnet: str = Field(default="", description="子网段，如 192.168.1.0/24")

    @property
    def subject(self) -> str:
        """该告警应该发布到的 NATS subject：alerts.<severity>。"""
        return f"alerts.{self.severity.value}"


class AlertContextBundle(BaseModel):
    """告警上下文包——时窗聚合后的产物。

    对应 Go 端 go-telemetry/pkg/contract/bundle.go。
    Go 端把一个时间窗口内的多条告警打包成一个 Bundle 发过来，
    避免 100 条告警逐条冲垮 LLM。

    LLM 收到 Bundle 后能看到完整上下文：
    - 过去 N 秒内收到了多少条告警
    - 涉及哪些 IP / 协议
    - 最高严重度 / 是否是告警风暴
    - 风暴中心节点（根因分析线索）
    """

    bundle_id: str
    window_start: datetime
    window_end: datetime
    alert_count: int

    # 窗口内的告警列表
    alerts: list[AlertSnapshot]

    # 去重后的统计信息
    source_ips: list[str]
    dest_ips: list[str]
    protocols: list[str]
    max_severity: Severity
    avg_packet_rate: float = Field(default=0.0, description="平均包速率")
    total_failed_conn: int = Field(default=0, description="总连接失败次数")

    # 告警风暴检测（提案核心创新点）
    is_alert_storm: bool = Field(default=False, description="告警数 >= 阈值时为 true")
    storm_node_id: str = Field(default="", description="风暴中心节点")
    subnet: str = Field(default="", description="主要子网")

    @property
    def subject(self) -> str:
        """该 Bundle 应该发布到的 NATS subject：alerts.bundle.<max_severity>。"""
        return f"alerts.bundle.{self.max_severity.value}"
