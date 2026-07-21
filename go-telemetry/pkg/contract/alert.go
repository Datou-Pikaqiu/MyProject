// Package contract 定义 Go/Python 之间共享的数据契约。
//
// 这是整个系统的核心：Go 端产生的告警快照通过 JSON 序列化后经由 NATS 传给 Python 端。
// 修改这里的结构体必须同步修改 ai-agent/src/ai_agent/consumer/models.py。
package contract

import "time"

// AlertSnapshot 是 Go 端发给 Python 端的"告警上下文快照"。
//
// 对应提案第 4 节"可供 LLM 使用的网络和设备证据"。
// 字段分四组：基础元数据 / 上下文特征 / 设备状态 / 拓扑信息。
type AlertSnapshot struct {
	// === 基础元数据 ===
	AlertID    string    `json:"alert_id"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`    // Modbus / DNP3 / IEC104 / ...
	Severity   string    `json:"severity"`    // low / medium / high / critical
	RawMessage string    `json:"raw_message"` // 原始告警文本（后续 sanitizer 要做注入防护）

	// === 上下文特征（提案第4节）===
	// 让 LLM 理解"这个 IP 最近行为是否异常"
	FailedConnections5m int     `json:"failed_connections_5m"` // 过去5分钟连接失败次数
	AbnormalPayloadLen  int     `json:"abnormal_payload_len"`  // 异常载荷长度（字节），0 表示无异常
	PacketRate          float64 `json:"packet_rate"`           // 当前包速率（pps）

	// === 设备状态（提案第4节）===
	// 让 LLM 理解"被攻击的是 PLC 还是普通主机"——影响分诊优先级
	SourceRole string `json:"source_role"` // 源设备角色：PLC / HMI / SCADA / Engineering Workstation / Unknown
	DestRole   string `json:"dest_role"`   // 目的设备角色

	// === 拓扑信息（为 Sprint 3 根因分析铺垫）===
	// 让 LLM 理解电网网络拓扑，识别"主因告警"vs"衍生告警"
	NodeID string `json:"node_id"` // 节点唯一标识
	Subnet string `json:"subnet"`  // 子网段，如 "192.168.1.0/24"
}

// Severity 级别常量，避免拼写错误。
const (
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Subject 返回该告警应该发布到的 NATS subject。
// 规范：alerts.<severity>，Python 端用 alerts.* 通配订阅。
func (a AlertSnapshot) Subject() string {
	return "alerts." + a.Severity
}
