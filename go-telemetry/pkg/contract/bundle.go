package contract

import "time"

// AlertContextBundle 是时窗聚合后的"告警上下文包"。
//
// 提案第 1 节"时序窗口聚合"的产物：Go 端把一个时间窗口内的多条告警
// 打包成一个 Bundle 发给 Python，避免告警风暴时逐条冲垮 LLM。
//
// LLM 收到 Bundle 后能看到完整上下文：
//   - 过去 N 秒内收到了多少条告警
//   - 涉及哪些 IP / 协议
//   - 最高严重度 / 是否是告警风暴
//   - 风暴中心节点（根因分析线索）
type AlertContextBundle struct {
	BundleID    string    `json:"bundle_id"`
	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
	AlertCount  int       `json:"alert_count"`

	// 窗口内的告警列表（按时间排序）
	// 注意：风暴场景下可能很多条，LLM 上下文窗口有限，后续可截断
	Alerts []AlertSnapshot `json:"alerts"`

	// 去重后的统计信息（让 LLM 快速理解上下文，不用读每条告警）
	SourceIPs       []string `json:"source_ips"`
	DestIPs         []string `json:"dest_ips"`
	Protocols       []string `json:"protocols"`
	MaxSeverity     string   `json:"max_severity"`      // 窗口内最高严重度
	AvgPacketRate   float64  `json:"avg_packet_rate"`   // 平均包速率
	TotalFailedConn int      `json:"total_failed_conn"` // 总连接失败次数

	// 告警风暴检测（提案核心创新点）
	IsAlertStorm bool   `json:"is_alert_storm"`  // 告警数 >= 阈值时为 true
	StormNodeID  string `json:"storm_node_id"`   // 风暴中心节点（被攻击最多的目的 IP 对应的 node_id）
	Subnet       string `json:"subnet"`          // 主要子网
}

// Subject 返回 Bundle 应该发布到的 NATS subject。
// 规范：alerts.bundle.<max_severity>
// Python 端用 alerts.bundle.* 通配订阅。
func (b AlertContextBundle) Subject() string {
	return "alerts.bundle." + b.MaxSeverity
}

// SeverityOrder 用于比较严重度高低。
var severityOrder = map[string]int{
	SeverityLow:      0,
	SeverityMedium:   1,
	SeverityHigh:     2,
	SeverityCritical: 3,
}

// MaxOf 返回两个 severity 中更高的那个。
func MaxOf(a, b string) string {
	if severityOrder[a] >= severityOrder[b] {
		return a
	}
	return b
}
