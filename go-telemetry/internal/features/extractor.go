// Package features 提供告警特征提取能力。
//
// 对应论文架构的特征提取层（Feature Extraction Layer）。
// 将 capture 层产出的 RawEvent 转换为富含上下文特征的 AlertSnapshot。
//
// 当前 JSONL 模式下大多数特征从文件直读（pass-through）；
// PCAP 模式下需从网络流量实时计算（failed_connections_5m、packet_rate 等）。
package features

import (
	"masterproject/internal/capture"
	"masterproject/pkg/contract"
)

// Extractor 将 RawEvent 转换为 AlertSnapshot。
//
// JSONL 路径：RawEvent 已含全部字段 → 直接映射
// PCAP 路径（未来）：需从原始报文计算特征，Extract 方法保持不变，
//
//	内部逻辑扩展即可（开放-封闭原则）
type Extractor struct {
	// 未来扩展：连接追踪表、速率滑动窗口、Payload 基线等
}

// NewExtractor 创建特征提取器。
func NewExtractor() *Extractor {
	return &Extractor{}
}

// Extract 将一批 RawEvent 转换为一组 AlertSnapshot。
func (e *Extractor) Extract(events []capture.RawEvent) []contract.AlertSnapshot {
	snapshots := make([]contract.AlertSnapshot, 0, len(events))
	for _, ev := range events {
		snapshot := e.extractOne(ev)
		snapshots = append(snapshots, snapshot)
	}
	return snapshots
}

// extractOne 将单个 RawEvent 转换为 AlertSnapshot。
func (e *Extractor) extractOne(ev capture.RawEvent) contract.AlertSnapshot {
	return contract.AlertSnapshot{
		// === 基础元数据（直接从 RawEvent 映射）===
		AlertID:    ev.Timestamp.Format("20060102-150405") + "-" + ev.SourceIP,
		Timestamp:  ev.Timestamp,
		SourceIP:   ev.SourceIP,
		DestIP:     ev.DestIP,
		Port:       ev.Port,
		Protocol:   ev.Protocol,
		Severity:   ev.Severity,
		RawMessage: ev.RawMessage,

		// === 上下文特征 ===
		// JSONL 路径：从文件直接读取
		// PCAP 路径（未来）：从连接追踪表、Payload 分析实时计算
		FailedConnections5m: ev.FailedConnections5m,
		AbnormalPayloadLen:  ev.PayloadLen,
		PacketRate:          ev.PacketRate,

		// === 设备状态 ===
		// JSONL 路径：从文件直接读取
		// PCAP 路径（未来）：从 CMDB / 拓扑文件映射 IP→角色
		SourceRole: ev.SourceRole,
		DestRole:   ev.DestRole,

		// === 拓扑信息 ===
		NodeID: ev.NodeID,
		Subnet: ev.Subnet,
	}
}
