// Package aggregator 实现时窗聚合器——提案第三个创新点。
//
// 把一个时间窗口内的多条告警聚合成一个 AlertContextBundle，
// 避免告警风暴时逐条冲垮 LLM。
//
// 触发条件（任一满足即发送 Bundle）：
//   1. 窗口时长 > windowSize（默认 5 秒）
//   2. 告警数 >= maxAlerts（默认 10 条，触发风暴标记）
package aggregator

import (
	"fmt"
	"sort"
	"time"

	"masterproject/pkg/contract"
)

// Aggregator 时窗聚合器。
type Aggregator struct {
	windowSize     time.Duration // 窗口最大时长
	maxAlerts      int           // 窗口最大告警数（也是风暴阈值）
	buffer         []contract.AlertSnapshot
	windowStart    time.Time
	bundleSeq      int // Bundle ID 序列号
}

// NewAggregator 创建聚合器。
//
// windowSize: 窗口最大时长，超时则发送 Bundle
// maxAlerts: 窗口最大告警数，达到则发送 Bundle 并标记为风暴
func NewAggregator(windowSize time.Duration, maxAlerts int) *Aggregator {
	return &Aggregator{
		windowSize:  windowSize,
		maxAlerts:   maxAlerts,
		buffer:      make([]contract.AlertSnapshot, 0, maxAlerts),
	}
}

// Add 添加一条告警到缓冲区。
// 返回非 nil 表示触发了聚合（调用方应该发送返回的 Bundle）。
func (a *Aggregator) Add(alert contract.AlertSnapshot) *contract.AlertContextBundle {
	// 第一条告警，记录窗口起点
	if len(a.buffer) == 0 {
		a.windowStart = alert.Timestamp
	}

	a.buffer = append(a.buffer, alert)

	// 检查触发条件
	windowDuration := alert.Timestamp.Sub(a.windowStart)
	if windowDuration >= a.windowSize || len(a.buffer) >= a.maxAlerts {
		return a.flush()
	}
	return nil
}

// Flush 强制刷新缓冲区（文件读完后调用，发走剩余告警）。
// 返回 nil 表示缓冲区为空。
func (a *Aggregator) Flush() *contract.AlertContextBundle {
	if len(a.buffer) == 0 {
		return nil
	}
	return a.flush()
}

// flush 生成 Bundle 并清空缓冲区。
func (a *Aggregator) flush() *contract.AlertContextBundle {
	alerts := a.buffer
	a.bundleSeq++

	bundle := a.buildBundle(alerts)

	// 清空缓冲区（保留底层数组的容量，避免重复分配）
	a.buffer = a.buffer[:0]

	return bundle
}

// buildBundle 从一组告警构造 AlertContextBundle。
func (a *Aggregator) buildBundle(alerts []contract.AlertSnapshot) *contract.AlertContextBundle {
	// 按时间戳排序（确保有序）
	sort.Slice(alerts, func(i, j int) bool {
		return alerts[i].Timestamp.Before(alerts[j].Timestamp)
	})

	windowStart := alerts[0].Timestamp
	windowEnd := alerts[len(alerts)-1].Timestamp

	// 去重 IP / 协议
	sourceIPSet := make(map[string]struct{})
	destIPSet := make(map[string]struct{})
	protocolSet := make(map[string]struct{})
	for _, al := range alerts {
		sourceIPSet[al.SourceIP] = struct{}{}
		destIPSet[al.DestIP] = struct{}{}
		protocolSet[al.Protocol] = struct{}{}
	}

	// 计算最高严重度
	maxSev := contract.SeverityLow
	for _, al := range alerts {
		maxSev = contract.MaxOf(maxSev, al.Severity)
	}

	// 计算平均包速率 + 总连接失败
	var totalRate float64
	totalFailed := 0
	for _, al := range alerts {
		totalRate += al.PacketRate
		totalFailed += al.FailedConnections5m
	}
	avgRate := totalRate / float64(len(alerts))

	// 告警风暴检测：告警数 >= maxAlerts
	isStorm := len(alerts) >= a.maxAlerts

	// 风暴中心节点：被攻击最多的 dest_ip 对应的 node_id
	stormNodeID := ""
	mainSubnet := ""
	if isStorm {
		destCount := make(map[string]int) // dest_ip -> 出现次数
		nodeMap := make(map[string]string) // dest_ip -> node_id
		for _, al := range alerts {
			destCount[al.DestIP]++
			nodeMap[al.DestIP] = al.NodeID
		}
		maxCount := 0
		for ip, count := range destCount {
			if count > maxCount {
				maxCount = count
				stormNodeID = nodeMap[ip]
			}
		}
		// 主子网：取第一条告警的子网
		mainSubnet = alerts[0].Subnet
	}

	return &contract.AlertContextBundle{
		BundleID:        fmt.Sprintf("bundle-%04d-%s", a.bundleSeq, windowStart.Format("150405")),
		WindowStart:     windowStart,
		WindowEnd:       windowEnd,
		AlertCount:      len(alerts),
		Alerts:          alerts,
		SourceIPs:       toSlice(sourceIPSet),
		DestIPs:         toSlice(destIPSet),
		Protocols:       toSlice(protocolSet),
		MaxSeverity:     maxSev,
		AvgPacketRate:   avgRate,
		TotalFailedConn: totalFailed,
		IsAlertStorm:    isStorm,
		StormNodeID:     stormNodeID,
		Subnet:          mainSubnet,
	}
}

// toSlice 把 map keys 转成有序 slice（便于 JSON 输出稳定）。
func toSlice(m map[string]struct{}) []string {
	s := make([]string, 0, len(m))
	for k := range m {
		s = append(s, k)
	}
	sort.Strings(s)
	return s
}
