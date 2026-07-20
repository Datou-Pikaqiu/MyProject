// Package main 是 Go 遥测服务的入口。
//
// Day 1 目标：验证 Go -> NATS 管道打通。
// 后续这里会演化成：流量重放 -> 特征提取 -> 时窗聚合 -> 队列投递。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/nats-io/nats.go"
)

// AlertSnapshot 是 Go 端发给 Python 端的"告警上下文快照"。
//
// 这是整个系统的核心数据契约 —— Go 和 Python 之间传递的最小信息单元。
// 提案第 4 节定义了 LLM 可用的证据字段，这个结构是它的起点。
// Day 1 先放最基础字段，后续 Sprint 会扩展：
//   - 拓扑信息（节点角色、上下游关系）
//   - 时窗统计（过去 5 分钟连接失败次数、异常载荷长度）
//   - 设备状态（PLC 控制器、HMI 操作站等资产角色）
type AlertSnapshot struct {
	AlertID    string    `json:"alert_id"`
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`   // 如 "Modbus", "DNP3"
	Severity   string    `json:"severity"`   // low / medium / high / critical
	RawMessage string    `json:"raw_message"` // 原始告警文本（后面要做注入防护）
}

func main() {
	// 1. 连接 NATS（默认地址 nats://localhost:4222）
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("[X] 连接 NATS 失败: %v", err)
	}
	defer nc.Close()
	fmt.Println("[OK] Go publisher 已连接 NATS")

	// 2. 构造一个模拟的告警快照
	// Day 3 会用真实流量重放替换这里
	snapshot := AlertSnapshot{
		AlertID:    "alert-001",
		Timestamp:  time.Now(),
		SourceIP:   "192.168.1.100",
		DestIP:     "192.168.1.50",
		Port:       502, // Modbus 默认端口
		Protocol:   "Modbus",
		Severity:   "high",
		RawMessage: "异常 Modbus 写入：未授权节点尝试修改 PLC 寄存器",
	}

	// 3. 序列化为 JSON
	// NATS 传字节，我们用 JSON 作为跨语言契约（Go struct tag <-> Python dict）
	data, err := json.Marshal(snapshot)
	if err != nil {
		log.Fatalf("[X] JSON 序列化失败: %v", err)
	}

	// 4. 发布到 NATS
	// subject 命名规范: alerts.<severity>
	// 设计意图：Python 端可按严重度选择性订阅
	//   - alerts.*          接收全部
	//   - alerts.critical   只接收致命告警（高优处理）
	subject := "alerts." + snapshot.Severity
	err = nc.Publish(subject, data)
	if err != nil {
		log.Fatalf("[X] 发布失败: %v", err)
	}

	// 5. 刷新确保消息发出（NATS Publish 是异步的，Flush 同步等待）
	err = nc.Flush()
	if err != nil {
		log.Fatalf("[X] Flush 失败: %v", err)
	}

	// 6. 打印发布结果（方便验证）
	fmt.Printf("[OK] 已发布告警到 subject [%s]\n", subject)
	fmt.Printf("     AlertID:  %s\n", snapshot.AlertID)
	fmt.Printf("     源->目的: %s -> %s:%d\n", snapshot.SourceIP, snapshot.DestIP, snapshot.Port)
	fmt.Printf("     协议:     %s\n", snapshot.Protocol)
	fmt.Printf("     严重度:   %s\n", snapshot.Severity)
	fmt.Printf("     Payload:  %d bytes\n", len(data))
}
