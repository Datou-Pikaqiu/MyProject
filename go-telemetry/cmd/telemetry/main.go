// Package main 是 Go 遥测服务的入口。
//
// Day 2：从 JSONL 文件读取合成告警，用 JetStream 持久化发布到 NATS。
// JetStream 保证消息不丢（core NATS 是 fire-and-forget，会丢消息）。
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
	"masterproject/pkg/contract"
)

// streamName 是 JetStream stream 的名称，Go/Python 两端必须一致。
const streamName = "ALERTS"

func main() {
	filePath := flag.String("file", "../datasets/synthetic_alerts.jsonl", "JSONL 告警文件路径")
	interval := flag.Duration("interval", 200*time.Millisecond, "发送间隔（如 200ms, 1s）")
	flag.Parse()

	// 1. 连接 NATS
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatalf("[X] 连接 NATS 失败: %v", err)
	}
	defer nc.Close()
	fmt.Printf("[OK] Go publisher 已连接 NATS，间隔 %v\n", *interval)

	// 2. 创建 JetStream context
	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("[X] 创建 JetStream context 失败: %v", err)
	}

	// 3. 确保 stream 存在（幂等：已存在则跳过）
	// stream 持久化存储 subject 匹配 alerts.* 的所有消息
	if _, err := js.StreamInfo(streamName); err != nil {
		_, err = js.AddStream(&nats.StreamConfig{
			Name:      streamName,
			Subjects:  []string{"alerts.*"},
			Retention: nats.LimitsPolicy, // 超过限制时丢弃旧消息
			MaxAge:    time.Hour,         // 消息保留 1 小时
		})
		if err != nil {
			log.Fatalf("[X] 创建 stream %s 失败: %v", streamName, err)
		}
		fmt.Printf("[OK] 已创建 JetStream stream: %s\n", streamName)
	} else {
		fmt.Printf("[OK] JetStream stream 已存在: %s\n", streamName)
	}

	// 4. 打开 JSONL 文件
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("[X] 打开文件失败: %v", err)
	}
	defer file.Close()

	// 5. 逐行读取并用 JetStream 发布
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	sent := 0
	bySeverity := map[string]int{}
	startTime := time.Now()

	for scanner.Scan() {
		line := scanner.Bytes()

		var alert contract.AlertSnapshot
		if err := json.Unmarshal(line, &alert); err != nil {
			log.Printf("[!] 第 %d 行解析失败: %v", sent+1, err)
			continue
		}

		data, err := json.Marshal(alert)
		if err != nil {
			log.Printf("[!] 序列化失败 %s: %v", alert.AlertID, err)
			continue
		}

		subject := alert.Subject()
		// JetStream Publish 是同步的，返回 ack 确认消息已持久化
		// （core NATS 的 Publish 是异步 fire-and-forget，不保证不丢）
		_, err = js.Publish(subject, data)
		if err != nil {
			log.Printf("[!] 发布失败 %s: %v", alert.AlertID, err)
			continue
		}

		sent++
		bySeverity[alert.Severity]++

		if sent == 1 || sent%10 == 0 || alert.Severity == contract.SeverityCritical {
			fmt.Printf("[发送 %3d] %-16s -> %-14s | %-8s | %s\n",
				sent, alert.AlertID, subject, alert.Severity,
				truncate(alert.RawMessage, 35))
		}

		time.Sleep(*interval)
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] 读取文件错误: %v", err)
	}

	// 6. 统计
	elapsed := time.Since(startTime)
	fmt.Printf("\n[完成] 共发送 %d 条告警，耗时 %v\n", sent, elapsed.Round(time.Millisecond))
	fmt.Printf("     按严重度: %v\n", bySeverity)
	fmt.Printf("     平均速率: %.1f 条/秒\n", float64(sent)/elapsed.Seconds())
}

// truncate 截断字符串到指定 rune 数，避免中文被截断成乱码。
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "..."
	}
	return s
}
