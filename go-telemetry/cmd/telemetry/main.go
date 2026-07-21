// Package main 是 Go 遥测服务的入口。
//
// Day 3：管道组装 = 读 JSONL → 时窗聚合 → JetStream 发布 Bundle
// main.go 只负责组装管道，逻辑拆到 internal/ 包里：
//   - internal/aggregator/ 时窗聚合（提案创新点）
//   - internal/producer/   JetStream 发布
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"masterproject/internal/aggregator"
	"masterproject/internal/producer"
	"masterproject/pkg/contract"
)

func main() {
	filePath := flag.String("file", "../datasets/synthetic_alerts.jsonl", "JSONL 告警文件路径")
	interval := flag.Duration("interval", 200*time.Millisecond, "发送间隔")
	windowSize := flag.Duration("window", 5*time.Second, "聚合窗口时长")
	maxAlerts := flag.Int("max-alerts", 10, "窗口最大告警数（达到则触发风暴标记）")
	flag.Parse()

	// 1. 创建 Producer（连接 NATS + 确保 stream）
	p, err := producer.NewProducer("nats://localhost:4222")
	if err != nil {
		log.Fatalf("[X] 创建 Producer 失败: %v", err)
	}
	defer p.Close()
	fmt.Printf("[OK] Producer 就绪，窗口 %v / 风暴阈值 %d 条\n", *windowSize, *maxAlerts)

	// 2. 创建聚合器
	agg := aggregator.NewAggregator(*windowSize, *maxAlerts)

	// 3. 打开 JSONL 文件
	file, err := os.Open(*filePath)
	if err != nil {
		log.Fatalf("[X] 打开文件失败: %v", err)
	}
	defer file.Close()

	// 4. 逐行读取 → 聚合 → 发布
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	totalAlerts := 0     // 读取的告警总数
	bundlesSent := 0     // 发送的 Bundle 数
	stormBundles := 0    // 风暴 Bundle 数
	startTime := time.Now()

	for scanner.Scan() {
		var alert contract.AlertSnapshot
		if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
			log.Printf("[!] 解析失败: %v", err)
			continue
		}

		totalAlerts++

		// 加入聚合器，返回非 nil 表示触发了聚合
		bundle := agg.Add(alert)
		if bundle != nil {
			if err := p.PublishBundle(bundle); err != nil {
				log.Printf("[!] 发布 Bundle 失败: %v", err)
			} else {
				bundlesSent++
				if bundle.IsAlertStorm {
					stormBundles++
				}
				printBundle(bundlesSent, bundle)
			}
		}

		time.Sleep(*interval)
	}

	// 5. 文件读完，Flush 剩余告警
	if bundle := agg.Flush(); bundle != nil {
		if err := p.PublishBundle(bundle); err != nil {
			log.Printf("[!] 发布最后 Bundle 失败: %v", err)
		} else {
			bundlesSent++
			if bundle.IsAlertStorm {
				stormBundles++
			}
			printBundle(bundlesSent, bundle)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("[!] 读取文件错误: %v", err)
	}

	// 6. 统计
	elapsed := time.Since(startTime)
	fmt.Printf("\n[完成] 读取 %d 条告警 → 聚合成 %d 个 Bundle（含 %d 个风暴）\n",
		totalAlerts, bundlesSent, stormBundles)
	fmt.Printf("     耗时 %v，平均 %.1f 告警/秒\n",
		elapsed.Round(time.Millisecond), float64(totalAlerts)/elapsed.Seconds())
}

// printBundle 打印 Bundle 发送日志。
func printBundle(seq int, b *contract.AlertContextBundle) {
	storm := ""
	if b.IsAlertStorm {
		storm = " [STORM]"
	}
	fmt.Printf("[Bundle %3d] %s | %d 条告警 | %-8s | 源IP:%d 目的IP:%d | 窗口 %v%s\n",
		seq, b.BundleID, b.AlertCount, b.MaxSeverity,
		len(b.SourceIPs), len(b.DestIPs),
		b.WindowEnd.Sub(b.WindowStart).Round(time.Millisecond),
		storm,
	)
}
