// Package main 是 Go 遥测服务的入口。
//
// 管道组装（论文架构）：
//   capture.Read() → features.Extract() → aggregator.Add() → producer.PublishBundle()
//
// 各层职责：
//   - internal/capture/   数据采集（JSONL / PCAP）
//   - internal/features/  特征提取（RawEvent → AlertSnapshot）
//   - internal/aggregator/ 时窗聚合（AlertSnapshot → AlertContextBundle）
//   - internal/producer/  JetStream 发布
package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"masterproject/internal/aggregator"
	"masterproject/internal/capture"
	"masterproject/internal/features"
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

	// 2. 创建数据采集器（capture 层）
	reader, err := capture.NewJSONLReader(*filePath)
	if err != nil {
		log.Fatalf("[X] 创建 Reader 失败: %v", err)
	}
	defer reader.Close()

	// 3. 创建特征提取器（features 层）
	extractor := features.NewExtractor()

	// 4. 创建聚合器（aggregator 层）
	agg := aggregator.NewAggregator(*windowSize, *maxAlerts)

	// 5. 管道主循环: capture → features → aggregate → publish
	totalAlerts := 0
	bundlesSent := 0
	stormBundles := 0
	startTime := time.Now()

	for {
		// capture 层：读取事件
		events, err := reader.Read()
		if err != nil {
			log.Fatalf("[X] 读取事件失败: %v", err)
		}
		if events == nil {
			break // EOF
		}

		// features 层：特征提取
		snapshots := extractor.Extract(events)

		for _, alert := range snapshots {
			totalAlerts++

			// aggregator 层：时窗聚合
			bundle := agg.Add(alert)
			if bundle != nil {
				// producer 层：发布 Bundle
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
	}

	// 6. 文件读完，Flush 剩余告警
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

	// 7. 统计
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
