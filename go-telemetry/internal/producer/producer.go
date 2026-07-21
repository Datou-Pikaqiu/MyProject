// Package producer 封装 JetStream 发布逻辑。
//
// 从 main.go 抽出，让 main.go 只负责管道组装。
// 职责：连接 NATS → 创建 stream → 发布 Bundle → 关闭连接。
package producer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"masterproject/pkg/contract"
)

// streamName 是 JetStream stream 名称，Go/Python 两端必须一致。
const streamName = "ALERTS"

// Producer JetStream 消息发布者。
type Producer struct {
	nc *nats.Conn
	js nats.JetStreamContext
}

// NewProducer 创建 Producer 并确保 stream 存在。
func NewProducer(natsURL string) (*Producer, error) {
	nc, err := nats.Connect(natsURL)
	if err != nil {
		return nil, fmt.Errorf("连接 NATS 失败: %w", err)
	}

	js, err := nc.JetStream()
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("创建 JetStream context 失败: %w", err)
	}

	// 确保 stream 存在且 subjects 包含 alerts.bundle.*（Day 3 新增）
	// Day 2 创建的 stream 只有 alerts.*，需要 UpdateStream 添加新 subject
	streamConfig := &nats.StreamConfig{
		Name:      streamName,
		Subjects:  []string{"alerts.*", "alerts.bundle.*"},
		Retention: nats.LimitsPolicy,
		MaxAge:    time.Hour,
	}
	if _, err := js.StreamInfo(streamName); err != nil {
		_, err = js.AddStream(streamConfig)
	} else {
		_, err = js.UpdateStream(streamConfig)
	}
	if err != nil {
		nc.Close()
		return nil, fmt.Errorf("配置 stream 失败: %w", err)
	}

	return &Producer{nc: nc, js: js}, nil
}

// PublishBundle 发布一个 AlertContextBundle 到 JetStream。
func (p *Producer) PublishBundle(bundle *contract.AlertContextBundle) error {
	data, err := json.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("序列化 Bundle 失败: %w", err)
	}
	_, err = p.js.Publish(bundle.Subject(), data)
	if err != nil {
		return fmt.Errorf("发布 Bundle 失败: %w", err)
	}
	return nil
}

// Close 关闭 NATS 连接。
func (p *Producer) Close() {
	if p.nc != nil {
		p.nc.Close()
	}
}
