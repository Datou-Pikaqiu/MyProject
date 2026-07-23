// Package capture 提供告警事件读取能力。
//
// 对应论文架构的数据采集层（Data Capture Layer）。
// 当前支持 JSONL 文件读取，PCAP 解析为占位实现（待 SWaT 数据集）。
//
// 接口设计：
//   EventReader 是统一的事件读取接口——无论数据源是 JSONL 还是 PCAP，
//   上层管道（features → aggregator → producer）不感知差异。
package capture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// RawEvent 是原始告警事件——特征提取之前的原始数据。
// 对应论文中"网络传感器上报的原始报文"。
// JSONL 路径：所有字段由数据文件直接填充。
// PCAP 路径（未来）：Timestamp/Port/Protocol/RawMessage/PayloadLen 从报文解析，
//
//	FailedConnections/PacketRate/SourceRole/DestRole/NodeID/Subnet
//	由 features 层实时计算。
type RawEvent struct {
	Timestamp  time.Time `json:"timestamp"`
	SourceIP   string    `json:"source_ip"`
	DestIP     string    `json:"dest_ip"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol"`
	Severity   string    `json:"severity"`
	RawMessage string    `json:"raw_message"`
	PayloadLen int       `json:"payload_len,omitempty"`
	// JSONL 预计算特征（PCAP 路径由 features 层计算）
	FailedConnections5m int     `json:"failed_connections_5m,omitempty"`
	PacketRate          float64 `json:"packet_rate,omitempty"`
	// 设备拓扑信息（JSONL 已填充，PCAP 需从网络拓扑推断）
	SourceRole string `json:"source_role,omitempty"`
	DestRole   string `json:"dest_role,omitempty"`
	NodeID     string `json:"node_id,omitempty"`
	Subnet     string `json:"subnet,omitempty"`
}

// EventReader 是事件读取接口。
// 所有数据源（JSONL/PCAP/Live）实现此接口。
// Read 返回一批事件（批量读取以提升吞吐），文件结束时返回空切片。
type EventReader interface {
	Read() ([]RawEvent, error)
	Close() error
	// Source 返回数据源描述（日志/调试用）
	Source() string
}

// JSONLReader 从 JSONL 文件逐行读取告警，每行一条。
type JSONLReader struct {
	file    *os.File
	scanner *bufio.Scanner
	path    string
}

// NewJSONLReader 创建 JSONL 读取器。
func NewJSONLReader(path string) (*JSONLReader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开 JSONL 文件失败: %w", err)
	}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	return &JSONLReader{file: file, scanner: scanner, path: path}, nil
}

// Read 读取下一行 JSONL，返回单个事件（非批量，与接口语义一致）。
func (r *JSONLReader) Read() ([]RawEvent, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return nil, fmt.Errorf("读取 JSONL 行失败: %w", err)
		}
		return nil, nil // EOF
	}
	var ev RawEvent
	if err := json.Unmarshal(r.scanner.Bytes(), &ev); err != nil {
		return nil, fmt.Errorf("JSONL 解析失败: %w", err)
	}
	return []RawEvent{ev}, nil
}

// Close 关闭文件。
func (r *JSONLReader) Close() error {
	return r.file.Close()
}

// Source 返回文件路径。
func (r *JSONLReader) Source() string {
	return r.path
}
