// Package capture — PCAP 读取器占位实现。
//
// 待 SWaT 数据集到达后，实现基于 gopacket 的工业协议解析：
//   - Modbus TCP（端口 502）
//   - DNP3（端口 20000）
//   - IEC 60870-5-104（端口 2404）
//
// 当前返回空数据，管道不会因缺少 PCAP 而崩溃。
package capture

import "fmt"

// PCAPReader 是 pcap 文件的 EventReader 占位实现。
// 目前返回空事件（不影响 JSONL 管道），SWaT 到达后再实现。
type PCAPReader struct {
	path string
}

// NewPCAPReader 创建 PCAP 读取器（占位）。
func NewPCAPReader(path string) (*PCAPReader, error) {
	return &PCAPReader{path: path}, nil
}

// Read 占位：返回空数据。
func (r *PCAPReader) Read() ([]RawEvent, error) {
	return nil, nil
}

// Close 占位。
func (r *PCAPReader) Close() error {
	return nil
}

// Source 返回文件路径。
func (r *PCAPReader) Source() string {
	return fmt.Sprintf("pcap:%s (占位)", r.path)
}
