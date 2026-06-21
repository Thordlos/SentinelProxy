package redaction

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RawLogEntry 原始请求/响应记录结构
type RawLogEntry struct {
	RequestID           string `json:"request_id"`
	CreatedAt           int64  `json:"created_at"`
	Request             string `json:"request,omitempty"`
	RequestAfterRedaction string `json:"request_after_redaction,omitempty"`
	RequestConverted    string `json:"request_converted,omitempty"`
	ResponseFromUpstream string `json:"response_from_upstream,omitempty"`
	Response            string `json:"response,omitempty"`
	StreamText          string `json:"stream_text,omitempty"`
}

var (
	rawLogMutex sync.Mutex
)

// RawLogFilePath 返回原始日志文件路径
func RawLogFilePath(requestID string) string {
	cfg := Config()
	dir := cfg.StateDir
	if dir == "" {
		dir = "logs/masking"
	}
	return filepath.Join(dir, "raw", requestID+".json")
}

// loadRawLogEntry 加载或创建原始日志条目
func loadRawLogEntry(requestID string) *RawLogEntry {
	path := RawLogFilePath(requestID)
	entry := &RawLogEntry{
		RequestID: requestID,
		CreatedAt: time.Now().Unix(),
	}

	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, entry)
	}
	return entry
}

// saveRawLogEntry 保存原始日志条目到磁盘
func saveRawLogEntry(entry *RawLogEntry) error {
	path := RawLogFilePath(entry.RequestID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// recordRawLog 通用记录辅助函数
func recordRawLog(requestID string, mutator func(*RawLogEntry)) {
	if requestID == "" {
		return
	}

	rawLogMutex.Lock()
	defer rawLogMutex.Unlock()

	entry := loadRawLogEntry(requestID)
	mutator(entry)
	_ = saveRawLogEntry(entry)
}

// RecordRawRequest 记录原始请求体（脱敏前）
func RecordRawRequest(requestID string, body []byte) {
	if !Config().LogRawRequests {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.Request = string(body)
	})
}

// RecordRawRequestAfterRedaction 记录脱敏后的请求体
func RecordRawRequestAfterRedaction(requestID string, body []byte) {
	if !Config().LogRawRequests {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.RequestAfterRedaction = string(body)
	})
}

// RecordRawRequestConverted 记录转换后发给上游的请求体
func RecordRawRequestConverted(requestID string, body []byte) {
	if !Config().LogRawRequests {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.RequestConverted = string(body)
	})
}

// RecordRawResponseFromUpstream 记录上游返回的原始响应体
func RecordRawResponseFromUpstream(requestID string, body []byte) {
	if !Config().LogRawRequests {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.ResponseFromUpstream = string(body)
	})
}

// RecordRawResponse 记录最终返回给客户端的响应体（还原后）
func RecordRawResponse(requestID string, body []byte) {
	if !Config().LogRawRequests {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.Response = string(body)
	})
}

// RecordRawStreamText 追加记录流式响应文本
func RecordRawStreamText(requestID string, text string) {
	if !Config().LogRawRequests || text == "" {
		return
	}
	recordRawLog(requestID, func(entry *RawLogEntry) {
		entry.StreamText += text
	})
}

// GetRawLogEntry 读取原始日志条目
func GetRawLogEntry(requestID string) (*RawLogEntry, error) {
	if requestID == "" {
		return nil, fmt.Errorf("request_id is empty")
	}
	path := RawLogFilePath(requestID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var entry RawLogEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// DeleteRawLog 删除原始日志文件
func DeleteRawLog(requestID string) error {
	if requestID == "" {
		return nil
	}
	return os.Remove(RawLogFilePath(requestID))
}
