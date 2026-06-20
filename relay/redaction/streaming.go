package redaction

import (
	"strings"
)

// StreamingUnmasker 流式响应恢复器
type StreamingUnmasker struct {
	state   *MaskingState
	pending strings.Builder
}

// NewStreamingUnmasker 创建流式恢复器
func NewStreamingUnmasker(state *MaskingState) *StreamingUnmasker {
	return &StreamingUnmasker{
		state: state,
	}
}

// Write 处理一个输入片段，返回可立即输出的文本
func (u *StreamingUnmasker) Write(input string) string {
	if input == "" {
		return ""
	}

	u.pending.WriteString(input)
	output, remaining := DrainUnmaskBuffer(u.pending.String(), u.state)
	u.pending.Reset()
	u.pending.WriteString(remaining)
	return output
}

// Flush 返回缓冲区中剩余数据
func (u *StreamingUnmasker) Flush() string {
	text := u.pending.String()
	if text == "" {
		return ""
	}

	// 尝试完整还原
	restored := UnmaskText(text, u.state)
	u.pending.Reset()
	return restored
}
