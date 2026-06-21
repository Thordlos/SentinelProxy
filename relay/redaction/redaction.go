package redaction

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/sentinelproxy/sentinelproxy/relay/model"
)

var (
	globalAnalyzer Analyzer
)

// Init 初始化脱敏模块
func Init(config *RedactionConfig) error {
	if config == nil {
		cfg := DefaultRedactionConfig()
		config = &cfg
	}

	configMutex.Lock()
	defer configMutex.Unlock()
	globalConfig = config

	if !config.Enabled {
		return nil
	}

	analyzer, err := NewAnalyzer(config)
	if err != nil {
		return fmt.Errorf("init redaction analyzer failed: %w", err)
	}
	globalAnalyzer = analyzer
	return nil
}

// getAnalyzer 返回当前 analyzer（线程安全）
func getAnalyzer() Analyzer {
	configMutex.RLock()
	defer configMutex.RUnlock()
	return globalAnalyzer
}

// MaskText 对单条文本脱敏
func MaskText(text string, state *MaskingState) (string, error) {
	analyzer := getAnalyzer()
	if analyzer == nil || !Config().Enabled {
		return text, nil
	}

	cfg := Config()
	if cfg.MaxTextLength > 0 && len(text) > cfg.MaxTextLength {
		return "", fmt.Errorf("text length %d exceeds max %d", len(text), cfg.MaxTextLength)
	}

	entities, err := analyzer.Analyze(text, nil)
	if err != nil {
		return "", err
	}

	if len(entities) == 0 {
		return text, nil
	}

	anonymizer := NewAnonymizer(cfg)
	masked, _, err := anonymizer.Anonymize(text, entities, state)
	return masked, err
}

// UnmaskText 对文本反向还原
func UnmaskText(text string, state *MaskingState) string {
	if state == nil {
		return text
	}

	// 1. 按掩码值长度降序替换（mask 操作产生的脱敏值）
	maskedValues := make([]string, 0, len(state.MaskedInverse))
	for masked := range state.MaskedInverse {
		maskedValues = append(maskedValues, masked)
	}
	sortByLengthDesc(maskedValues)
	for _, masked := range maskedValues {
		original := state.GetOriginalByMasked(masked)
		if original != "" {
			text = strings.ReplaceAll(text, masked, original)
		}
	}

	// 2. 按代号长度降序，避免短代号覆盖长代号
	codes := make([]string, 0, len(state.Inverse))
	for code := range state.Inverse {
		codes = append(codes, code)
	}
	sortByLengthDesc(codes)

	for _, code := range codes {
		original := state.GetOriginal(code)
		if original == "" {
			continue
		}
		// 新格式：<SENTINEL>code</SENTINEL>
		text = strings.ReplaceAll(text, MarkerStart+code+MarkerEnd, original)
		// 兼容旧格式：``code``
		text = strings.ReplaceAll(text, "``"+code+"``", original)
	}
	return text
}

// UnmaskBytes 对字节数组反向还原
func UnmaskBytes(data []byte, state *MaskingState) []byte {
	if state == nil || len(state.Inverse) == 0 {
		return data
	}

	// 尝试作为 JSON 处理，只对字符串值做替换
	var v any
	if err := json.Unmarshal(data, &v); err == nil {
		v = unmaskJSONValue(v, state)
		newData, err := json.Marshal(v)
		if err == nil {
			return newData
		}
	}

	// 非 JSON，直接字符串替换
	return []byte(UnmaskText(string(data), state))
}

// unmaskJSONValue 递归还原 JSON 值中的字符串
func unmaskJSONValue(value any, state *MaskingState) any {
	switch v := value.(type) {
	case string:
		return UnmaskText(v, state)
	case map[string]any:
		result := make(map[string]any)
		for k, val := range v {
			result[k] = unmaskJSONValue(val, state)
		}
		return result
	case []any:
		result := make([]any, len(v))
		for i, val := range v {
			result[i] = unmaskJSONValue(val, state)
		}
		return result
	default:
		return value
	}
}

// MaskJSONValue 递归脱敏 JSON 值中的字符串
func MaskJSONValue(value any, state *MaskingState) (any, error) {
	switch v := value.(type) {
	case string:
		return MaskText(v, state)
	case map[string]any:
		result := make(map[string]any)
		for k, val := range v {
			masked, err := MaskJSONValue(val, state)
			if err != nil {
				return nil, err
			}
			result[k] = masked
		}
		return result, nil
	case []any:
		result := make([]any, len(v))
		for i, val := range v {
			masked, err := MaskJSONValue(val, state)
			if err != nil {
				return nil, err
			}
			result[i] = masked
		}
		return result, nil
	default:
		return value, nil
	}
}

func sortByLengthDesc(strs []string) {
	for i := 0; i < len(strs); i++ {
		for j := i + 1; j < len(strs); j++ {
			if len(strs[j]) > len(strs[i]) {
				strs[i], strs[j] = strs[j], strs[i]
			}
		}
	}
}

const PreserveMarker = "``"

// ExtractPreservedFragments 提取 ``内容`` 保留片段
func ExtractPreservedFragments(text string) (string, map[string]string) {
	fragments := make(map[string]string)
	idx := 0

	pattern := strings.NewReplacer()
	_ = pattern

	var result strings.Builder
	marker := PreserveMarker
	for {
		start := strings.Index(text, marker)
		if start == -1 {
			result.WriteString(text)
			break
		}

		result.WriteString(text[:start])
		end := strings.Index(text[start+len(marker):], marker)
		if end == -1 {
			// 没有闭合标记，当作普通文本
			result.WriteString(text[start:])
			break
		}
		end += start + len(marker)

		placeholder := fmt.Sprintf("__SENTINEL_PRESERVE_%d__", idx)
		fragments[placeholder] = text[start+len(marker) : end]
		result.WriteString(placeholder)
		idx++

		text = text[end+len(marker):]
	}

	return result.String(), fragments
}

// RestorePreservedFragments 还原保留片段
func RestorePreservedFragments(text string, fragments map[string]string) string {
	for placeholder, original := range fragments {
		text = strings.ReplaceAll(text, placeholder, original)
	}
	return text
}

// MaskTextWithPreserve 对文本脱敏，支持保留片段
func MaskTextWithPreserve(text string, state *MaskingState) (string, error) {
	working, fragments := ExtractPreservedFragments(text)
	masked, err := MaskText(working, state)
	if err != nil {
		return "", err
	}
	return RestorePreservedFragments(masked, fragments), nil
}

// UnmaskTextWithPreserve 对文本还原，支持保留片段
func UnmaskTextWithPreserve(text string, state *MaskingState) string {
	working, fragments := ExtractPreservedFragments(text)
	restored := UnmaskText(working, state)
	return RestorePreservedFragments(restored, fragments)
}

// MaskBytes 对字节数组脱敏（作为 JSON 处理）
func MaskBytes(data []byte, state *MaskingState) ([]byte, error) {
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}

	masked, err := MaskJSONValue(v, state)
	if err != nil {
		return nil, err
	}

	return json.Marshal(masked)
}

// DrainUnmaskBuffer 从缓冲区中输出已确认可还原的部分
// 返回：(可输出文本, 保留的 buffer)
func DrainUnmaskBuffer(buffer string, state *MaskingState) (string, string) {
	output := &bytes.Buffer{}
	i := 0

	for i < len(buffer) {
		markerPos := strings.Index(buffer[i:], MarkerStart)
		if markerPos == -1 {
			// 没有完整开始标签，检查末尾是否有开始标签的前缀
			output.WriteString(buffer[i:])
			written := output.String()
			// 先检查 MaskedInverse 前缀（IP 等纯文本值可能跨 chunk）
			clean, held := drainMaskedInverse(written, state)
			if held != "" {
				return clean, held
			}
			// 再检查 MarkerStart 前缀
			for j := 1; j <= len(MarkerStart) && j <= len(clean); j++ {
				suffix := clean[len(clean)-j:]
				if strings.HasPrefix(MarkerStart, suffix) {
					return clean[:len(clean)-j], suffix
				}
			}
			return clean, ""
		}
		markerPos += i

		// 输出标记前内容
		output.WriteString(buffer[i:markerPos])

		// 查找闭合标记
		closePos := strings.Index(buffer[markerPos+len(MarkerStart):], MarkerEnd)
		if closePos == -1 {
			// 没有闭合，保留从当前标记开始的所有内容
			return output.String(), buffer[markerPos:]
		}
		closePos += markerPos + len(MarkerStart)

		code := buffer[markerPos+len(MarkerStart) : closePos]
		original := state.GetOriginal(code)
		if original != "" {
			output.WriteString(original)
			i = closePos + len(MarkerEnd)
		} else {
			// 不是有效代号，当作普通文本输出
			output.WriteString(buffer[markerPos : closePos+len(MarkerEnd)])
			i = closePos + len(MarkerEnd)
		}
	}

	// 末尾处理：检查 MaskedInverse 前缀
	final := output.String()
	clean, held := drainMaskedInverse(final, state)
	return clean, held
}

// drainMaskedInverse 替换输出中的 MaskedInverse 值（如假 IP、假邮箱、假车牌），
// 并检查末尾是否有不完整的掩码值片断（跨 SSE chunk 截断）。
// 返回：(可安全输出的文本, 需要保留在 buffer 中的后缀)
func drainMaskedInverse(text string, state *MaskingState) (string, string) {
	if state == nil || len(state.MaskedInverse) == 0 {
		return text, ""
	}

	// 计算最大掩码值长度
	maxMaskLen := 0
	maskedValues := make([]string, 0, len(state.MaskedInverse))
	for masked := range state.MaskedInverse {
		maskedValues = append(maskedValues, masked)
		if len(masked) > maxMaskLen {
			maxMaskLen = len(masked)
		}
	}
	sortByLengthDesc(maskedValues)

	// 1. 替换完整的 MaskedInverse 值
	result := text
	for _, masked := range maskedValues {
		original := state.MaskedInverse[masked]
		if original != "" && strings.Contains(result, masked) {
			result = strings.ReplaceAll(result, masked, original)
		}
	}

	// 2. 检查末尾是否有不完整的掩码值前缀或未完成的多字节 UTF-8 字符，
	//    如果是则 hold 回 buffer，等待后续 chunk 拼接完整后再替换。
	b := []byte(result)

	// 2.1 计算因末尾 UTF-8 字符不完整需要保留的字节数
	incompleteByteLen := 0
	for i := len(b) - 1; i >= 0; i-- {
		// continuation byte: 10xxxxxx
		if b[i] >= 0x80 && b[i] <= 0xBF {
			incompleteByteLen++
			continue
		}
		// 到达 lead byte，判断从该位置到末尾是否是一个完整有效的 UTF-8 字符
		if utf8.ValidString(string(b[i:])) {
			incompleteByteLen = 0
		} else {
			incompleteByteLen = len(b) - i
		}
		break
	}

	// 2.2 计算末尾最长、且是某个 MaskedInverse key 前缀的后缀（按 rune 边界）
	validPart := result
	if incompleteByteLen > 0 {
		validPart = result[:len(result)-incompleteByteLen]
	}
	runes := []rune(validPart)
	heldRunes := 0
	for l := 1; l <= len(runes) && l < maxMaskLen; l++ {
		suffix := string(runes[len(runes)-l:])
		if len(suffix) >= maxMaskLen {
			break
		}
		for _, masked := range maskedValues {
			if strings.HasPrefix(masked, suffix) {
				heldRunes = l
				break
			}
		}
	}

	heldByteLen := incompleteByteLen
	if heldRunes > 0 {
		suffix := string(runes[len(runes)-heldRunes:])
		if len(suffix) > heldByteLen {
			heldByteLen = len(suffix)
		}
	}

	if heldByteLen > 0 {
		return result[:len(result)-heldByteLen], result[len(result)-heldByteLen:]
	}
	return result, ""
}

// PreviewResult 预览结果
type PreviewResult struct {
	Masked       string            `json:"masked"`
	Restored     string            `json:"restored"`
	Mappings     []PreviewMapping  `json:"mappings"`
	SessionID    string            `json:"session_id"`
}

// PreviewMapping 预览映射
type PreviewMapping struct {
	Code     string `json:"code"`
	Original string `json:"original"`
	Type     string `json:"type"`
}

// PreviewMasking 预览脱敏效果
// 使用指定的 sessionID 维护会话状态，保证同一会话预览映射一致
func PreviewMasking(text string, sessionID string) (*PreviewResult, error) {
	cfg := Config()
	if !cfg.Enabled {
		return &PreviewResult{
			Masked:    text,
			Restored:  text,
			Mappings:  []PreviewMapping{},
			SessionID: sessionID,
		}, nil
	}

	if sessionID == "" {
		sessionID = "preview_" + fmt.Sprintf("%d", len(text))
	}

	state, err := LoadMaskingState(sessionID, cfg)
	if err != nil {
		state = NewMaskingState(sessionID, cfg)
	}

	masked, err := MaskTextWithPreserve(text, state)
	if err != nil {
		return nil, err
	}

	restored := UnmaskTextWithPreserve(masked, state)

	var mappings []PreviewMapping
	for code, original := range state.Inverse {
		entityType := state.EntityTypes[code]
		mappings = append(mappings, PreviewMapping{
			Code:     code,
			Original: original,
			Type:     entityType,
		})
	}

	// 保存预览会话状态
	_ = state.Save()

	return &PreviewResult{
		Masked:    masked,
		Restored:  restored,
		Mappings:  mappings,
		SessionID: sessionID,
	}, nil
}

// RedactRequest 对 GeneralOpenAIRequest 进行脱敏
// 只处理 role == "user" 的消息，assistant 历史消息不处理
func RedactRequest(req *model.GeneralOpenAIRequest, state *MaskingState) error {
	if req == nil || state == nil || !Config().Enabled {
		return nil
	}

	for i := range req.Messages {
		msg := &req.Messages[i]
		if msg.Role != "user" {
			continue
		}

		// 处理 content
		switch content := msg.Content.(type) {
		case string:
			if content == "" {
				continue
			}
			masked, err := MaskTextWithPreserve(content, state)
			if err != nil {
				return fmt.Errorf("mask message content failed: %w", err)
			}
			msg.Content = masked
		case []any:
			for j, item := range content {
				itemMap, ok := item.(map[string]any)
				if !ok {
					continue
				}
				if itemMap["type"] != "text" {
					continue
				}
				text, ok := itemMap["text"].(string)
				if !ok || text == "" {
					continue
				}
				masked, err := MaskTextWithPreserve(text, state)
				if err != nil {
					return fmt.Errorf("mask message content block failed: %w", err)
				}
				itemMap["text"] = masked
				content[j] = itemMap
			}
		}
	}

	return nil
}

// RedactToolArguments 对 tool_calls 的 arguments 做递归脱敏
func RedactToolArguments(args any, state *MaskingState) (any, error) {
	return MaskJSONValue(args, state)
}
