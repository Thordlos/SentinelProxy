package redaction

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

const (
	// MarkerStart 是代号开始标记
	MarkerStart = "<SENTINEL>"
	// MarkerEnd 是代号结束标记
	MarkerEnd = "</SENTINEL>"
	// Marker 兼容旧格式（已弃用）
	Marker = MarkerStart
)

// Anonymizer 脱敏器
type Anonymizer struct {
	config *RedactionConfig
}

// NewAnonymizer 创建脱敏器
func NewAnonymizer(config *RedactionConfig) *Anonymizer {
	return &Anonymizer{config: config}
}

// Anonymize 对文本进行脱敏，返回脱敏后文本和生成的代号映射
// 注意：entities 必须已经按 Start 排序且不重叠
func (a *Anonymizer) Anonymize(text string, entities []Entity, state *MaskingState) (string, []CodeMapping, error) {
	if len(entities) == 0 {
		return text, nil, nil
	}

	var mappings []CodeMapping

	// 从右到左替换，避免 offset 变化影响后续替换
	for i := len(entities) - 1; i >= 0; i-- {
		entity := entities[i]
		code := state.GetCode(entity.Text, entity.Type)
		mappings = append(mappings, CodeMapping{
			Code:     code,
			Original: entity.Text,
			Type:     entity.Type,
		})

		replacement := a.applyOperator(entity.Text, code, entity.Operator, state)
		text = text[:entity.Start] + replacement + text[entity.End:]
	}

	// 反转 mappings 使其按文本出现顺序排列
	for i, j := 0, len(mappings)-1; i < j; i, j = i+1, j-1 {
		mappings[i], mappings[j] = mappings[j], mappings[i]
	}

	return text, mappings, nil
}

// applyOperator 根据操作符生成替换内容
func (a *Anonymizer) applyOperator(original, code string, op OperatorConfig, state *MaskingState) string {
	opType := NormalizeOperatorType(op.Type)
	switch opType {
	case OpMask:
		masked := maskString(original, op.MaskChar, op.CharsToMask, op.FromEnd)
		if state != nil {
			state.SetMaskedMapping(masked, original)
		}
		return masked
	case OpHash:
		h := sha256.Sum256([]byte(original))
		return fmt.Sprintf("%x", h[:8])
	case OpRandomize:
		// 格式保持随机化：生成格式正确的假值（当前主要用于 IP）
		fakeIP := RandomizeIP(original, state, op)
		return fakeIP
	case OpBlock:
		return code // block 在更高层处理
	case OpSymbolize:
		return MarkerStart + code + MarkerEnd
	default:
		// 未知操作符默认按符号化处理
		return MarkerStart + code + MarkerEnd
	}
}

// maskString 对字符串做部分掩码
func maskString(s, maskChar string, charsToMask int, fromEnd bool) string {
	if maskChar == "" {
		maskChar = "*"
	}
	if charsToMask <= 0 {
		charsToMask = len(s) / 2
	}
	if charsToMask >= len(s) {
		return strings.Repeat(maskChar, len(s))
	}

	if fromEnd {
		return s[:len(s)-charsToMask] + strings.Repeat(maskChar, charsToMask)
	}
	start := (len(s) - charsToMask) / 2
	end := start + charsToMask
	return s[:start] + strings.Repeat(maskChar, charsToMask) + s[end:]
}

// CodeMapping 代号与原词的映射关系
type CodeMapping struct {
	Code     string
	Original string
	Type     string
}
