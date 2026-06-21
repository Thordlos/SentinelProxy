package redaction

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
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

		replacement := a.applyOperator(entity.Text, code, entity.Type, entity.Operator, state)
		text = text[:entity.Start] + replacement + text[entity.End:]

		// 统计该实体类型的命中次数
		state.IncrementHitCount(entity.Type)
	}

	// 反转 mappings 使其按文本出现顺序排列
	for i, j := 0, len(mappings)-1; i < j; i, j = i+1, j-1 {
		mappings[i], mappings[j] = mappings[j], mappings[i]
	}

	return text, mappings, nil
}

// applyOperator 根据操作符生成替换内容
func (a *Anonymizer) applyOperator(original, code, entityType string, op OperatorConfig, state *MaskingState) string {
	opType := NormalizeOperatorType(op.Type)
	switch opType {
	case OpMask:
		masked := maskString(original, op.MaskChar, op.CharsToMask, op.FromEnd)
		if state != nil {
			state.SetMaskedMapping(masked, original)
		}
		return masked
	case OpRandomize:
		// 格式保持随机化：根据实体类型生成格式正确的假值
		fake := randomizeByType(original, entityType, state, op)
		return fake
	case OpTokenize:
		token := generateToken(original, state, op)
		return token
	case OpBlock:
		return code // block 在更高层处理
	case OpSymbolize:
		return MarkerStart + code + MarkerEnd
	default:
		// 未知操作符默认按符号化处理
		return MarkerStart + code + MarkerEnd
	}
}

// generateToken 生成定长可还原 token，并存入 MaskedInverse
func generateToken(original string, state *MaskingState, op OperatorConfig) string {
	if original == "" || state == nil {
		return original
	}

	// 同一会话内，相同原始值返回相同 token
	if existing := state.GetTokenForward(original); existing != "" {
		return existing
	}

	length := op.TokenLength
	if length <= 0 {
		length = 16
	}

	charset := op.TokenChars
	if charset == "" {
		charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	}
	runes := []rune(charset)

	// 生成随机 token，避免与已有 masked 值冲突
	charLen := big.NewInt(int64(len(runes)))
	generateRandom := func() string {
		var b strings.Builder
		for i := 0; i < length; i++ {
			n, err := rand.Int(rand.Reader, charLen)
			if err != nil {
				n = big.NewInt(int64(i % len(runes)))
			}
			b.WriteRune(runes[n.Int64()])
		}
		return b.String()
	}

	var token string
	for attempts := 0; attempts < 100; attempts++ {
		candidate := generateRandom()
		if state.GetOriginalByMasked(candidate) == "" {
			token = candidate
			break
		}
	}

	if token == "" {
		// 极端情况：使用 SHA-256 派生确定性 token，并确保不冲突
		h := sha256.Sum256([]byte(original))
		hex := fmt.Sprintf("%x", h)
		base := []rune(hex)[:min(length, len(hex))]
		token = string(base)
		for attempts := 0; state.GetOriginalByMasked(token) != "" && attempts < 1000; attempts++ {
			suffix := fmt.Sprintf("%d", attempts)
			runeSuffix := []rune(suffix)
			if len(runeSuffix) >= length {
				token = string(runeSuffix[:length])
			} else {
				token = string(base[:length-len(runeSuffix)]) + suffix
			}
		}
	}

	state.SetTokenForward(original, token)
	state.SetMaskedMapping(token, original)
	return token
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// randomizeByType 根据实体类型选择格式保持随机化策略
func randomizeByType(original, entityType string, state *MaskingState, op OperatorConfig) string {
	switch entityType {
	case "IP_ADDRESS":
		return RandomizeIP(original, state, op)
	case "PHONE_NUMBER":
		return RandomizePhone(original, state)
	case "ID_CARD":
		return RandomizeIDCard(original, state)
	case "EMAIL_ADDRESS":
		return RandomizeEmail(original, state)
	case "BANK_CARD":
		return RandomizeBankCard(original, state)
	case "LICENSE_PLATE":
		return RandomizeLicensePlate(original, state)
	default:
		// 对其他类型，先做通用掩码，再尝试还原；后续可扩展更多格式
		masked := maskString(original, op.MaskChar, op.CharsToMask, op.FromEnd)
		if state != nil {
			state.SetMaskedMapping(masked, original)
		}
		return masked
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
