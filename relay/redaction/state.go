package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CodeGenerator 代号生成器
type CodeGenerator struct {
	config       *RedactionConfig
	counters     map[string]int
	usedCodes    map[string]bool
	entityTypes  map[string]string // code -> entityType
}

// NewCodeGenerator 创建代号生成器
func NewCodeGenerator(config *RedactionConfig) *CodeGenerator {
	return &CodeGenerator{
		config:      config,
		counters:    make(map[string]int),
		usedCodes:   make(map[string]bool),
		entityTypes: make(map[string]string),
	}
}

// Generate 生成代号
func (g *CodeGenerator) Generate(original, entityType string) string {
	var code string

	if g.config.CodeStyle == "RAND" {
		// 随机风格：ENT_a3f9k2
		for {
			hash := sha256.Sum256([]byte(original + time.Now().String()))
			rand := hex.EncodeToString(hash[:])[:g.config.CodeLength]
			code = fmt.Sprintf("%s_%s", g.config.CodePrefix, rand)
			if !g.usedCodes[code] {
				break
			}
		}
	} else {
		// typed 风格：ENTITY_TYPE_N
		prefix := g.config.CodePrefix
		if entityType != "" {
			prefix = entityType
		}
		for {
			g.counters[prefix]++
			code = fmt.Sprintf("%s_%d", prefix, g.counters[prefix])
			if !g.usedCodes[code] {
				break
			}
		}
	}

	g.usedCodes[code] = true
	g.entityTypes[code] = entityType
	return code
}

// MaskingState 会话级脱敏状态
type MaskingState struct {
	SessionID     string            `json:"session_id"`
	Forward       map[string]string `json:"forward"`        // 原词 -> 代号
	Inverse       map[string]string `json:"inverse"`        // 代号 -> 原词
	MaskedInverse map[string]string `json:"masked_inverse"` // 掩码值 -> 原词
	ForwardIP     map[string]string `json:"forward_ip"`     // 原IP -> 假IP（IP 格式保持随机化）
	Counters      map[string]int    `json:"counters"`       // 各类型计数器
	UsedCodes     map[string]bool   `json:"used_codes"`     // 已使用代号
	EntityTypes   map[string]string `json:"entity_types"`   // 代号 -> 实体类型
	CreatedAt     time.Time         `json:"created_at"`
	LastAccessed  time.Time         `json:"last_accessed"`
	generator     *CodeGenerator
}

// NewMaskingState 创建新的会话状态
func NewMaskingState(sessionID string, config *RedactionConfig) *MaskingState {
	return &MaskingState{
		SessionID:     sessionID,
		Forward:       make(map[string]string),
		Inverse:       make(map[string]string),
		MaskedInverse: make(map[string]string),
		ForwardIP:     make(map[string]string),
		Counters:      make(map[string]int),
		UsedCodes:     make(map[string]bool),
		EntityTypes:   make(map[string]string),
		CreatedAt:     time.Now(),
		LastAccessed:  time.Now(),
		generator:     NewCodeGenerator(config),
	}
}

// SetMaskedMapping 保存掩码值到原始值的映射
func (s *MaskingState) SetMaskedMapping(masked, original string) {
	if s == nil || masked == "" || original == "" {
		return
	}
	if s.MaskedInverse == nil {
		s.MaskedInverse = make(map[string]string)
	}
	s.MaskedInverse[masked] = original
	s.LastAccessed = time.Now()
}

// GetOriginalByMasked 通过掩码值获取原始值
func (s *MaskingState) GetOriginalByMasked(masked string) string {
	if s == nil {
		return ""
	}
	s.LastAccessed = time.Now()
	return s.MaskedInverse[masked]
}

// SetForwardIP 保存原始 IP 到假 IP 的映射（IP 格式保持随机化）
func (s *MaskingState) SetForwardIP(originalIP, fakeIP string) {
	if s == nil || originalIP == "" || fakeIP == "" {
		return
	}
	if s.ForwardIP == nil {
		s.ForwardIP = make(map[string]string)
	}
	s.ForwardIP[originalIP] = fakeIP
	s.LastAccessed = time.Now()
}

// GetForwardIP 获取原始 IP 对应的假 IP（IP 格式保持随机化）
func (s *MaskingState) GetForwardIP(originalIP string) string {
	if s == nil {
		return ""
	}
	s.LastAccessed = time.Now()
	return s.ForwardIP[originalIP]
}

// GetCode 获取原词对应的代号，不存在则生成
func (s *MaskingState) GetCode(original, entityType string) string {
	if code, ok := s.Forward[original]; ok {
		s.LastAccessed = time.Now()
		return code
	}

	code := s.generator.Generate(original, entityType)
	s.Forward[original] = code
	s.Inverse[code] = original
	s.UsedCodes[code] = true
	s.EntityTypes[code] = entityType
	if entityType != "" {
		s.Counters[entityType] = s.generator.counters[entityType]
	}
	s.LastAccessed = time.Now()
	return code
}

// GetOriginal 获取代号对应的原词
func (s *MaskingState) GetOriginal(code string) string {
	s.LastAccessed = time.Now()
	return s.Inverse[code]
}

// ToJSON 序列化状态
func (s *MaskingState) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// Save 保存状态到磁盘
func (s *MaskingState) Save() error {
	path := StateFilePath(s.SessionID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	data, err := s.ToJSON()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// LoadMaskingState 从磁盘加载状态
func LoadMaskingState(sessionID string, config *RedactionConfig) (*MaskingState, error) {
	path := StateFilePath(sessionID)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	state := &MaskingState{}
	if err := json.Unmarshal(data, state); err != nil {
		return nil, err
	}

	// 恢复运行时结构
	state.generator = NewCodeGenerator(config)
	state.generator.counters = state.Counters
	state.generator.usedCodes = state.UsedCodes
	state.generator.entityTypes = state.EntityTypes
	if state.MaskedInverse == nil {
		state.MaskedInverse = make(map[string]string)
	}
	if state.ForwardIP == nil {
		state.ForwardIP = make(map[string]string)
	}
	state.LastAccessed = time.Now()
	return state, nil
}
