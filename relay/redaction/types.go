package redaction

// OperatorType 定义脱敏操作类型
type OperatorType string

const (
	// OpReplace 替换为 ``代号``
	OpReplace OperatorType = "replace"
	// OpMask 部分掩码，如 138****8888
	OpMask OperatorType = "mask"
	// OpHash 哈希，不可逆
	OpHash OperatorType = "hash"
	// OpBlock 命中后阻断请求
	OpBlock OperatorType = "block"
	// OpIPRandom IP 格式保持随机化，私有IP→私有IP，公网IP→公网IP，可逆
	OpIPRandom OperatorType = "ip_random"
)

// OperatorConfig 操作符配置
type OperatorConfig struct {
	Type        OperatorType `yaml:"type" json:"type"`
	NewValue    string       `yaml:"new_value,omitempty" json:"new_value,omitempty"`
	MaskChar    string       `yaml:"mask_char,omitempty" json:"mask_char,omitempty"`
	CharsToMask int          `yaml:"chars_to_mask,omitempty" json:"chars_to_mask,omitempty"`
	FromEnd     bool         `yaml:"from_end,omitempty" json:"from_end,omitempty"`
	HashType    string       `yaml:"hash_type,omitempty" json:"hash_type,omitempty"`
	// IP 格式保持随机化专用配置
	IPRandomPreserveScope bool `yaml:"ip_random_preserve_scope,omitempty" json:"ip_random_preserve_scope,omitempty"` // 保持公私域划分（默认 true）
	IPRandomCrossClass    bool `yaml:"ip_random_cross_class,omitempty" json:"ip_random_cross_class,omitempty"`       // 允许私有地址跨 A/B/C 类（默认 true）
	IPRandomPreserveBits  int  `yaml:"ip_random_preserve_bits,omitempty" json:"ip_random_preserve_bits,omitempty"`   // 公网地址保留前 N 位（默认 0）
}

// Rule 自定义规则
type Rule struct {
	ID          string         `yaml:"id" json:"id"`
	Name        string         `yaml:"name" json:"name"`
	EntityType  string         `yaml:"entity_type" json:"entity_type"`
	Keyword     string         `yaml:"keyword,omitempty" json:"keyword,omitempty"`
	Pattern     string         `yaml:"pattern,omitempty" json:"pattern,omitempty"`
	Score       float64        `yaml:"score" json:"score"`
	Operator    OperatorConfig `yaml:"operator" json:"operator"`
	Description string         `yaml:"description,omitempty" json:"description,omitempty"`
}

// CompiledRule 编译后的规则
type CompiledRule struct {
	Rule
}

// Entity 表示检测到的敏感实体
type Entity struct {
	Type     string  // 实体类型，如 EMAIL_ADDRESS
	Start    int     // 在原始文本中的起始位置
	End      int     // 在原始文本中的结束位置
	Text     string  // 原始值
	Score    float64 // 置信度
	RuleID   string  // 命中的规则 ID
	Operator OperatorConfig
}

// BuiltInEntityConfig 内置实体配置
type BuiltInEntityConfig struct {
	Type     string         `yaml:"type" json:"type"`
	Name     string         `yaml:"name,omitempty" json:"name,omitempty"`
	Enabled  bool           `yaml:"enabled" json:"enabled"`
	Operator OperatorConfig `yaml:"operator" json:"operator"`
}

// RedactionConfig 脱敏总配置
type RedactionConfig struct {
	Enabled         bool                  `yaml:"enabled" json:"enabled"`
	FailClosed      bool                  `yaml:"fail_closed" json:"fail_closed"`
	ScoreThreshold  float64               `yaml:"score_threshold" json:"score_threshold"`
	MaxTextLength   int                   `yaml:"max_text_length" json:"max_text_length"`
	CacheTTLHours   int                   `yaml:"cache_ttl_hours" json:"cache_ttl_hours"`
	StateDir        string                `yaml:"state_dir" json:"state_dir"`
	CodeStyle       string                `yaml:"code_style" json:"code_style"`
	CodePrefix      string                `yaml:"code_prefix" json:"code_prefix"`
	CodeLength      int                   `yaml:"code_length" json:"code_length"`
	LogRawRequests  bool                  `yaml:"log_raw_requests" json:"log_raw_requests"`
	DefaultOperator OperatorConfig        `yaml:"default_operator" json:"default_operator"`
	BuiltInEntities []BuiltInEntityConfig `yaml:"built_in_entities" json:"built_in_entities"`
	StaticRules     []Rule                `yaml:"static_rules" json:"static_rules"`
	DynamicRules    []Rule                `yaml:"dynamic_rules" json:"dynamic_rules"`
}

// DefaultRedactionConfig 返回默认配置
func DefaultRedactionConfig() RedactionConfig {
	return RedactionConfig{
		Enabled:        false,
		FailClosed:     true,
		ScoreThreshold: 0.0,
		MaxTextLength:  1024 * 1024,
		CacheTTLHours:  24,
		StateDir:       "logs/masking",
		CodeStyle:      "typed",
		CodePrefix:     "ENT",
		CodeLength:     6,
		LogRawRequests: false,
		DefaultOperator: OperatorConfig{
			Type: OpReplace,
		},
		BuiltInEntities: []BuiltInEntityConfig{
			{Type: "ID_CARD", Name: "身份证", Enabled: true, Operator: OperatorConfig{Type: OpReplace}},
			{Type: "PHONE_NUMBER", Name: "手机号", Enabled: true, Operator: OperatorConfig{Type: OpReplace}},
			{Type: "EMAIL_ADDRESS", Name: "邮箱", Enabled: true, Operator: OperatorConfig{Type: OpReplace}},
			{Type: "BANK_CARD", Name: "银行卡", Enabled: true, Operator: OperatorConfig{Type: OpReplace}},
			{Type: "LICENSE_PLATE", Name: "车牌号", Enabled: false, Operator: OperatorConfig{Type: OpReplace}},
			{Type: "IP_ADDRESS", Name: "IP地址", Enabled: false, Operator: OperatorConfig{Type: OpReplace}},
		},
	}
}

// BuiltInEntityTypeList 返回启用的内置实体类型列表
func (cfg *RedactionConfig) BuiltInEntityTypeList() []string {
	var types []string
	for _, entity := range cfg.BuiltInEntities {
		if entity.Enabled {
			types = append(types, entity.Type)
		}
	}
	return types
}

// GetBuiltInEntityOperator 获取指定内置实体的操作符
func (cfg *RedactionConfig) GetBuiltInEntityOperator(entityType string) OperatorConfig {
	for _, entity := range cfg.BuiltInEntities {
		if entity.Type == entityType {
			return entity.Operator
		}
	}
	return cfg.DefaultOperator
}

// SetBuiltInEntityNames 根据内置规则设置实体名称
func (cfg *RedactionConfig) SetBuiltInEntityNames() {
	names := BuiltInEntityNames()
	for i := range cfg.BuiltInEntities {
		if cfg.BuiltInEntities[i].Name == "" {
			if name, ok := names[cfg.BuiltInEntities[i].Type]; ok {
				cfg.BuiltInEntities[i].Name = name
			}
		}
	}
}

// NormalizeConfig 规范化配置（向后兼容、填充默认值）
func (cfg *RedactionConfig) NormalizeConfig() {
	cfg.SetBuiltInEntityNames()
	for i := range cfg.BuiltInEntities {
		if cfg.BuiltInEntities[i].Operator.Type == "" {
			cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
		}
	}
	for i := range cfg.StaticRules {
		if cfg.StaticRules[i].Operator.Type == "" {
			cfg.StaticRules[i].Operator = cfg.DefaultOperator
		}
	}
	for i := range cfg.DynamicRules {
		if cfg.DynamicRules[i].Operator.Type == "" {
			cfg.DynamicRules[i].Operator = cfg.DefaultOperator
		}
	}
}
