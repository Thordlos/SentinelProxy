package redaction

// Analyzer 是 PII 检测器接口
type Analyzer interface {
	Analyze(text string, entities []string) ([]Entity, error)
}

// defaultAnalyzer 使用规则引擎的默认检测器
type defaultAnalyzer struct {
	engine *RuleEngine
}

// NewAnalyzer 创建默认检测器
func NewAnalyzer(config *RedactionConfig) (Analyzer, error) {
	engine, err := NewRuleEngine(config)
	if err != nil {
		return nil, err
	}
	return &defaultAnalyzer{engine: engine}, nil
}

// Analyze 检测文本中的敏感实体
func (a *defaultAnalyzer) Analyze(text string, entities []string) ([]Entity, error) {
	return a.engine.Analyze(text, entities)
}
