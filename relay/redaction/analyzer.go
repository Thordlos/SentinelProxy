package redaction

// Analyzer 是 PII 检测器接口
type Analyzer interface {
	Analyze(text string, entities []string) ([]Entity, error)
}

// compositeAnalyzer 组合字段名分析器、规则引擎和可选的 NER 模型分析器。
// 执行顺序：FieldAnalyzer → RuleEngine → modelAnalyzer，最后合并去重。
type compositeAnalyzer struct {
	fieldAnalyzer *FieldAnalyzer
	ruleEngine    *RuleEngine
	modelAnalyzer *modelAnalyzer
}

// NewAnalyzer 创建完整的分析器链。
func NewAnalyzer(config *RedactionConfig) (Analyzer, error) {
	engine, err := NewRuleEngine(config)
	if err != nil {
		return nil, err
	}

	ca := &compositeAnalyzer{
		fieldAnalyzer: NewFieldAnalyzer(config),
		ruleEngine:    engine,
	}

	if config.NER.Enabled {
		ca.modelAnalyzer = newModelAnalyzer(config.NER, config)
	}

	return ca, nil
}

// Analyze 依次调用各分析器并合并结果。
func (a *compositeAnalyzer) Analyze(text string, entities []string) ([]Entity, error) {
	var all []Entity

	// 1. 字段名/姓氏启发式（结构化数据，零外部依赖）
	if fieldEnts, err := a.fieldAnalyzer.Analyze(text, entities); err == nil {
		all = append(all, fieldEnts...)
	}

	// 2. 规则引擎（正则、静态/动态规则）
	if ruleEnts, err := a.ruleEngine.Analyze(text, entities); err == nil {
		all = append(all, ruleEnts...)
	}

	// 3. 本地 NER 模型（自由文本，带超时与缓存）
	if a.modelAnalyzer != nil {
		if modelEnts, err := a.modelAnalyzer.Analyze(text, entities); err == nil {
			all = append(all, modelEnts...)
		}
	}

	// 4. 合并去重
	return MergeEntities(all), nil
}

// defaultAnalyzer 是旧的默认检测器（保留用于兼容某些独立调用场景）。
type defaultAnalyzer struct {
	engine *RuleEngine
}

// Analyze 检测文本中的敏感实体
func (a *defaultAnalyzer) Analyze(text string, entities []string) ([]Entity, error) {
	return a.engine.Analyze(text, entities)
}
