package redaction

import (
	"fmt"
	"regexp"
	"sort"
)

// RuleEngine 规则引擎
type RuleEngine struct {
	rules []CompiledRule
}

// NewRuleEngine 创建规则引擎
func NewRuleEngine(config *RedactionConfig) (*RuleEngine, error) {
	var rules []Rule

	// 内置规则
	builtIn := BuiltInRules()
	builtInMap := make(map[string]Rule)
	for _, rule := range builtIn {
		builtInMap[rule.EntityType] = rule
	}

	// 根据 built_in_entities 启用内置规则，并应用配置的操作符
	for _, entity := range config.BuiltInEntities {
		if !entity.Enabled {
			continue
		}
		rule, ok := builtInMap[entity.Type]
		if !ok {
			continue
		}
		rule.Operator = entity.Operator
		if rule.Operator.Type == "" {
			rule.Operator = config.DefaultOperator
		}
		rules = append(rules, rule)
	}

	// 静态规则（关键词）
	for _, rule := range config.StaticRules {
		r := rule
		if r.Operator.Type == "" {
			r.Operator = config.DefaultOperator
		}
		// 静态规则使用 keyword 生成正则 pattern
		if r.Keyword != "" {
			r.Pattern = fmt.Sprintf(`(?<![\w` + "`" + `])%s(?![\w` + "`" + `])`, regexp.QuoteMeta(r.Keyword))
		}
		rules = append(rules, r)
	}

	// 动态规则（正则）
	for _, rule := range config.DynamicRules {
		r := rule
		if r.Operator.Type == "" {
			r.Operator = config.DefaultOperator
		}
		rules = append(rules, r)
	}

	// 静态规则按关键词长度降序排序，避免短词覆盖长词
	sort.SliceStable(rules, func(i, j int) bool {
		li, lj := 0, 0
		if rules[i].Pattern != "" {
			li = len(rules[i].Pattern)
		}
		if rules[j].Pattern != "" {
			lj = len(rules[j].Pattern)
		}
		return li > lj
	})

	compiled := make([]CompiledRule, 0, len(rules))
	seenIDs := make(map[string]bool)
	for _, rule := range rules {
		if rule.ID == "" {
			// 为没有 ID 的规则生成一个
			rule.ID = fmt.Sprintf("rule_%s", rule.EntityType)
		}
		if seenIDs[rule.ID] {
			// ID 重复时追加序号
			baseID := rule.ID
			idx := 1
			for seenIDs[rule.ID] {
				rule.ID = fmt.Sprintf("%s_%d", baseID, idx)
				idx++
			}
		}
		seenIDs[rule.ID] = true

		// 验证正则
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return nil, fmt.Errorf("invalid pattern in rule %s: %w", rule.ID, err)
		}
		compiled = append(compiled, CompiledRule{Rule: rule})
	}

	return &RuleEngine{rules: compiled}, nil
}

// Analyze 检测文本中的敏感实体
func (e *RuleEngine) Analyze(text string, entities []string) ([]Entity, error) {
	cfg := Config()
	var results []Entity
	seen := make(map[[2]int]bool)

	for _, rule := range e.rules {
		// 如果指定了实体类型过滤
		if len(entities) > 0 && !contains(entities, rule.EntityType) {
			continue
		}

		// 跳过超过置信度阈值的
		if rule.Score < cfg.ScoreThreshold {
			continue
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, err
		}

		matches := re.FindAllStringIndex(text, -1)
		for _, m := range matches {
			pos := [2]int{m[0], m[1]}
			if seen[pos] {
				continue
			}
			seen[pos] = true

			results = append(results, Entity{
				Type:     rule.EntityType,
				Start:    m[0],
				End:      m[1],
				Text:     text[m[0]:m[1]],
				Score:    rule.Score,
				RuleID:   rule.ID,
				Operator: rule.Operator,
			})
		}
	}

	// 按起始位置排序，相同起始位置按长度降序
	sort.Slice(results, func(i, j int) bool {
		if results[i].Start == results[j].Start {
			return results[i].End > results[j].End
		}
		return results[i].Start < results[j].Start
	})

	// 处理重叠：保留最长匹配
	results = mergeOverlapping(results)
	return results, nil
}

// mergeOverlapping 处理重叠实体，保留最长匹配
func mergeOverlapping(entities []Entity) []Entity {
	if len(entities) == 0 {
		return entities
	}

	var merged []Entity
	current := entities[0]
	for i := 1; i < len(entities); i++ {
		next := entities[i]
		// 如果 next 与 current 重叠，选择更长的
		if next.Start < current.End {
			if next.End-next.Start > current.End-current.Start {
				current = next
			}
		} else {
			merged = append(merged, current)
			current = next
		}
	}
	merged = append(merged, current)
	return merged
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
