package redaction

// BuiltInRules 返回内置 PII 规则
func BuiltInRules() []Rule {
	return []Rule{
		{
			ID:           "id_card",
			Name:         "中国大陆身份证",
			EntityType:   "ID_CARD",
			Pattern:      `\b[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b`,
			Score:        1.0,
			Operator:     OperatorConfig{Type: OpSymbolize},
			DigitLengths: []int{18},
		},
		{
			ID:           "phone_number",
			Name:         "中国大陆手机号",
			EntityType:   "PHONE_NUMBER",
			Pattern:      `\b1[3-9]\d{9}\b`,
			Score:        1.0,
			Operator:     OperatorConfig{Type: OpSymbolize},
			DigitLengths: []int{11},
		},
		{
			ID:         "email_address",
			Name:       "电子邮箱",
			EntityType: "EMAIL_ADDRESS",
			Pattern:    `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`,
			Score:      1.0,
			Operator:   OperatorConfig{Type: OpSymbolize},
		},
		{
			ID:           "bank_card",
			Name:         "银行卡号",
			EntityType:   "BANK_CARD",
			Pattern:      `\b(?:4\d{3}|5[1-5]\d{2}|6\d{3}|3[47]\d{2})(?:[- ]?\d{4}){3}[- ]?\d{4}\b|\b\d{16,19}\b`,
			Score:        1.0,
			Operator:     OperatorConfig{Type: OpSymbolize},
			DigitLengths: []int{16, 17, 18, 19},
		},
		{
			ID:         "license_plate",
			Name:       "中国车牌号",
			EntityType: "LICENSE_PLATE",
			Pattern:    `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z][A-Z0-9]{4,5}[A-Z0-9挂学警港澳]?`,
			Score:      1.0,
			Operator:   OperatorConfig{Type: OpSymbolize},
		},
		{
			ID:         "ipv4_address",
			Name:       "IPv4 地址",
			EntityType: "IP_ADDRESS",
			Pattern:    `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`,
			Score:      1.0,
			Operator:   OperatorConfig{Type: OpSymbolize},
		},
	}
}

// BuiltInEntityNames 返回内置实体类型到名称的映射
func BuiltInEntityNames() map[string]string {
	names := make(map[string]string)
	for _, rule := range BuiltInRules() {
		if _, ok := names[rule.EntityType]; !ok {
			names[rule.EntityType] = rule.Name
		}
	}
	return names
}

// BuiltInEntityTypes 返回所有内置实体类型
func BuiltInEntityTypes() []string {
	types := make([]string, 0, len(BuiltInRules()))
	seen := make(map[string]bool)
	for _, rule := range BuiltInRules() {
		if !seen[rule.EntityType] {
			seen[rule.EntityType] = true
			types = append(types, rule.EntityType)
		}
	}
	return types
}

// BuiltInEntityConfigs 返回默认的内置实体配置列表
func BuiltInEntityConfigs() []BuiltInEntityConfig {
	configs := make([]BuiltInEntityConfig, 0)
	names := BuiltInEntityNames()
	seen := make(map[string]bool)
	for _, rule := range BuiltInRules() {
		if seen[rule.EntityType] {
			continue
		}
		seen[rule.EntityType] = true
		configs = append(configs, BuiltInEntityConfig{
			Type:     rule.EntityType,
			Name:     names[rule.EntityType],
			Enabled:  true,
			Operator: OperatorConfig{Type: OpSymbolize},
			Pattern:  rule.Pattern,
		})
	}
	return configs
}
