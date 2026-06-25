package redaction

import (
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FieldAnalyzer 基于字段名和中文姓氏规则识别姓名/用户名。
// 它擅长处理结构化数据（JSON key/value、JWT claim、表单字段），不依赖外部模型。
type FieldAnalyzer struct {
	cfg             *RedactionConfig
	personKeyRe     *regexp.Regexp
	userNameKeyRe   *regexp.Regexp
	surnameRe       *regexp.Regexp
}

// NewFieldAnalyzer 创建字段名分析器
func NewFieldAnalyzer(cfg *RedactionConfig) *FieldAnalyzer {
	personKeys := []string{
		"name", "full_name", "fullname", "real_name", "realname",
		"display_name", "displayname", "nick_name", "nickname",
		"given_name", "givenname", "family_name", "familyname",
		"surname", "first_name", "firstname", "last_name", "lastname",
		"联系人", "姓名", "名字", "昵称",
	}
	userNameKeys := []string{
		"user_name", "username", "login", "account",
		"userid", "user_id", "会员名", "账号", "账户", "用户名",
	}

	return &FieldAnalyzer{
		cfg:           cfg,
		personKeyRe:   buildFieldValueRegex(personKeys),
		userNameKeyRe: buildFieldValueRegex(userNameKeys),
		surnameRe:     buildSurnameRegex(),
	}
}

// Analyze 扫描文本中的姓名/用户名实体。
// entities 参数用于过滤实体类型；为空时按配置中启用的内置实体类型过滤。
func (fa *FieldAnalyzer) Analyze(text string, entities []string) ([]Entity, error) {
	filter := entities
	if len(filter) == 0 {
		filter = fa.cfg.BuiltInEntityTypeList()
	}

	var results []Entity

	wantPerson := contains(filter, "PERSON_NAME")
	wantUser := contains(filter, "USER_NAME")

	if wantPerson {
		results = append(results, fa.matchFieldValues(text, "PERSON_NAME", fa.personKeyRe)...)
		results = append(results, fa.matchSurnameNames(text)...)
	}
	if wantUser {
		results = append(results, fa.matchFieldValues(text, "USER_NAME", fa.userNameKeyRe)...)
	}

	return results, nil
}

// matchFieldValues 根据字段名正则匹配 key:value 对。
func (fa *FieldAnalyzer) matchFieldValues(text, entityType string, re *regexp.Regexp) []Entity {
	var results []Entity
	op := fa.cfg.GetBuiltInEntityOperator(entityType)

	matches := re.FindAllStringSubmatchIndex(text, -1)
	for _, m := range matches {
		if len(m) < 8 {
			continue
		}
		valStart, valEnd := m[6], m[7]
		value := text[valStart:valEnd]

		// 去除 value 两端的引号
		trimmed := strings.Trim(value, `"'`)
		leftSkip := len(value) - len(strings.TrimLeft(value, `"'`))
		rightSkip := len(value) - len(strings.TrimRight(value, `"'`))
		if trimmed == "" {
			continue
		}
		// 跳过布尔、null、纯数字
		lower := strings.ToLower(trimmed)
		if lower == "true" || lower == "false" || lower == "null" {
			continue
		}
		if _, err := strconv.ParseFloat(trimmed, 64); err == nil {
			continue
		}
		// 限制长度，避免把整段文本当名字
		if utf8.RuneCountInString(trimmed) > 40 {
			continue
		}

		start := valStart + leftSkip
		end := valEnd - rightSkip
		results = append(results, Entity{
			Type:     entityType,
			Start:    start,
			End:      end,
			Text:     trimmed,
			Score:    0.95,
			RuleID:   "field_" + strings.ToLower(entityType),
			Operator: op,
		})
	}
	return results
}

// 常见中文虚词/助词/常见非人名用字，用于过滤假阳性。
var commonParticles = map[rune]bool{
	'的': true, '是': true, '在': true, '和': true, '了': true, '着': true, '过': true,
	'把': true, '被': true, '给': true, '让': true, '向': true, '从': true, '到': true,
	'对': true, '为': true, '与': true, '及': true, '或': true, '而': true, '但': true,
	'因': true, '所': true, '等': true, '呢': true, '吗': true, '吧': true, '啊': true,
	'哦': true, '呀': true, '都': true, '还': true, '又': true, '也': true, '就': true,
	'才': true, '却': true, '并': true, '且': true, '虽': true, '这': true, '那': true,
	'有': true, '没': true, '不': true, '很': true, '太': true, '要': true, '会': true,
	'能': true, '可': true, '已': true, '将': true, '以': true, '则': true, '其': true,
	'上': true, '下': true, '中': true, '大': true, '小': true, '多': true, '少': true,
}

// matchSurnameNames 基于中文姓氏 + 1~2 个汉字做启发式姓名识别。
// 增加虚词过滤：如果姓氏后面跟的是常见助词/介词，则忽略这一条。
func (fa *FieldAnalyzer) matchSurnameNames(text string) []Entity {
	var results []Entity
	op := fa.cfg.GetBuiltInEntityOperator("PERSON_NAME")
	runes := []rune(text)

	matches := fa.surnameRe.FindAllStringSubmatchIndex(text, -1)
	for _, m := range matches {
		if len(m) < 4 {
			continue
		}
		start, end := m[2], m[3]
		name := text[start:end]
		// 姓名长度 2~3 个汉字
		runeLen := utf8.RuneCountInString(name)
		if runeLen < 2 || runeLen > 3 {
			continue
		}
		// 过滤：匹配到的最后一个字符如果是虚词，跳过
		nameRunes := []rune(name)
		if commonParticles[nameRunes[len(nameRunes)-1]] {
			continue
		}
		// 过滤：匹配后面的第一个字符如果是虚词，跳过（如「张三也」后跟「也」时）
		endRuneIdx := utf8.RuneCountInString(text[:end])
		if endRuneIdx < len(runes) && commonParticles[runes[endRuneIdx]] {
			continue
		}
		results = append(results, Entity{
			Type:     "PERSON_NAME",
			Start:    start,
			End:      end,
			Text:     name,
			Score:    0.55,
			RuleID:   "surname_heuristic",
			Operator: op,
		})
	}
	return results
}

// buildFieldValueRegex 构造字段名匹配正则。
// 可匹配 JSON、HTTP header、JWT claim 等 key:value 形式。
func buildFieldValueRegex(keys []string) *regexp.Regexp {
	escaped := make([]string, 0, len(keys))
	for _, k := range keys {
		escaped = append(escaped, regexp.QuoteMeta(k))
	}
	// key 前面是非单词/非引号字符或起始；key 本身可有可选引号；
	// key 与 value 之间支持 : = 及可选空格；value 最多 80 字节（引号可选）。
	pattern := `(?i)(?:^|[^\w"\'])(["']?)(` + strings.Join(escaped, "|") + `)["']?\s*[:：=]\s*["']?([^"'\s,;}\]\\]{1,80})["']?`
	return regexp.MustCompile(pattern)
}

// buildSurnameRegex 构造中文姓名启发式正则。
func buildSurnameRegex() *regexp.Regexp {
	surnames := []string{
		"李", "王", "张", "刘", "陈", "杨", "黄", "赵", "周", "吴",
		"徐", "孙", "马", "朱", "胡", "郭", "何", "林", "罗", "高",
		"郑", "梁", "谢", "宋", "唐", "许", "韩", "冯", "邓", "曹",
		"彭", "曾", "肖", "田", "董", "袁", "潘", "于", "蒋", "蔡",
		"余", "杜", "叶", "程", "苏", "魏", "吕", "丁", "任", "沈",
		"姚", "卢", "姜", "崔", "钟", "谭", "陆", "汪", "范", "金",
		"石", "廖", "贾", "夏", "付", "方", "白", "邹", "孟", "熊",
		"秦", "邱", "江", "尹", "薛", "闫", "段", "雷", "侯", "龙",
		"史", "黎", "贺", "顾", "毛", "郝", "龚", "邵", "万", "钱",
		"严", "覃", "武", "戴", "莫", "孔", "常", "汤", "赖", "萧",
		"傅", "阎", "包", "储", "侯", "车", "江", "池", "汪", "沃",
	}
	// 姓氏后接 1~2 个汉字（常见中文名为 2~3 字）。
	pattern := `((?:` + strings.Join(surnames, "|") + `)[\p{Han}]{1,2})`
	return regexp.MustCompile(pattern)
}
