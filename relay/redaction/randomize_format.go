package redaction

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// RandomizePhone 对中国大陆手机号进行格式保持随机化
// 生成 1[3-9]xxxxxxxx 格式的假手机号，同一会话内相同原手机号返回相同假号
func RandomizePhone(original string, state *MaskingState) string {
	if original == "" || state == nil {
		return original
	}
	if existing := state.GetMaskedMappingKey(original); existing != "" {
		return existing
	}

	prefixes := []string{
		"130", "131", "132", "133", "134", "135", "136", "137", "138", "139",
		"150", "151", "152", "153", "155", "156", "157", "158", "159",
		"180", "181", "182", "183", "184", "185", "186", "187", "188", "189",
		"190", "191", "193", "195", "196", "197", "198", "199",
	}

	exclude := buildExcludeSet(state)
	var fake string
	for attempts := 0; attempts < 200; attempts++ {
		prefix := prefixes[randIntn(len(prefixes))]
		suffix := randomDigits(8)
		candidate := prefix + suffix
		if !exclude[candidate] {
			fake = candidate
			break
		}
	}

	if fake == "" {
		fake = "138" + randomDigits(8)
	}

	state.SetMaskedMapping(fake, original)
	return fake
}

// RandomizeIDCard 对中国大陆身份证号进行格式保持随机化
// 生成 18 位格式正确的假身份证号（含校验码），同一会话内相同原身份证号返回相同假号
func RandomizeIDCard(original string, state *MaskingState) string {
	if original == "" || state == nil {
		return original
	}
	if existing := state.GetMaskedMappingKey(original); existing != "" {
		return existing
	}

	areaCodes := []string{
		"110101", "310115", "440106", "500101", "330106",
		"510107", "420106", "610104", "370102", "320106",
		"430103", "410102", "230103", "210102", "120101",
		"530102", "450102", "650102", "830000", "820000",
	}

	exclude := buildExcludeSet(state)
	var fake string
	for attempts := 0; attempts < 200; attempts++ {
		area := areaCodes[randIntn(len(areaCodes))]
		year := 1980 + randIntn(26)
		month := 1 + randIntn(12)
		day := 1 + randIntn(28)
		birth := formatDate(year, month, day)
		seq := randomDigits(3)
		base := area + birth + seq
		candidate := base + idCardCheckCode(base)
		if !exclude[candidate] {
			fake = candidate
			break
		}
	}

	if fake == "" {
		fake = "11010119900101123X"
	}

	state.SetMaskedMapping(fake, original)
	return fake
}

// RandomizeEmail 对电子邮箱进行格式保持随机化
// 生成 local@domain 格式的假邮箱，同一会话内相同原邮箱返回相同假邮箱
func RandomizeEmail(original string, state *MaskingState) string {
	if original == "" || state == nil {
		return original
	}
	if existing := state.GetMaskedMappingKey(original); existing != "" {
		return existing
	}

	domains := []string{
		"example.com", "test.com", "demo.org", "sample.net",
		"mail.com", "email.org", "dummy.net", "sandbox.com",
	}

	local := generateEmailLocal(original)
	exclude := buildExcludeSet(state)
	var fake string
	for attempts := 0; attempts < 50; attempts++ {
		domain := domains[randIntn(len(domains))]
		candidate := local + "@" + domain
		if !exclude[candidate] {
			fake = candidate
			break
		}
	}

	if fake == "" {
		fake = local + "@example.com"
	}

	state.SetMaskedMapping(fake, original)
	return fake
}

// generateEmailLocal 生成一个与原邮箱长度接近的随机用户名
func generateEmailLocal(original string) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := len(original)
	if length < 3 {
		length = 6
	} else if length > 12 {
		length = 12
	}

	var b strings.Builder
	b.WriteByte(chars[randIntn(26)]) // 首字符为字母
	for i := 1; i < length; i++ {
		b.WriteByte(chars[randIntn(len(chars))])
	}
	return b.String()
}

// RandomizeBankCard 对银行卡号进行格式保持随机化
// 生成 16-19 位、通过 Luhn 校验的假卡号，同一会话内相同原卡号返回相同假卡号
func RandomizeBankCard(original string, state *MaskingState) string {
	if original == "" || state == nil {
		return original
	}
	if existing := state.GetMaskedMappingKey(original); existing != "" {
		return existing
	}

	// 常见卡组织前缀
	prefixes := [][]int{
		{4},                   // Visa
		{5, 1}, {5, 2}, {5, 3}, {5, 4}, {5, 5}, // MasterCard
		{6, 2},                // 银联
		{3, 5},                // JCB
	}

	length := len(original)
	if length < 16 || length > 19 {
		length = 16
	}

	exclude := buildExcludeSet(state)
	var fake string
	for attempts := 0; attempts < 200; attempts++ {
		prefix := prefixes[randIntn(len(prefixes))]
		digits := make([]int, length)
		copy(digits, prefix)
		for i := len(prefix); i < length-1; i++ {
			digits[i] = randIntn(10)
		}
		digits[length-1] = luhnCheckDigit(digits[:length-1])
		candidate := digitsToString(digits)
		if !exclude[candidate] {
			fake = candidate
			break
		}
	}

	if fake == "" {
		fake = "6214830000000000" // 默认银联测试卡格式
	}

	state.SetMaskedMapping(fake, original)
	return fake
}

// luhnCheckDigit 计算 Luhn 校验位，使完整卡号通过校验
func luhnCheckDigit(digits []int) int {
	sum := 0
	alternate := true
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return (10 - (sum % 10)) % 10
}

// luhnCheckDigitForString 计算字符串数字序列的 Luhn 校验位
func luhnCheckDigitForString(s string) int {
	digits := make([]int, 0, len(s))
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			digits = append(digits, int(ch-'0'))
		}
	}
	return luhnCheckDigit(digits)
}

// digitsToString 把数字切片拼接为字符串
func digitsToString(digits []int) string {
	var b strings.Builder
	for _, d := range digits {
		b.WriteByte(byte('0' + d))
	}
	return b.String()
}

// RandomizeLicensePlate 对中国大陆车牌号进行格式保持随机化
// 生成 民用车/新能源 格式的假车牌，同一会话内相同原车牌返回相同假车牌
func RandomizeLicensePlate(original string, state *MaskingState) string {
	if original == "" || state == nil {
		return original
	}
	if existing := state.GetMaskedMappingKey(original); existing != "" {
		return existing
	}

	provinces := []string{
		"京", "津", "沪", "渝", "冀", "豫", "云", "辽", "黑", "湘",
		"皖", "鲁", "新", "苏", "浙", "赣", "鄂", "桂", "甘", "晋",
		"蒙", "陕", "吉", "闽", "贵", "粤", "青", "藏", "川", "宁", "琼",
	}

	const letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
	const alphanum = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789"

	province := provinces[randIntn(len(provinces))]
	letter := string(letters[randIntn(len(letters))])

	// 新能源车牌多一位，简单按原车牌长度决定
	length := len(original)
	var candidate string
	if length >= 8 {
		// 新能源：省份 + D/F + 1位字母/数字 + 5位数字/字母
		energyType := "DF"[randIntn(2)]
		extra := string(alphanum[randIntn(len(alphanum))])
		seq := randomAlphaNum(5, alphanum)
		candidate = province + string(energyType) + extra + seq
	} else {
		seq := randomAlphaNum(5, alphanum)
		candidate = province + letter + seq
	}

	state.SetMaskedMapping(candidate, original)
	return candidate
}

// randomAlphaNum 从字符集中生成 n 位随机字符串
func randomAlphaNum(n int, charset string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(charset[randIntn(len(charset))])
	}
	return b.String()
}

// idCardCheckCode 计算 18 位身份证号的校验码
func idCardCheckCode(base17 string) string {
	if len(base17) != 17 {
		return "X"
	}
	weights := []int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
	codes := []string{"1", "0", "X", "9", "8", "7", "6", "5", "4", "3", "2"}
	sum := 0
	for i, ch := range base17 {
		d, err := strconv.Atoi(string(ch))
		if err != nil {
			return "X"
		}
		sum += d * weights[i]
	}
	return codes[sum%11]
}

// randomDigits 生成 n 位随机数字字符串
func randomDigits(n int) string {
	if n <= 0 {
		return ""
	}
	max := big.NewInt(0).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return strings.Repeat("0", n)
	}
	return fmt.Sprintf("%0"+strconv.Itoa(n)+"d", num.Int64())
}

func formatDate(year, month, day int) string {
	return fmt.Sprintf("%04d%02d%02d", year, month, day)
}

// randIntn 返回 [0, n) 的随机整数
func randIntn(n int) int {
	if n <= 0 {
		return 0
	}
	num, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return 0
	}
	return int(num.Int64())
}

// buildExcludeSet 构建已用假值排除集合，避免冲突
func buildExcludeSet(state *MaskingState) map[string]bool {
	exclude := make(map[string]bool)
	if state == nil {
		return exclude
	}
	for k := range state.MaskedInverse {
		exclude[k] = true
	}
	for _, v := range state.Inverse {
		exclude[v] = true
	}
	for _, v := range state.Forward {
		exclude[v] = true
	}
	return exclude
}
