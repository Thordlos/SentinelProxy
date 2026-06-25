package redaction

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/sentinelproxy/sentinelproxy/relay/model"
)

func newTestConfig() *RedactionConfig {
	cfg := DefaultRedactionConfig()
	cfg.Enabled = true
	cfg.StateDir = filepath.Join(os.TempDir(), "sentinel_test")
	_ = os.MkdirAll(cfg.StateDir, 0755)
	return &cfg
}

func enableEntityType(cfg *RedactionConfig, entityType string) {
	for i := range cfg.BuiltInEntities {
		if cfg.BuiltInEntities[i].Type == entityType {
			cfg.BuiltInEntities[i].Enabled = true
			return
		}
	}
	cfg.BuiltInEntities = append(cfg.BuiltInEntities, BuiltInEntityConfig{
		Type:     entityType,
		Name:     entityType,
		Enabled:  true,
		Operator: OperatorConfig{Type: OpSymbolize},
	})
}

func TestBuiltInRules(t *testing.T) {
	cfg := newTestConfig()
	engine, err := NewRuleEngine(cfg)
	if err != nil {
		t.Fatalf("NewRuleEngine failed: %v", err)
	}

	text := "我的手机号是13812345678，邮箱是alice@example.com"
	entities, err := engine.Analyze(text, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	if len(entities) != 2 {
		t.Fatalf("expected 2 entities, got %d", len(entities))
	}

	types := make(map[string]bool)
	for _, e := range entities {
		types[e.Type] = true
	}
	if !types["PHONE_NUMBER"] {
		t.Errorf("expected PHONE_NUMBER entity")
	}
	if !types["EMAIL_ADDRESS"] {
		t.Errorf("expected EMAIL_ADDRESS entity")
	}
}

func TestBuiltInEntityConfigsIncludePattern(t *testing.T) {
	configs := BuiltInEntityConfigs()
	rules := BuiltInRules()

	ruleMap := make(map[string]string)
	for _, rule := range rules {
		if _, ok := ruleMap[rule.EntityType]; !ok {
			ruleMap[rule.EntityType] = rule.Pattern
		}
	}

	for _, cfg := range configs {
		expected, ok := ruleMap[cfg.Type]
		if !ok {
			t.Errorf("built-in entity %s has no corresponding rule", cfg.Type)
			continue
		}
		if cfg.Pattern == "" {
			t.Errorf("built-in entity %s should expose non-empty pattern", cfg.Type)
		}
		if cfg.Pattern != expected {
			t.Errorf("pattern mismatch for %s: got %q, want %q", cfg.Type, cfg.Pattern, expected)
		}
	}
}

func TestMaskText(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_session", cfg)
	text := "联系我 13812345678 或 alice@example.com"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if masked == text {
		t.Errorf("expected masked text, got original: %s", masked)
	}

	if state.GetOriginal("EMAIL_ADDRESS_1") != "alice@example.com" {
		t.Errorf("expected EMAIL_ADDRESS_1 -> alice@example.com, got %s", state.GetOriginal("EMAIL_ADDRESS_1"))
	}
	if state.GetOriginal("PHONE_NUMBER_1") != "13812345678" {
		t.Errorf("expected PHONE_NUMBER_1 -> 13812345678, got %s", state.GetOriginal("PHONE_NUMBER_1"))
	}

	t.Logf("masked: %s", masked)
}

func TestUnmaskText(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_session", cfg)
	text := "联系我 13812345678 或 alice@example.com"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("expected restored text '%s', got '%s'", text, restored)
	}
}

func TestMaskTextWithPreserve(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultOperator = OperatorConfig{Type: OpSymbolize}
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_session", cfg)
	text := "请分析``英伟达``和我的手机号13812345678的产品"
	masked, err := MaskTextWithPreserve(text, state)
	if err != nil {
		t.Fatalf("MaskTextWithPreserve failed: %v", err)
	}

	if !strings.Contains(masked, "英伟达") {
		t.Errorf("preserved fragment should remain: %s", masked)
	}
	if strings.Contains(masked, "13812345678") {
		t.Errorf("unpreserved phone number should be masked: %s", masked)
	}
	if !strings.Contains(masked, "PHONE_NUMBER") {
		t.Errorf("masked text should contain placeholder: %s", masked)
	}
	t.Logf("masked with preserve: %s", masked)
}

func TestStreamingUnmasker(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_session", cfg)
	_, err := MaskText("我的邮箱是 alice@example.com", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	unmasker := NewStreamingUnmasker(state)

	// 模拟跨 chunk 截断
	out1 := unmasker.Write("联系 ")
	out2 := unmasker.Write("<SENTINEL>EMAIL")
	out3 := unmasker.Write("_ADDRESS_1</SENTINEL> ")
	out4 := unmasker.Write("了解")
	out5 := unmasker.Flush()

	full := out1 + out2 + out3 + out4 + out5
	expected := "联系 alice@example.com 了解"
	if full != expected {
		t.Errorf("expected '%s', got '%s'", expected, full)
	}
}

func TestStreamingUnmaskerPartialMarker(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_session", cfg)
	unmasker := NewStreamingUnmasker(state)

	// 普通文本中的 `` 不是代号
	out1 := unmasker.Write("他说 ``")
	out2 := unmasker.Write("hello`` 世界")
	out3 := unmasker.Flush()

	full := out1 + out2 + out3
	expected := "他说 ``hello`` 世界"
	if full != expected {
		t.Errorf("expected '%s', got '%s'", expected, full)
	}
}

func TestMaskingStateSaveAndLoad(t *testing.T) {
	cfg := newTestConfig()
	state := NewMaskingState("test_save_load", cfg)
	state.GetCode("敏感公司", "COMPANY")
	state.GetCode("13812345678", "PHONE_NUMBER")

	if err := state.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := LoadMaskingState("test_save_load", cfg)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.GetOriginal("COMPANY_1") != "敏感公司" {
		t.Errorf("expected COMPANY_1 -> 敏感公司")
	}
	if loaded.GetOriginal("PHONE_NUMBER_1") != "13812345678" {
		t.Errorf("expected PHONE_NUMBER_1 -> 13812345678")
	}
}

func TestRedactRequest(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	req := &model.GeneralOpenAIRequest{
		Messages: []model.Message{
			{Role: "system", Content: "系统提示：13812345678"},
			{Role: "user", Content: "我的手机号是13812345678"},
			{Role: "assistant", Content: "我已记录您的手机号13812345678"},
		},
	}

	state := NewMaskingState("test_react", cfg)
	if err := RedactRequest(req, state); err != nil {
		t.Fatalf("RedactRequest failed: %v", err)
	}

	// system 消息不应被脱敏
	if req.Messages[0].Content != "系统提示：13812345678" {
		t.Errorf("system message should not be masked, got: %v", req.Messages[0].Content)
	}

	// user 消息应该被脱敏
	userContent := req.Messages[1].Content.(string)
	if userContent == "我的手机号是13812345678" {
		t.Errorf("user message should be masked")
	}
	if strings.Contains(userContent, "13812345678") {
		t.Errorf("user message should not contain original phone: %s", userContent)
	}

	// assistant 消息不应被处理
	assistantContent := req.Messages[2].Content.(string)
	if assistantContent != "我已记录您的手机号13812345678" {
		t.Errorf("assistant message should remain unchanged, got: %s", assistantContent)
	}
}

func TestUnmaskMaskOperation(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultOperator = OperatorConfig{Type: OpMask, MaskChar: "*", CharsToMask: 4, FromEnd: false}
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_mask_restore", cfg)
	text := "我的手机号是13812345678"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if masked == text {
		t.Errorf("expected masked text, got original: %s", masked)
	}
	if !strings.Contains(masked, "****") {
		t.Errorf("expected masked text to contain ****, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("expected restored text '%s', got '%s'", text, restored)
	}

	t.Logf("masked: %s, restored: %s", masked, restored)
}

func TestStreamingUnmaskerSplitMarker(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_split_marker", cfg)
	_, err := MaskText("手机号13812345678", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	unmasker := NewStreamingUnmasker(state)

	// 模拟 <SENTINEL>PHONE_NUMBER_1</SENTINEL> 被拆成多个 chunk
	out1 := unmasker.Write("注册手机")
	out2 := unmasker.Write("<SENTIN")
	out3 := unmasker.Write("EL>PHONE")
	out4 := unmasker.Write("_NUMBER_1</SENTINEL>")
	out5 := unmasker.Flush()

	full := out1 + out2 + out3 + out4 + out5
	expected := "注册手机13812345678"
	if full != expected {
		t.Errorf("expected '%s', got '%s'", expected, full)
	}
}

func TestIPRandomizePrivateToPrivate(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_private", cfg)
	text := "源IP 10.0.0.50 和 192.168.1.100 需要检查"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 验证 IP 已被替换为不同的 IP
	if masked == text {
		t.Errorf("expected masked text, got original: %s", masked)
	}

	// 验证替换后仍是 IP 格式
	// 假 IP 应该仍是点分十进制格式，不含 SENTINEL 标记
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("fake IP should not contain SENTINEL markers: %s", masked)
	}

	// 验证假 IP 仍是私有地址
	// 提取文本中的 IP 地址
	ipPattern := `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`
	re := regexp.MustCompile(ipPattern)
	ips := re.FindAllString(masked, -1)
	if len(ips) < 2 {
		t.Errorf("expected at least 2 IPs in masked text, got %d: %s", len(ips), masked)
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			t.Errorf("expected valid IP, got: %s", ip)
			continue
		}
		if !isPrivateIP(parsed) {
			t.Errorf("expected private IP, got public: %s", ip)
		}
	}

	t.Logf("masked: %s", masked)
}

func TestIPRandomizePublicToPublic(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_public", cfg)
	text := "攻击源 207.154.238.21 来自国外"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if masked == text {
		t.Errorf("expected masked text, got original: %s", masked)
	}

	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("fake IP should not contain SENTINEL markers: %s", masked)
	}

	// 提取假 IP 并验证是公网地址
	ipPattern := `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`
	re := regexp.MustCompile(ipPattern)
	ips := re.FindAllString(masked, -1)
	if len(ips) < 1 {
		t.Errorf("expected at least 1 IP in masked text, got %d: %s", len(ips), masked)
	}
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if isPrivateIP(parsed) {
			t.Errorf("expected public IP, got private: %s", ip)
		}
	}

	t.Logf("masked: %s", masked)
}

func TestIPRandomizeRoundTrip(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_roundtrip", cfg)
	original := "源IP 207.154.238.21 目的IP 10.1.192.162"
	masked, err := MaskText(original, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if masked == original {
		t.Errorf("expected masked text, got original: %s", masked)
	}

	// 还原：假 IP → 原 IP
	restored := UnmaskText(masked, state)
	if restored != original {
		t.Errorf("round-trip failed:\n  original: %s\n  masked:   %s\n  restored: %s", original, masked, restored)
	}

	t.Logf("masked: %s\nrestored: %s", masked, restored)
}

func TestIPRandomizeSessionConsistency(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_session", cfg)

	// 第一次脱敏
	masked1, err := MaskText("IP是 207.154.238.21", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 第二次脱敏相同 IP（同一会话）
	masked2, err := MaskText("还是 207.154.238.21 这个IP", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 提取两次的假 IP
	ipPattern := `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`
	re := regexp.MustCompile(ipPattern)
	ips1 := re.FindAllString(masked1, -1)
	ips2 := re.FindAllString(masked2, -1)

	if len(ips1) < 1 || len(ips2) < 1 {
		t.Fatalf("expected IPs in both masked texts: %s / %s", masked1, masked2)
	}

	if ips1[0] != ips2[0] {
		t.Errorf("same original IP should map to same fake IP in same session: %s vs %s", ips1[0], ips2[0])
	}

	t.Logf("session consistency: %s -> %s, %s -> %s", "207.154.238.21", ips1[0], "207.154.238.21", ips2[0])
}

func TestIPRandomizeCrossClass(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{
			Type:                 OpIPRandom,
			IPRandomPreserveScope: true,
			IPRandomCrossClass:    true,
		}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_crossclass", cfg)

	// 脱敏多个 A 类私有地址，验证可能跨类
	var ips []string
	origTexts := []string{"10.0.0.50", "10.128.64.1", "10.255.255.254"}
	for _, ip := range origTexts {
		masked, err := MaskText("IP: "+ip, state)
		if err != nil {
			t.Fatalf("MaskText failed: %v", err)
		}
		ipPattern := `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`
		re := regexp.MustCompile(ipPattern)
		found := re.FindAllString(masked, -1)
		if len(found) > 0 {
			ips = append(ips, found[0])
		}
	}

	// 所有生成的都应该是私有 IP
	for _, ip := range ips {
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		if !isPrivateIP(parsed) {
			t.Errorf("expected private IP, got: %s", ip)
		}
	}

	t.Logf("generated private IPs: %v", ips)
}

func TestIPRandomizeStreaming(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_streaming", cfg)
	// 先注册一个映射：207.154.238.21 -> 某个假 IP
	masked, err := MaskText("207.154.238.21", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 提取假 IP
	ipPattern := `\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b`
	re := regexp.MustCompile(ipPattern)
	fakeIP := re.FindString(masked)
	if fakeIP == "" {
		t.Fatalf("could not extract fake IP from masked text: %s", masked)
	}
	t.Logf("fake IP: %s", fakeIP)

	unmasker := NewStreamingUnmasker(state)

	// 模拟流式分块：假 IP 被拆在多个 chunk 中
	out1 := unmasker.Write("发现来自 ")
	out2 := unmasker.Write(fakeIP[:len(fakeIP)-4]) // 先写前半部分
	out3 := unmasker.Write(fakeIP[len(fakeIP)-4:])  // 再写后半部分
	out4 := unmasker.Write(" 的攻击")
	out5 := unmasker.Flush()

	full := out1 + out2 + out3 + out4 + out5
	expected := "发现来自 207.154.238.21 的攻击"
	if full != expected {
		t.Errorf("streaming unmask failed:\n  expected: %s\n  got:      %s", expected, full)
	}

	t.Logf("streaming result: %s", full)
}

func TestIPRandomizeMaskedInverse(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpIPRandom}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_ip_inverse", cfg)
	_, err := MaskText("目标IP 10.1.192.162", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 验证 MaskedInverse 中有假 IP → 原始 IP 的映射
	if len(state.MaskedInverse) == 0 {
		t.Errorf("MaskedInverse should contain fakeIP -> originalIP mapping")
	}

	// 验证 ForwardIP 中有原始 IP → 假 IP 的映射
	if len(state.ForwardIP) == 0 {
		t.Errorf("ForwardIP should contain originalIP -> fakeIP mapping")
	}

	found := false
	for fakeIP, orig := range state.MaskedInverse {
		if orig == "10.1.192.162" {
			t.Logf("MaskedInverse: %s -> %s", fakeIP, orig)
			found = true
			break
		}
	}
	if !found {
		t.Errorf("MaskedInverse should map fake IP to '10.1.192.162', got: %v", state.MaskedInverse)
	}

	fakeIP := state.GetForwardIP("10.1.192.162")
	if fakeIP == "" {
		t.Errorf("ForwardIP should have mapping for '10.1.192.162'")
	}
	t.Logf("ForwardIP: 10.1.192.162 -> %s", fakeIP)
}

func TestUnmaskBytes(t *testing.T) {
	cfg := newTestConfig()
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_unmask_bytes", cfg)
	masked, err := MaskText("我的邮箱是 alice@example.com", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	resp := map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]any{
					"content": masked,
				},
			},
		},
	}
	data, _ := json.Marshal(resp)
	restored := UnmaskBytes(data, state)

	var result map[string]any
	if err := json.Unmarshal(restored, &result); err != nil {
		t.Fatalf("Unmarshal restored data failed: %v", err)
	}

	choices := result["choices"].([]any)
	msg := choices[0].(map[string]any)["message"].(map[string]any)
	content := msg["content"].(string)
	if content != "我的邮箱是 alice@example.com" {
		t.Errorf("expected restored content, got: %s", content)
	}
}

func TestOperatorAliasNormalization(t *testing.T) {
	tests := []struct {
		input    OperatorType
		expected OperatorType
	}{
		{"replace", OpSymbolize},
		{"ip_random", OpRandomize},
		{"symbolize", OpSymbolize},
		{"randomize", OpRandomize},
		{"mask", OpMask},
		{"tokenize", OpTokenize},
		{"block", OpBlock},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		got := NormalizeOperatorType(tt.input)
		if got != tt.expected {
			t.Errorf("NormalizeOperatorType(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}

	for _, tt := range tests {
		if tt.input == "unknown" {
			continue
		}
		if !IsValidOperatorType(tt.input) {
			t.Errorf("IsValidOperatorType(%q) should be true", tt.input)
		}
	}
	if IsValidOperatorType("unknown") {
		t.Errorf("IsValidOperatorType(\"unknown\") should be false")
	}
}

func TestConfigLoadWithLegacyOperators(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "redaction.yaml")

	legacyConfig := `enabled: true
fail_closed: true
score_threshold: 0
max_text_length: 1048576
cache_ttl_hours: 24
state_dir: logs/masking
code_style: typed
code_prefix: ENT
code_length: 6
log_raw_requests: false
default_operator:
    type: replace
built_in_entities:
    - type: IP_ADDRESS
      name: IPv4 地址
      enabled: true
      operator:
        type: ip_random
        ip_random_preserve_scope: true
        ip_random_cross_class: true
        ip_random_preserve_bits: 0
static_rules: []
dynamic_rules: []
`
	if err := os.WriteFile(configPath, []byte(legacyConfig), 0644); err != nil {
		t.Fatalf("write legacy config failed: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	cfg.NormalizeConfig()

	if cfg.DefaultOperator.Type != OpSymbolize {
		t.Errorf("default_operator: expected %q, got %q", OpSymbolize, cfg.DefaultOperator.Type)
	}

	ipOperator := cfg.GetBuiltInEntityOperator("IP_ADDRESS")
	if ipOperator.Type != OpRandomize {
		t.Errorf("IP_ADDRESS operator: expected %q, got %q", OpRandomize, ipOperator.Type)
	}

	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	state := NewMaskingState("test_legacy", cfg)
	text := "源IP 207.154.238.21"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}
	if strings.Contains(masked, "207.154.238.21") {
		t.Errorf("IP should be randomized, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}
}

func TestSymbolizeOperation(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultOperator = OperatorConfig{Type: OpSymbolize}
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_symbolize", cfg)
	text := "我的邮箱是 alice@example.com"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if !strings.Contains(masked, MarkerStart) {
		t.Errorf("expected symbolize to produce marker, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}
}

func TestTokenizeOperation(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultOperator = OperatorConfig{Type: OpTokenize, TokenLength: 16}
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_tokenize", cfg)
	text := "我的邮箱是 alice@example.com"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if masked == text {
		t.Errorf("expected masked text, got original: %s", masked)
	}

	// token 应该在 MaskedInverse 中
	if len(state.MaskedInverse) == 0 {
		t.Errorf("expected token mapping in MaskedInverse")
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}
}

func TestTokenizeSessionConsistency(t *testing.T) {
	cfg := newTestConfig()
	cfg.DefaultOperator = OperatorConfig{Type: OpTokenize, TokenLength: 16}
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Operator = cfg.DefaultOperator
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_tokenize_consistency", cfg)
	masked1, err := MaskText("alice@example.com", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}
	masked2, err := MaskText("再次联系 alice@example.com", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	// 两次脱敏相同邮箱应得到相同 token
	if !strings.HasSuffix(masked2, masked1) {
		t.Errorf("same original should produce same token: masked1=%q, masked2=%q", masked1, masked2)
	}

	// 检查 TokenForward 只有一个映射
	if len(state.TokenForward) != 1 {
		t.Errorf("expected 1 token forward mapping, got %d", len(state.TokenForward))
	}

	restored1 := UnmaskText(masked1, state)
	restored2 := UnmaskText(masked2, state)
	if restored1 != "alice@example.com" {
		t.Errorf("restore1 failed: %q", restored1)
	}
	if restored2 != "再次联系 alice@example.com" {
		t.Errorf("restore2 failed: %q", restored2)
	}
}

func TestRandomizePhone(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "PHONE_NUMBER", Name: "手机号", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_phone_random", cfg)
	text := "我的手机号是13812345678"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "13812345678") {
		t.Errorf("phone should be randomized, got: %s", masked)
	}
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("randomized phone should not contain SENTINEL marker, got: %s", masked)
	}

	phonePattern := `1[3-9]\d{9}`
	re := regexp.MustCompile(phonePattern)
	fakePhone := re.FindString(masked)
	if fakePhone == "" {
		t.Errorf("expected valid phone format in masked text, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}

	t.Logf("masked: %s", masked)
}

func TestRandomizePhoneSessionConsistency(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "PHONE_NUMBER", Name: "手机号", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_phone_session", cfg)
	masked1, err := MaskText("手机号13812345678", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}
	masked2, err := MaskText("再次联系13812345678", state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	phonePattern := `1[3-9]\d{9}`
	re := regexp.MustCompile(phonePattern)
	phone1 := re.FindString(masked1)
	phone2 := re.FindString(masked2)
	if phone1 == "" || phone2 == "" {
		t.Fatalf("expected phones in both masked texts: %s / %s", masked1, masked2)
	}
	if phone1 != phone2 {
		t.Errorf("same original phone should map to same fake phone: %s vs %s", phone1, phone2)
	}
}

func TestRandomizeIDCard(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "ID_CARD", Name: "身份证", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_idcard_random", cfg)
	text := "身份证号是110101199001011234"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "110101199001011234") {
		t.Errorf("ID card should be randomized, got: %s", masked)
	}
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("randomized ID card should not contain SENTINEL marker, got: %s", masked)
	}

	idPattern := `\d{17}[\dXx]`
	re := regexp.MustCompile(idPattern)
	fakeID := re.FindString(masked)
	if fakeID == "" {
		t.Errorf("expected valid ID card format in masked text, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}

	t.Logf("masked: %s", masked)
}

func TestRandomizeIDCardCheckCode(t *testing.T) {
	cases := []string{
		"110101199001011234",
		"310115198805162345",
	}
	for _, c := range cases {
		base := c[:17]
		check := idCardCheckCode(base)
		if len(check) != 1 {
			t.Errorf("expected single check code for %s, got %q", c, check)
		}
	}
}

func TestRandomizeBankCard(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "BANK_CARD", Name: "银行卡", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_bankcard_random", cfg)
	text := "我的银行卡号 6222021234567890123"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "6222021234567890123") {
		t.Errorf("bank card should be randomized, got: %s", masked)
	}
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("randomized bank card should not contain SENTINEL marker, got: %s", masked)
	}

	// 验证生成的是 16-19 位数字
	cardPattern := `\d{16,19}`
	re := regexp.MustCompile(cardPattern)
	fakeCard := re.FindString(masked)
	if fakeCard == "" {
		t.Errorf("expected valid bank card format in masked text, got: %s", masked)
	}
	if !luhnValid(fakeCard) {
		t.Errorf("generated bank card should pass Luhn check: %s", fakeCard)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}

	t.Logf("masked: %s", masked)
}

func luhnValid(s string) bool {
	sum := 0
	alternate := false
	for i := len(s) - 1; i >= 0; i-- {
		d := int(s[i] - '0')
		if d < 0 || d > 9 {
			return false
		}
		if alternate {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alternate = !alternate
	}
	return sum%10 == 0
}

func TestRandomizeEmail(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "EMAIL_ADDRESS", Name: "邮箱", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_email_random", cfg)
	text := "我的邮箱是 alice@example.com"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "alice@example.com") {
		t.Errorf("email should be randomized, got: %s", masked)
	}
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("randomized email should not contain SENTINEL marker, got: %s", masked)
	}

	emailPattern := `[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`
	re := regexp.MustCompile(emailPattern)
	fakeEmail := re.FindString(masked)
	if fakeEmail == "" {
		t.Errorf("expected valid email format in masked text, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}

	t.Logf("masked: %s", masked)
}

func TestRandomizeLicensePlate(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "LICENSE_PLATE", Name: "车牌号", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_plate_random", cfg)
	text := "车牌号是京A12345"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "京A12345") {
		t.Errorf("license plate should be randomized, got: %s", masked)
	}
	if strings.Contains(masked, "<SENTINEL>") {
		t.Errorf("randomized license plate should not contain SENTINEL marker, got: %s", masked)
	}

	platePattern := `[京津沪渝冀豫云辽黑湘皖鲁新苏浙赣鄂桂甘晋蒙陕吉闽贵粤青藏川宁琼][A-Z][A-Z0-9]{4,6}`
	re := regexp.MustCompile(platePattern)
	fakePlate := re.FindString(masked)
	if fakePlate == "" {
		t.Errorf("expected valid license plate format in masked text, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}

	t.Logf("masked: %s", masked)
}

func TestGreedyDigitLengthMatching(t *testing.T) {
	cfg := newTestConfig()
	for i := range cfg.BuiltInEntities {
		cfg.BuiltInEntities[i].Enabled = true
		cfg.BuiltInEntities[i].Operator = OperatorConfig{Type: OpRandomize}
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	tests := []struct {
		name        string
		text        string
		wantSameLen int
	}{
		{"18 位应优先识别为身份证并保持位数", "身份证号310115198805162345", 18},
		{"16 位应识别为银行卡并保持位数", "银行卡6222021234567890", 16},
		{"19 位应识别为银行卡并保持位数", "银行卡6222021234567890123", 19},
		{"11 位应识别为手机号并保持位数", "手机号15987654321", 11},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := NewMaskingState("greedy_"+tt.name, cfg)
			masked, err := MaskText(tt.text, state)
			if err != nil {
				t.Fatalf("MaskText failed: %v", err)
			}

			digitPattern := regexp.MustCompile(`\d+`)
			fake := digitPattern.FindString(masked)
			if len(fake) != tt.wantSameLen {
				t.Errorf("expected masked digit length %d, got %d (%s)", tt.wantSameLen, len(fake), masked)
			}

			restored := UnmaskText(masked, state)
			if restored != tt.text {
				t.Errorf("round-trip failed: expected %q, got %q", tt.text, restored)
			}

			t.Logf("masked: %s", masked)
		})
	}
}

func TestRandomizeOperation(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "IP_ADDRESS", Name: "IPv4 地址", Enabled: true, Operator: OperatorConfig{Type: OpRandomize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_randomize", cfg)
	text := "源IP 207.154.238.21"
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "207.154.238.21") {
		t.Errorf("IP should be randomized, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}
}

func TestMaskingStateHitCounts(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "PHONE_NUMBER", Name: "手机号", Enabled: true, Operator: OperatorConfig{Type: OpSymbolize}},
		{Type: "EMAIL_ADDRESS", Name: "邮箱", Enabled: true, Operator: OperatorConfig{Type: OpSymbolize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_hits", cfg)
	text := "手机13812345678，邮箱 alice@example.com，手机13812345678"
	if _, err := MaskText(text, state); err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if state.HitCounts["PHONE_NUMBER"] != 2 {
		t.Errorf("expected PHONE_NUMBER hit count 2, got %d", state.HitCounts["PHONE_NUMBER"])
	}
	if state.HitCounts["EMAIL_ADDRESS"] != 1 {
		t.Errorf("expected EMAIL_ADDRESS hit count 1, got %d", state.HitCounts["EMAIL_ADDRESS"])
	}
	if state.TotalHits() != 3 {
		t.Errorf("expected total hits 3, got %d", state.TotalHits())
	}
}

func TestMaskingStateDisplayID(t *testing.T) {
	cfg := newTestConfig()
	state := NewMaskingState("auth_abc123def456", cfg)
	if state.DisplayID() == "" {
		t.Errorf("expected non-empty display id")
	}
	if len(state.DisplayID()) != 16 {
		t.Errorf("expected display id length 16, got %d", len(state.DisplayID()))
	}
}

func TestSessionManagerUserIndex(t *testing.T) {
	cfg := newTestConfig()
	sm := NewSessionManager(cfg)

	state1 := NewMaskingState("session_1", cfg)
	state1.SetUserInfo(42, 100)
	state2 := NewMaskingState("session_2", cfg)
	state2.SetUserInfo(42, 101)
	state3 := NewMaskingState("session_3", cfg)
	state3.SetUserInfo(99, 200)

	sm.mu.Lock()
	sm.states["session_1"] = state1
	sm.states["session_2"] = state2
	sm.states["session_3"] = state3
	sm.updateUserIndexLocked(42, "session_1")
	sm.updateUserIndexLocked(42, "session_2")
	sm.updateUserIndexLocked(99, "session_3")
	sm.mu.Unlock()

	user42 := sm.ListUserSessions(42)
	if len(user42) != 2 {
		t.Errorf("expected 2 sessions for user 42, got %d", len(user42))
	}

	user99 := sm.ListUserSessions(99)
	if len(user99) != 1 {
		t.Errorf("expected 1 session for user 99, got %d", len(user99))
	}

	totalSessions, totalHits, hitCounts := sm.GetUserStats(42)
	if totalSessions != 2 {
		t.Errorf("expected total sessions 2, got %d", totalSessions)
	}
	if totalHits != 0 {
		t.Errorf("expected total hits 0, got %d", totalHits)
	}
	if len(hitCounts) != 0 {
		t.Errorf("expected empty hit counts, got %v", hitCounts)
	}
}

func TestSessionManagerGetSessionOwnership(t *testing.T) {
	cfg := newTestConfig()
	sm := NewSessionManager(cfg)

	state := NewMaskingState("owned_session", cfg)
	state.SetUserInfo(42, 100)

	sm.mu.Lock()
	sm.states["owned_session"] = state
	sm.updateUserIndexLocked(42, "owned_session")
	sm.mu.Unlock()

	// 所有者可以访问
	got, ok := sm.GetSession("owned_session", 42)
	if !ok || got.SessionID != "owned_session" {
		t.Errorf("owner should be able to access their session")
	}

	// 其他用户不能访问
	_, ok = sm.GetSession("owned_session", 99)
	if ok {
		t.Errorf("other user should not access owner's session")
	}

	// 匿名（userID=0）不能访问已归属会话
	_, ok = sm.GetSession("owned_session", 0)
	if ok {
		t.Errorf("anonymous should not access owned session")
	}

	// 管理员模式可以访问
	got, ok = sm.GetSessionAdmin("owned_session")
	if !ok || got.SessionID != "owned_session" {
		t.Errorf("admin should be able to access any session")
	}
}

func TestMaskingStatePersistenceWithUserInfo(t *testing.T) {
	cfg := newTestConfig()
	state := NewMaskingState("persist_user_test", cfg)
	state.SetUserInfo(42, 100)
	state.IncrementHitCount("PHONE_NUMBER")
	state.IncrementHitCount("EMAIL_ADDRESS")

	if err := state.Save(); err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	defer os.Remove(StateFilePath(state.SessionID))

	loaded, err := LoadMaskingState(state.SessionID, cfg)
	if err != nil {
		t.Fatalf("LoadMaskingState failed: %v", err)
	}

	if loaded.UserID != 42 {
		t.Errorf("expected user_id 42, got %d", loaded.UserID)
	}
	if loaded.TokenID != 100 {
		t.Errorf("expected token_id 100, got %d", loaded.TokenID)
	}
	if loaded.HitCounts["PHONE_NUMBER"] != 1 {
		t.Errorf("expected PHONE_NUMBER hit count 1, got %d", loaded.HitCounts["PHONE_NUMBER"])
	}
	if loaded.HitCounts["EMAIL_ADDRESS"] != 1 {
		t.Errorf("expected EMAIL_ADDRESS hit count 1, got %d", loaded.HitCounts["EMAIL_ADDRESS"])
	}
}

func TestMaskingStateUserInfoMerge(t *testing.T) {
	cfg := newTestConfig()
	state := NewMaskingState("merge_test", cfg)

	// 第一次设置有效值
	state.SetUserInfo(42, 100)
	// 第二次尝试覆盖不应生效
	state.SetUserInfo(99, 200)

	if state.UserID != 42 {
		t.Errorf("expected user_id to remain 42, got %d", state.UserID)
	}
	if state.TokenID != 100 {
		t.Errorf("expected token_id to remain 100, got %d", state.TokenID)
	}
}

func TestFieldAnalyzerJSONKeyValue(t *testing.T) {
	cfg := DefaultRedactionConfig()
	enableEntityType(&cfg, "PERSON_NAME")
	enableEntityType(&cfg, "USER_NAME")
	fa := NewFieldAnalyzer(&cfg)
	text := `{"name":"张三","age":30,"username":"zhangsan123"}`
	ents, err := fa.Analyze(text, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	var gotName, gotUser bool
	for _, e := range ents {
		if e.Type == "PERSON_NAME" && e.Text == "张三" {
			gotName = true
		}
		if e.Type == "USER_NAME" && e.Text == "zhangsan123" {
			gotUser = true
		}
	}
	if !gotName {
		t.Errorf("expected PERSON_NAME 张三, got %+v", ents)
	}
	if !gotUser {
		t.Errorf("expected USER_NAME zhangsan123, got %+v", ents)
	}
}

func TestFieldAnalyzerSurnameMatch(t *testing.T) {
	cfg := DefaultRedactionConfig()
	enableEntityType(&cfg, "PERSON_NAME")
	fa := NewFieldAnalyzer(&cfg)
	text := "他叫李四，电话是13812345678"
	ents, err := fa.Analyze(text, nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	var gotName bool
	for _, e := range ents {
		if e.Type == "PERSON_NAME" && e.Text == "李四" {
			gotName = true
		}
	}
	if !gotName {
		t.Errorf("expected PERSON_NAME 李四, got %+v", ents)
	}
}

func TestFieldAnalyzerFiltersEntityType(t *testing.T) {
	cfg := DefaultRedactionConfig()
	fa := NewFieldAnalyzer(&cfg)
	text := `{"name":"张三","username":"zhangsan123"}`
	ents, err := fa.Analyze(text, []string{"PERSON_NAME"})
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	for _, e := range ents {
		if e.Type == "USER_NAME" {
			t.Errorf("expected USER_NAME filtered out, got %+v", e)
		}
	}
}

func TestModelAnalyzerIntegration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entities": []map[string]interface{}{
				{"type": "PERSON_NAME", "start": 3, "end": 5, "text": "张三", "score": 0.9},
			},
		})
	}))
	defer server.Close()

	cfg := DefaultRedactionConfig()
	ma := newModelAnalyzer(NERConfig{
		Enabled:  true,
		Endpoint: server.URL + "/analyze",
		Timeout:  1 * time.Second,
	}, &cfg)

	ents, err := ma.Analyze("他是张三", nil)
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}
	if len(ents) != 1 || ents[0].Text != "张三" {
		t.Errorf("expected 1 entity 张三, got %+v", ents)
	}
	if ents[0].Operator.Type != OpSymbolize {
		t.Errorf("expected symbolize operator, got %+v", ents[0].Operator)
	}
}

func TestModelAnalyzerFallback(t *testing.T) {
	cfg := DefaultRedactionConfig()
	ma := newModelAnalyzer(NERConfig{
		Enabled:  true,
		Endpoint: "http://127.0.0.1:59999/analyze", // 无效端口
		Timeout:  10 * time.Millisecond,
	}, &cfg)

	ents, err := ma.Analyze("我的名字是张三", nil)
	if err != nil {
		t.Errorf("model analyzer should fallback gracefully, got error: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("expected empty fallback, got %d entities", len(ents))
	}
}

func TestMergeEntitiesOverlap(t *testing.T) {
	entities := []Entity{
		{Type: "PERSON_NAME", Start: 0, End: 4, Text: "张三", Score: 0.9},
		{Type: "USER_NAME", Start: 0, End: 4, Text: "张三", Score: 0.6},
	}
	merged := MergeEntities(entities)
	if len(merged) != 1 {
		t.Errorf("expected 1 entity after merge, got %d", len(merged))
	}
	if merged[0].Type != "PERSON_NAME" {
		t.Errorf("expected PERSON_NAME to win (higher score), got %s", merged[0].Type)
	}
}

func TestCompositeAnalyzerNameAndPhone(t *testing.T) {
	cfg := newTestConfig()
	cfg.BuiltInEntities = []BuiltInEntityConfig{
		{Type: "PHONE_NUMBER", Name: "手机号", Enabled: true, Operator: OperatorConfig{Type: OpSymbolize}},
		{Type: "PERSON_NAME", Name: "姓名", Enabled: true, Operator: OperatorConfig{Type: OpSymbolize}},
		{Type: "USER_NAME", Name: "用户名", Enabled: true, Operator: OperatorConfig{Type: OpSymbolize}},
	}
	if err := Init(cfg); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	state := NewMaskingState("test_composite", cfg)
	text := `{"real_name":"王五","phone":"13812345678","username":"wangwu"}`
	masked, err := MaskText(text, state)
	if err != nil {
		t.Fatalf("MaskText failed: %v", err)
	}

	if strings.Contains(masked, "王五") {
		t.Errorf("real_name should be redacted, got: %s", masked)
	}
	if strings.Contains(masked, "wangwu") {
		t.Errorf("username should be redacted, got: %s", masked)
	}
	if strings.Contains(masked, "13812345678") {
		t.Errorf("phone should be redacted, got: %s", masked)
	}

	restored := UnmaskText(masked, state)
	if restored != text {
		t.Errorf("round-trip failed: expected %q, got %q", text, restored)
	}
	t.Logf("masked: %s", masked)
}

