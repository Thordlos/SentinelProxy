package redaction

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/sentinelproxy/sentinelproxy/relay/model"
)

func newTestConfig() *RedactionConfig {
	cfg := DefaultRedactionConfig()
	cfg.Enabled = true
	cfg.StateDir = filepath.Join(os.TempDir(), "sentinel_test")
	_ = os.MkdirAll(cfg.StateDir, 0755)
	return &cfg
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
	if !strings.Contains(userContent, "PHONE_NUMBER") {
		t.Errorf("user message should contain placeholder: %s", userContent)
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
