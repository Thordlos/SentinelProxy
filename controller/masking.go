package controller

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sentinelproxy/sentinelproxy/common/ctxkey"
	"github.com/sentinelproxy/sentinelproxy/relay/redaction"
)

// GetMaskingConfig 获取脱敏配置
func GetMaskingConfig(c *gin.Context) {
	cfg := redaction.Config()
	cfg.NormalizeConfig()
	cfg.SetBuiltInEntityNames()
	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    cfg,
	})
}

// SaveMaskingConfig 保存脱敏配置
type maskingConfigRequest struct {
	Enabled         bool                            `json:"enabled"`
	FailClosed      bool                            `json:"fail_closed"`
	ScoreThreshold  float64                         `json:"score_threshold"`
	MaxTextLength   int                             `json:"max_text_length"`
	CacheTTLHours   int                             `json:"cache_ttl_hours"`
	StateDir        string                          `json:"state_dir"`
	CodeStyle       string                          `json:"code_style"`
	CodePrefix      string                          `json:"code_prefix"`
	CodeLength      int                             `json:"code_length"`
	LogRawRequests  bool                            `json:"log_raw_requests"`
	DefaultOperator redaction.OperatorConfig        `json:"default_operator"`
	BuiltInEntities []redaction.BuiltInEntityConfig `json:"built_in_entities"`
	StaticRules     []redaction.Rule                `json:"static_rules"`
	DynamicRules    []redaction.Rule                `json:"dynamic_rules"`
}

func SaveMaskingConfig(c *gin.Context) {
	var req maskingConfigRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	cfg := redaction.RedactionConfig{
		Enabled:         req.Enabled,
		FailClosed:      req.FailClosed,
		ScoreThreshold:  req.ScoreThreshold,
		MaxTextLength:   req.MaxTextLength,
		CacheTTLHours:   req.CacheTTLHours,
		StateDir:        req.StateDir,
		CodeStyle:       req.CodeStyle,
		CodePrefix:      req.CodePrefix,
		CodeLength:      req.CodeLength,
		LogRawRequests:  req.LogRawRequests,
		DefaultOperator: req.DefaultOperator,
		BuiltInEntities: req.BuiltInEntities,
		StaticRules:     req.StaticRules,
		DynamicRules:    req.DynamicRules,
	}

	// 设置内置实体名称
	cfg.SetBuiltInEntityNames()
	cfg.NormalizeConfig()

	// 验证配置（尝试创建规则引擎）
	if _, err := redaction.NewRuleEngine(&cfg); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "规则验证失败: " + err.Error(),
		})
		return
	}

	// 保存配置到文件
	if err := redaction.SaveConfig(&cfg); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "保存配置失败: " + err.Error(),
		})
		return
	}

	// 热加载
	if err := redaction.ReloadConfig(&cfg); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "热加载失败: " + err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"message": "配置已保存并生效",
	})
}

// GetMaskingBuiltinEntities 获取内置实体列表
func GetMaskingBuiltinEntities(c *gin.Context) {
	configs := redaction.BuiltInEntityConfigs()

	// 填充每个内置实体的正则 pattern，便于前端复制为自定义规则
	rules := redaction.BuiltInRules()
	ruleMap := make(map[string]string)
	for _, rule := range rules {
		if _, ok := ruleMap[rule.EntityType]; !ok {
			ruleMap[rule.EntityType] = rule.Pattern
		}
	}
	for i := range configs {
		if pattern, ok := ruleMap[configs[i].Type]; ok {
			configs[i].Pattern = pattern
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    configs,
	})
}

// PreviewMasking 预览脱敏效果
type previewRequest struct {
	Text      string `json:"text"`
	SessionID string `json:"session_id"`
}

func PreviewMasking(c *gin.Context) {
	var req previewRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	result, err := redaction.PreviewMasking(req.Text, req.SessionID)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    result,
	})
}

// SessionSummary 用户会话摘要
type SessionSummary struct {
	SessionID    string    `json:"session_id"`
	DisplayID    string    `json:"display_id"`
	CreatedAt    time.Time `json:"created_at"`
	LastAccessed time.Time `json:"last_accessed"`
	EntityCount  int       `json:"entity_count"`
	HitCount     int       `json:"hit_count"`
}

// SessionDetail 用户会话详情
type SessionDetail struct {
	SessionID      string              `json:"session_id"`
	DisplayID      string              `json:"display_id"`
	CreatedAt      time.Time           `json:"created_at"`
	LastAccessed   time.Time           `json:"last_accessed"`
	HitCounts      map[string]int      `json:"hit_counts"`
	SymbolMappings []SymbolMappingItem `json:"symbol_mappings"`
	MaskedMappings []MaskedMappingItem `json:"masked_mappings"`
	IPMappings     []IPMappingItem     `json:"ip_mappings"`
	TokenMappings  []TokenMappingItem  `json:"token_mappings"`
}

// SymbolMappingItem 符号化映射项
type SymbolMappingItem struct {
	Code     string `json:"code"`
	Original string `json:"original"`
	Type     string `json:"type"`
}

// MaskedMappingItem 掩码/随机化/token 映射项
type MaskedMappingItem struct {
	Masked   string `json:"masked"`
	Original string `json:"original"`
	Type     string `json:"type"`
}

// IPMappingItem IP 映射项
type IPMappingItem struct {
	Original string `json:"original"`
	Fake     string `json:"fake"`
}

// TokenMappingItem Token 映射项
type TokenMappingItem struct {
	Original string `json:"original"`
	Token    string `json:"token"`
}

// UserStats 用户脱敏统计
type UserStats struct {
	TotalSessions int            `json:"total_sessions"`
	TotalHits     int            `json:"total_hits"`
	HitCounts     map[string]int `json:"hit_counts"`
}

// GetMaskingSessions 获取当前用户的脱敏会话列表
func GetMaskingSessions(c *gin.Context) {
	userID := c.GetInt(ctxkey.Id)
	if userID <= 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法识别当前用户",
		})
		return
	}

	sm := redaction.GetSessionManager()
	sessions := sm.ListUserSessions(userID)

	var summaries []SessionSummary
	for _, state := range sessions {
		summaries = append(summaries, SessionSummary{
			SessionID:    state.SessionID,
			DisplayID:    state.DisplayID(),
			CreatedAt:    state.CreatedAt,
			LastAccessed: state.LastAccessed,
			EntityCount:  len(state.Forward) + len(state.MaskedInverse),
			HitCount:     state.TotalHits(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    summaries,
	})
}

// GetMaskingSessionDetail 获取当前用户指定会话的映射详情
func GetMaskingSessionDetail(c *gin.Context) {
	userID := c.GetInt(ctxkey.Id)
	if userID <= 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法识别当前用户",
		})
		return
	}

	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "缺少会话 ID",
		})
		return
	}

	sm := redaction.GetSessionManager()
	state, ok := sm.GetSession(sessionID, userID)
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "会话不存在或无权访问",
		})
		return
	}

	detail := SessionDetail{
		SessionID:      state.SessionID,
		DisplayID:      state.DisplayID(),
		CreatedAt:      state.CreatedAt,
		LastAccessed:   state.LastAccessed,
		HitCounts:      state.HitCounts,
		SymbolMappings: make([]SymbolMappingItem, 0, len(state.Inverse)),
		MaskedMappings: make([]MaskedMappingItem, 0, len(state.MaskedInverse)),
		IPMappings:     make([]IPMappingItem, 0, len(state.ForwardIP)),
		TokenMappings:  make([]TokenMappingItem, 0, len(state.TokenForward)),
	}

	for code, original := range state.Inverse {
		detail.SymbolMappings = append(detail.SymbolMappings, SymbolMappingItem{
			Code:     code,
			Original: original,
			Type:     state.EntityTypes[code],
		})
	}

	for masked, original := range state.MaskedInverse {
		// 跳过 token 映射，避免重复展示
		if _, isToken := findTokenOriginal(state, masked); isToken {
			continue
		}
		detail.MaskedMappings = append(detail.MaskedMappings, MaskedMappingItem{
			Masked:   masked,
			Original: original,
		})
	}

	for original, fake := range state.ForwardIP {
		detail.IPMappings = append(detail.IPMappings, IPMappingItem{
			Original: original,
			Fake:     fake,
		})
	}

	for original, token := range state.TokenForward {
		detail.TokenMappings = append(detail.TokenMappings, TokenMappingItem{
			Original: original,
			Token:    token,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    detail,
	})
}

// findTokenOriginal 判断 masked 值是否来自 token 映射
func findTokenOriginal(state *redaction.MaskingState, masked string) (string, bool) {
	for original, token := range state.TokenForward {
		if token == masked {
			return original, true
		}
	}
	return "", false
}

// GetMaskingSelfStats 获取当前用户的脱敏统计聚合
func GetMaskingSelfStats(c *gin.Context) {
	userID := c.GetInt(ctxkey.Id)
	if userID <= 0 {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "无法识别当前用户",
		})
		return
	}

	sm := redaction.GetSessionManager()
	totalSessions, totalHits, hitCounts := sm.GetUserStats(userID)

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data": UserStats{
			TotalSessions: totalSessions,
			TotalHits:     totalHits,
			HitCounts:     hitCounts,
		},
	})
}

// AdminListMaskingSessions 管理员查看指定用户的会话列表（id=0 表示全部）
func AdminListMaskingSessions(c *gin.Context) {
	targetUserID, _ := strconv.Atoi(c.Query("user_id"))

	sm := redaction.GetSessionManager()
	var sessions []*redaction.MaskingState
	if targetUserID > 0 {
		sessions = sm.ListUserSessions(targetUserID)
	} else {
		// 扫描所有磁盘会话
		sessions = sm.ListAllSessions()
	}

	var summaries []SessionSummary
	for _, state := range sessions {
		summaries = append(summaries, SessionSummary{
			SessionID:    state.SessionID,
			DisplayID:    state.DisplayID(),
			CreatedAt:    state.CreatedAt,
			LastAccessed: state.LastAccessed,
			EntityCount:  len(state.Forward) + len(state.MaskedInverse),
			HitCount:     state.TotalHits(),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    summaries,
	})
}

// AdminGetMaskingSessionDetail 管理员查看任意会话详情
func AdminGetMaskingSessionDetail(c *gin.Context) {
	sessionID := c.Param("id")
	if sessionID == "" {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "缺少会话 ID",
		})
		return
	}

	sm := redaction.GetSessionManager()
	state, ok := sm.GetSessionAdmin(sessionID)
	if !ok {
		c.JSON(http.StatusOK, gin.H{
			"success": false,
			"message": "会话不存在",
		})
		return
	}

	detail := SessionDetail{
		SessionID:      state.SessionID,
		DisplayID:      state.DisplayID(),
		CreatedAt:      state.CreatedAt,
		LastAccessed:   state.LastAccessed,
		HitCounts:      state.HitCounts,
		SymbolMappings: make([]SymbolMappingItem, 0, len(state.Inverse)),
		MaskedMappings: make([]MaskedMappingItem, 0, len(state.MaskedInverse)),
		IPMappings:     make([]IPMappingItem, 0, len(state.ForwardIP)),
		TokenMappings:  make([]TokenMappingItem, 0, len(state.TokenForward)),
	}

	for code, original := range state.Inverse {
		detail.SymbolMappings = append(detail.SymbolMappings, SymbolMappingItem{
			Code:     code,
			Original: original,
			Type:     state.EntityTypes[code],
		})
	}

	for masked, original := range state.MaskedInverse {
		if _, isToken := findTokenOriginal(state, masked); isToken {
			continue
		}
		detail.MaskedMappings = append(detail.MaskedMappings, MaskedMappingItem{
			Masked:   masked,
			Original: original,
		})
	}

	for original, fake := range state.ForwardIP {
		detail.IPMappings = append(detail.IPMappings, IPMappingItem{
			Original: original,
			Fake:     fake,
		})
	}

	for original, token := range state.TokenForward {
		detail.TokenMappings = append(detail.TokenMappings, TokenMappingItem{
			Original: original,
			Token:    token,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"success": true,
		"data":    detail,
	})
}
