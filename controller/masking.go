package controller

import (
	"net/http"

	"github.com/gin-gonic/gin"
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
