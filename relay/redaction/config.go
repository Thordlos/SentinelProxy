package redaction

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	globalConfig     *RedactionConfig
	globalConfigPath string
	configMutex      sync.RWMutex
)

// GetConfigPath 返回当前配置文件路径
func GetConfigPath() string {
	if globalConfigPath != "" {
		return globalConfigPath
	}
	if v := os.Getenv("SENTINEL_REDACTION_CONFIG"); v != "" {
		return v
	}
	return "config/redaction.yaml"
}

// LoadConfig 从指定路径加载脱敏配置
func LoadConfig(path string) (*RedactionConfig, error) {
	cfg := DefaultRedactionConfig()

	if path == "" {
		path = GetConfigPath()
	}
	globalConfigPath = path

	// 如果配置文件存在则加载
	if _, err := os.Stat(path); err == nil {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read redaction config failed: %w", err)
		}
		if err := unmarshalConfig(data, &cfg); err != nil {
			return nil, fmt.Errorf("parse redaction config failed: %w", err)
		}
	}

	// 环境变量覆盖
	applyEnvOverrides(&cfg)

	// 规范化配置
	cfg.NormalizeConfig()

	// 确保状态目录存在
	if cfg.StateDir != "" {
		if err := os.MkdirAll(cfg.StateDir, 0755); err != nil {
			return nil, fmt.Errorf("create state dir failed: %w", err)
		}
	}

	configMutex.Lock()
	globalConfig = &cfg
	configMutex.Unlock()
	return &cfg, nil
}

// unmarshalConfig 解析 YAML，支持 built_in_entities 的旧格式（字符串数组）和新格式（对象数组）
func unmarshalConfig(data []byte, cfg *RedactionConfig) error {
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return err
	}

	// 处理 built_in_entities 的向后兼容：如果是字符串数组，先转换成对象数组
	if entitiesRaw, ok := raw["built_in_entities"]; ok {
		if entities, ok := entitiesRaw.([]interface{}); ok {
			converted := make([]interface{}, 0, len(entities))
			needsConvert := false
			for _, item := range entities {
				if s, ok := item.(string); ok {
					converted = append(converted, map[string]interface{}{"type": s, "enabled": true})
					needsConvert = true
				} else {
					converted = append(converted, item)
				}
			}
			if needsConvert {
				raw["built_in_entities"] = converted
				newData, err := yaml.Marshal(raw)
				if err != nil {
					return fmt.Errorf("marshal converted config failed: %w", err)
				}
				data = newData
			}
		}
	}

	// 按标准结构解析
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return err
	}

	return nil
}

// SaveConfig 保存配置到 YAML 文件
func SaveConfig(cfg *RedactionConfig) error {
	path := GetConfigPath()

	// 规范化并填充名称
	cfg.NormalizeConfig()
	cfg.SetBuiltInEntityNames()

	// 确保目录存在
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create config dir failed: %w", err)
	}

	// 备份原文件
	if _, err := os.Stat(path); err == nil {
		backupPath := path + ".bak"
		_ = os.Rename(path, backupPath)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config failed: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write config file failed: %w", err)
	}

	return nil
}

// ReloadConfig 热加载配置
func ReloadConfig(cfg *RedactionConfig) error {
	cfg.NormalizeConfig()

	// 重新初始化分析器
	analyzer, err := NewAnalyzer(cfg)
	if err != nil {
		return fmt.Errorf("init analyzer failed: %w", err)
	}

	// 更新全局配置
	configMutex.Lock()
	globalConfig = cfg
	globalAnalyzer = analyzer
	configMutex.Unlock()

	// 重新初始化会话管理器（保留现有状态）
	InitSessionManager(cfg)

	return nil
}

// Config 返回全局配置（线程安全）
func Config() *RedactionConfig {
	configMutex.RLock()
	defer configMutex.RUnlock()
	if globalConfig == nil {
		cfg := DefaultRedactionConfig()
		globalConfig = &cfg
	}
	return globalConfig
}

// IsEnabled 返回脱敏是否启用
func IsEnabled() bool {
	return Config().Enabled
}

// applyEnvOverrides 用环境变量覆盖配置
func applyEnvOverrides(cfg *RedactionConfig) {
	if v := os.Getenv("SENTINEL_REDACTION_ENABLED"); v != "" {
		cfg.Enabled = parseBool(v, cfg.Enabled)
	}
	if v := os.Getenv("SENTINEL_REDACTION_FAIL_CLOSED"); v != "" {
		cfg.FailClosed = parseBool(v, cfg.FailClosed)
	}
	if v := os.Getenv("SENTINEL_REDACTION_STATE_DIR"); v != "" {
		cfg.StateDir = v
	}
	if v := os.Getenv("SENTINEL_REDACTION_LOG_RAW_REQUESTS"); v != "" {
		cfg.LogRawRequests = parseBool(v, cfg.LogRawRequests)
	}
	if v := os.Getenv("SENTINEL_REDACTION_NER_ENABLED"); v != "" {
		cfg.NER.Enabled = parseBool(v, cfg.NER.Enabled)
	}
	if v := os.Getenv("SENTINEL_REDACTION_NER_ENDPOINT"); v != "" {
		cfg.NER.Endpoint = v
	}
	if v := os.Getenv("SENTINEL_REDACTION_NER_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.NER.Timeout = d
		}
	}
}

func parseBool(s string, defaultValue bool) bool {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return defaultValue
	}
	return b
}
