package redaction

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	// ContextKeyState 用于在 gin.Context 中存储 MaskingState
	ContextKeyState = "sentinel_masking_state"
)

var (
	globalSessionManager *SessionManager
)

// InitSessionManager 初始化全局会话管理器
func InitSessionManager(config *RedactionConfig) {
	if config == nil {
		cfg := DefaultRedactionConfig()
		config = &cfg
	}
	globalSessionManager = NewSessionManager(config)
}

// GetSessionManager 获取全局会话管理器
func GetSessionManager() *SessionManager {
	if globalSessionManager == nil {
		cfg := DefaultRedactionConfig()
		globalSessionManager = NewSessionManager(&cfg)
	}
	return globalSessionManager
}

// SessionManager 管理会话级脱敏状态
type SessionManager struct {
	config  *RedactionConfig
	states  map[string]*MaskingState
	mu      sync.RWMutex
	stateDir string
}

// NewSessionManager 创建会话管理器
func NewSessionManager(config *RedactionConfig) *SessionManager {
	stateDir := config.StateDir
	if stateDir == "" {
		stateDir = "logs/masking"
	}
	_ = os.MkdirAll(stateDir, 0755)

	return &SessionManager{
		config:   config,
		states:   make(map[string]*MaskingState),
		stateDir: stateDir,
	}
}

// ResolveSessionID 从 gin context 解析 session_id
func (sm *SessionManager) ResolveSessionID(c *gin.Context) string {
	// 优先级 1: 自定义 header
	sessionID := c.GetHeader("x-session-id")
	if sessionID != "" {
		return safeSessionID(sessionID)
	}

	// 优先级 2: Authorization header 的 hash
	auth := c.GetHeader("Authorization")
	if auth != "" {
		hash := sha256.Sum256([]byte(auth))
		return "auth_" + hex.EncodeToString(hash[:8])
	}

	// 优先级 3: 客户端 IP
	clientIP := c.ClientIP()
	if clientIP == "" {
		clientIP = "unknown"
	}
	return "ip_" + strings.ReplaceAll(clientIP, ".", "_")
}

// GetState 获取或创建会话状态
func (sm *SessionManager) GetState(c *gin.Context) (*MaskingState, error) {
	if !sm.config.Enabled {
		return nil, nil
	}

	sessionID := sm.ResolveSessionID(c)

	// 先检查 gin context 是否已有
	if val, exists := c.Get(ContextKeyState); exists {
		if state, ok := val.(*MaskingState); ok {
			return state, nil
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 检查内存中是否已有
	if state, ok := sm.states[sessionID]; ok {
		c.Set(ContextKeyState, state)
		return state, nil
	}

	// 尝试从磁盘加载
	state, err := LoadMaskingState(sessionID, sm.config)
	if err != nil {
		// 文件不存在则创建新状态
		state = NewMaskingState(sessionID, sm.config)
	}

	sm.states[sessionID] = state
	c.Set(ContextKeyState, state)
	return state, nil
}

// StoreState 存储状态到 gin context
func (sm *SessionManager) StoreState(c *gin.Context, state *MaskingState) {
	if state != nil {
		c.Set(ContextKeyState, state)
	}
}

// GetStateFromContext 从 gin context 获取状态
func GetStateFromContext(c *gin.Context) *MaskingState {
	if val, exists := c.Get(ContextKeyState); exists {
		if state, ok := val.(*MaskingState); ok {
			return state
		}
	}
	return nil
}

// SaveAll 保存所有状态到磁盘
func (sm *SessionManager) SaveAll() error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	var lastErr error
	for _, state := range sm.states {
		if err := state.Save(); err != nil {
			lastErr = err
		}
	}
	return lastErr
}

// SaveState 保存指定状态到磁盘
func (sm *SessionManager) SaveState(sessionID string) error {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	if state, ok := sm.states[sessionID]; ok {
		return state.Save()
	}
	return nil
}

// CleanupExpired 清理过期状态
func (sm *SessionManager) CleanupExpired() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(sm.config.CacheTTLHours) * time.Hour)

	for sid, state := range sm.states {
		if state.LastAccessed.Before(cutoff) {
			delete(sm.states, sid)
		}
	}

	// 清理磁盘过期文件
	files, err := filepath.Glob(filepath.Join(sm.stateDir, "*.json"))
	if err != nil {
		return err
	}

	for _, file := range files {
		state, err := LoadMaskingState(filepath.Base(file[:len(file)-5]), sm.config)
		if err != nil {
			continue
		}
		if state.LastAccessed.Before(cutoff) {
			_ = os.Remove(file)
		}
	}

	return nil
}

// safeSessionID 清理 sessionID，防止目录遍历和非法字符
func safeSessionID(sessionID string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9_.@-]`)
	safe := re.ReplaceAllString(sessionID, "_")
	if len(safe) > 128 {
		safe = safe[:128]
	}
	return safe
}

// StateFilePath 返回指定 session 的状态文件路径
func StateFilePath(sessionID string) string {
	safeID := safeSessionID(sessionID)
	return filepath.Join(Config().StateDir, safeID+".json")
}
