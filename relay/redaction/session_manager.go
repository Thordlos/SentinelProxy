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
	"github.com/sentinelproxy/sentinelproxy/common/ctxkey"
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
	config    *RedactionConfig
	states    map[string]*MaskingState
	mu        sync.RWMutex
	stateDir  string
	userIndex map[int]map[string]bool // user_id -> set of session_ids
}

// NewSessionManager 创建会话管理器
func NewSessionManager(config *RedactionConfig) *SessionManager {
	stateDir := config.StateDir
	if stateDir == "" {
		stateDir = "logs/masking"
	}
	_ = os.MkdirAll(stateDir, 0755)

	return &SessionManager{
		config:    config,
		states:    make(map[string]*MaskingState),
		stateDir:  stateDir,
		userIndex: make(map[int]map[string]bool),
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
			// 更新用户关联信息（可能之前未设置）
			userID := c.GetInt(ctxkey.Id)
			tokenID := c.GetInt(ctxkey.TokenId)
			state.SetUserInfo(userID, tokenID)
			sm.updateUserIndex(userID, sessionID)
			return state, nil
		}
	}

	sm.mu.Lock()
	defer sm.mu.Unlock()

	// 检查内存中是否已有
	if state, ok := sm.states[sessionID]; ok {
		userID := c.GetInt(ctxkey.Id)
		tokenID := c.GetInt(ctxkey.TokenId)
		state.SetUserInfo(userID, tokenID)
		sm.updateUserIndexLocked(userID, sessionID)
		c.Set(ContextKeyState, state)
		return state, nil
	}

	// 尝试从磁盘加载
	state, err := LoadMaskingState(sessionID, sm.config)
	if err != nil {
		// 文件不存在则创建新状态
		state = NewMaskingState(sessionID, sm.config)
	}

	userID := c.GetInt(ctxkey.Id)
	tokenID := c.GetInt(ctxkey.TokenId)
	state.SetUserInfo(userID, tokenID)
	sm.states[sessionID] = state
	sm.updateUserIndexLocked(userID, sessionID)
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

// updateUserIndex 更新用户与会话的索引（线程安全包装）
func (sm *SessionManager) updateUserIndex(userID int, sessionID string) {
	if userID <= 0 || sessionID == "" {
		return
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.updateUserIndexLocked(userID, sessionID)
}

// updateUserIndexLocked 更新用户与会话的索引（调用方已持有写锁）
func (sm *SessionManager) updateUserIndexLocked(userID int, sessionID string) {
	if userID <= 0 || sessionID == "" {
		return
	}
	if sm.userIndex[userID] == nil {
		sm.userIndex[userID] = make(map[string]bool)
	}
	sm.userIndex[userID][sessionID] = true
}

// ListUserSessions 返回指定用户的所有会话状态（内存 + 磁盘）
func (sm *SessionManager) ListUserSessions(userID int) []*MaskingState {
	if userID <= 0 {
		return nil
	}

	sm.mu.RLock()
	// 先收集内存中属于该用户的会话
	memoryStates := make([]*MaskingState, 0)
	if ids, ok := sm.userIndex[userID]; ok {
		for sid := range ids {
			if state, ok := sm.states[sid]; ok {
				memoryStates = append(memoryStates, state)
			}
		}
	}
	sm.mu.RUnlock()

	// 补充扫描磁盘：有些会话可能不在内存中
	diskStates := make(map[string]*MaskingState)
	files, err := filepath.Glob(filepath.Join(sm.stateDir, "*.json"))
	if err == nil {
		for _, file := range files {
			sid := filepath.Base(file[:len(file)-5])
			state, err := LoadMaskingState(sid, sm.config)
			if err != nil || state.UserID != userID {
				continue
			}
			diskStates[sid] = state
		}
	}

	// 内存中的状态优先，避免重复
	for _, state := range memoryStates {
		diskStates[state.SessionID] = state
	}

	result := make([]*MaskingState, 0, len(diskStates))
	for _, state := range diskStates {
		result = append(result, state)
	}
	return result
}

// GetSession 获取指定会话的状态；若指定了 userID，则校验所有权
func (sm *SessionManager) GetSession(sessionID string, userID int) (*MaskingState, bool) {
	if sessionID == "" {
		return nil, false
	}

	sm.mu.RLock()
	if state, ok := sm.states[sessionID]; ok {
		sm.mu.RUnlock()
		if state.UserID != 0 && state.UserID != userID {
			return nil, false
		}
		return state, true
	}
	sm.mu.RUnlock()

	// 尝试从磁盘加载
	state, err := LoadMaskingState(sessionID, sm.config)
	if err != nil {
		return nil, false
	}
	if state.UserID != 0 && state.UserID != userID {
		return nil, false
	}

	// 缓存到内存
	sm.mu.Lock()
	sm.states[sessionID] = state
	if state.UserID > 0 {
		sm.updateUserIndexLocked(state.UserID, sessionID)
	}
	sm.mu.Unlock()
	return state, true
}

// GetSessionAdmin 管理员获取任意会话状态（不校验所有权）
func (sm *SessionManager) GetSessionAdmin(sessionID string) (*MaskingState, bool) {
	if sessionID == "" {
		return nil, false
	}

	sm.mu.RLock()
	if state, ok := sm.states[sessionID]; ok {
		sm.mu.RUnlock()
		return state, true
	}
	sm.mu.RUnlock()

	state, err := LoadMaskingState(sessionID, sm.config)
	if err != nil {
		return nil, false
	}

	sm.mu.Lock()
	sm.states[sessionID] = state
	if state.UserID > 0 {
		sm.updateUserIndexLocked(state.UserID, sessionID)
	}
	sm.mu.Unlock()
	return state, true
}

// GetUserStats 聚合指定用户所有会话的命中统计
func (sm *SessionManager) GetUserStats(userID int) (totalSessions, totalHits int, hitCounts map[string]int) {
	sessions := sm.ListUserSessions(userID)
	hitCounts = make(map[string]int)
	for _, state := range sessions {
		totalSessions++
		totalHits += state.TotalHits()
		for entityType, count := range state.HitCounts {
			hitCounts[entityType] += count
		}
	}
	return totalSessions, totalHits, hitCounts
}

// ListAllSessions 返回内存 + 磁盘中的所有会话（管理员用）
func (sm *SessionManager) ListAllSessions() []*MaskingState {
	all := make(map[string]*MaskingState)

	sm.mu.RLock()
	for sid, state := range sm.states {
		all[sid] = state
	}
	sm.mu.RUnlock()

	files, err := filepath.Glob(filepath.Join(sm.stateDir, "*.json"))
	if err == nil {
		for _, file := range files {
			sid := filepath.Base(file[:len(file)-5])
			if _, ok := all[sid]; ok {
				continue
			}
			state, err := LoadMaskingState(sid, sm.config)
			if err != nil {
				continue
			}
			all[sid] = state
		}
	}

	result := make([]*MaskingState, 0, len(all))
	for _, state := range all {
		result = append(result, state)
	}
	return result
}
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
			if state.UserID > 0 && sm.userIndex[state.UserID] != nil {
				delete(sm.userIndex[state.UserID], sid)
			}
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
