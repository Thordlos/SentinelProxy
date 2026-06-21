# SentinelProxy 设计文档

> 一个面向企业内网的 LLM 安全代理网关，基于 one-api 深度改造，核心能力是在请求转发给模型服务商之前对敏感信息进行脱敏，并在模型返回后将脱敏占位符恢复为原始值。

---

## 1. 项目背景

### 1.1 原始动机
用户的主力大模型为国产模型（DeepSeek、Kimi/Moonshot、通义、文心、讯飞等）。在日常使用中，本地应用会把包含敏感信息的请求直接发送给模型服务商，存在数据泄露风险。

用户已有一个原型项目 `codeproxy`，验证了以下核心思路：
- 会话级脱敏状态（`MaskingState`）
- `<SENTINEL>CODE</SENTINEL>` 标记格式
- 流式响应实时还原
- 静态关键词 + 动态正则规则

### 1.2 为什么选择基于 one-api 改造
用户场景为 **企业/多团队**，需要：
- 多用户 key 管理
- 配额与计费
- Web 管理后台
- 国产模型渠道管理
- 负载均衡

one-api 已经完整提供以上能力，且 DeepSeek、Kimi/Moonshot 等国产模型在 one-api 中直接复用 `openai.Adaptor`，改造工作量可控。

### 1.3 关键约束
- 部署在园区内网，**不跟随 one-api 上游更新**
- 可以对原始代码做大幅修改，必要时可调整架构
- 纯 Go 实现，不引入 Python/Presidio 外部服务
- 保持单一二进制部署，避免复杂依赖

---

## 2. 核心设计决策

| 决策项 | 选择 | 原因 |
|--------|------|------|
| 基础框架 | one-api | 国产模型支持完整，有用户/计费/Web UI |
| 项目名 | SentinelProxy | 体现"守护敏感数据不流出" |
| 检测引擎 | 纯 Go 正则规则引擎 | 内网部署，无外部依赖 |
| 占位符格式 | `<SENTINEL>CODE</SENTINEL>` | 继承 codeproxy 验证成功的方案，流式恢复简单可靠 |
| 代号风格 | typed（类型编号） | `COMPANY_1`、`PHONE_2`，可读性强，便于调试 |
| 状态粒度 | 会话级 `MaskingState` | 多轮对话中同一敏感词保持同一代号 |
| 脱敏范围 | user 消息 + tool 参数 | assistant 历史消息不处理（模型看到的本就是脱敏态） |
| 部署形态 | 直接 fork 内嵌 | 脱敏是核心能力，不是可选插件 |

---

## 3. 总体架构

### 3.1 部署形态

```
┌─────────────────────────────────────────────────────────────────┐
│                        园区内网                                  │
│                                                                  │
│  ┌─────────────┐      ┌─────────────────────────┐      ┌─────┐  │
│  │  Client App │─────▶│      SentinelProxy      │─────▶│ LLM │  │
│  │  (敏感数据)  │      │  · 用户/Key/配额/计费   │      │上游 │  │
│  └─────────────┘      │  · 国产模型渠道管理     │      └─────┘  │
│                       │  · 请求脱敏             │                │
│                       │  · 响应恢复             │                │
│                       └─────────────────────────┘                │
│                                  │                               │
│                                  ▼                               │
│                       ┌─────────────────────────┐                │
│                       │  config/redaction.yaml  │                │
│                       │  logs/masking/*.json    │                │
│                       └─────────────────────────┘                │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 数据流

#### 非流式请求

```
Client Request
    │
    ▼
[中间件：TokenAuth → Distribute]
    │
    ▼
[RelayTextHelper]
    │
    ├── getAndValidateTextRequest
    │
    ▼
[RedactRequest]
    │  1. 解析 session_id
    │  2. 加载/创建 MaskingState
    │  3. 对 user 消息和 tool 参数脱敏
    │  4. 生成 `<SENTINEL>CODE</SENTINEL>` 并更新双向映射
    │  5. 将 MaskingState 存入 gin.Context
    ▼
[adaptor.ConvertRequest → DoRequest → 上游 LLM]
    │
    ▼
[Handler]
    │  1. 读取完整响应 body
    │  2. 用 MaskingState 反向替换 `<SENTINEL>CODE</SENTINEL>`
    │  3. 写回 client
    ▼
Client Response (含原始值)
```

#### 流式请求

```
Client Request
    │
    ▼
[RedactRequest]  ← 同非流式，请求体完整脱敏
    │
    ▼
[adaptor.DoRequest → 上游 LLM (stream=true)]
    │
    ▼
[StreamHandler]
    │  逐行读取 SSE chunk
    ▼
[StreamingUnmasker]
    │  解析每个 chunk 的 delta.content
    │  用 `<SENTINEL>CODE</SENTINEL>` 映射实时恢复
    │  处理跨 chunk 截断
    ▼
Client SSE Stream (含原始值)
```

---

## 4. 核心模块

新增 Go package：`relay/redaction/`

```
relay/redaction/
├── types.go          # 公共数据结构
├── config.go         # 配置加载
├── builtin.go        # 内置 PII 规则
├── rules.go          # 规则引擎
├── analyzer.go       # PII 检测器
├── anonymizer.go     # 脱敏器 + 代号生成
├── state.go          # MaskingState 会话状态
├── redaction.go      # 入口：RedactRequest / UnmaskResponse
├── streaming.go      # 流式恢复器
└── redaction_test.go # 单元测试
```

### 4.1 占位符格式

统一使用 XML 风格标记：

```
<SENTINEL>COMPANY_1</SENTINEL>
<SENTINEL>PHONE_NUMBER_2</SENTINEL>
<SENTINEL>EMAIL_ADDRESS_3</SENTINEL>
```

**为什么选这种格式：**
- 标记边界清晰，包含开始/结束标签
- 便于流式状态机识别不完整标签
- 与内部状态表映射配合，还原可靠
- 保留旧格式 ``CODE`` 兼容

### 4.2 会话状态 MaskingState

```go
type MaskingState struct {
    SessionID     string
    Forward       map[string]string  // 原词 -> <SENTINEL>CODE</SENTINEL>
    Inverse       map[string]string  // <SENTINEL>CODE</SENTINEL> -> 原词
    MaskedInverse map[string]string  // 替换值 -> 原词
    ForwardIP     map[string]string  // 原IP -> 假IP
    TokenForward  map[string]string  // 原值 -> token
    Counters      map[string]int
    UsedCodes     map[string]bool
    EntityTypes   map[string]string
    CreatedAt     time.Time
    LastAccessed  time.Time
}
```

**会话识别优先级：**
1. 请求 header `x-session-id`
2. Authorization header 的 hash
3. 客户端 IP

**持久化：**
- 每会话一个 JSON 文件：`logs/masking/{session_id}.json`
- TTL 过期后自动清理（默认 24 小时）
- 服务重启时从磁盘加载

### 4.3 规则引擎

规则来源：
1. 内置规则（身份证、手机号、邮箱、银行卡等）
2. `config/redaction.yaml` 中的 `custom_rules`
3. 请求级规则（可选，通过 header 传入）

规则优先级：请求级 > 自定义 > 内置。

> 注：更详细的脱敏状态表、操作符实现与还原流程，见 [redaction-architecture.md](./redaction-architecture.md)。

### 4.4 脱敏操作符

| 规范名 | 说明 | 恢复方式 |
|--------|------|---------|
| `symbolize`（原 `replace`） | 替换为 `<SENTINEL>CODE</SENTINEL>` | `Inverse[code] = original` |
| `mask` | 部分掩码，如 `138****5678` | `MaskedInverse[masked] = original` |
| `randomize`（原 `ip_random`） | 格式保持随机化：假 IP、假手机号、假身份证、假邮箱、假银行卡、假车牌等 | `MaskedInverse[fake] = original` |
| `tokenize` | 定长随机 token | `MaskedInverse[token] = original` |
| `block` | 命中后阻断请求 | - |

所有脱敏算子均基于 `MaskingState` 映射表实现可还原。默认使用 `symbolize`；内置实体中 `PHONE_NUMBER`、`ID_CARD`、`IP_ADDRESS` 默认使用 `randomize`，以保留格式语义。

---

## 5. 关键实现细节

### 5.1 请求脱敏插入点

在 `relay/controller/text.go` 的 `RelayTextHelper` 中，在 `getAndValidateTextRequest` 之后、模型名映射之前插入：

```go
// 对 chat completions 请求做脱敏
if redaction.IsEnabled() && meta.Mode == relaymode.ChatCompletions {
    state, err := redaction.GetOrCreateState(c)
    if err == nil {
        if err := redaction.RedactRequest(textRequest, state); err != nil {
            if redaction.Config().FailClosed {
                return openai.ErrorWrapper(err, "redaction_failed", http.StatusInternalServerError)
            }
            logger.Warnf(ctx, "redaction failed (fail-open): %s", err.Error())
        } else {
            redaction.StoreState(c, state)
        }
    } else if redaction.Config().FailClosed {
        return openai.ErrorWrapper(err, "redaction_state_failed", http.StatusInternalServerError)
    }
}
```

### 5.2 Message 处理

只处理 `role == "user"` 的消息。`Message.Content` 可能是：
- `string`：直接脱敏
- `[]any` 多模态数组：只对 `type == "text"` 的项脱敏

`assistant` 历史消息不处理，因为模型之前看到的输入就是脱敏态。

### 5.3 Tool 参数处理

递归遍历 `tools`、`tool_choice`、`tool_calls` 中的字符串值，调用 `mask_text`。

### 5.4 非流式响应恢复

在 `relay/adaptor/openai/main.go` 的 `Handler` 中：

```go
responseBody, _ := io.ReadAll(resp.Body)

if state := redaction.GetState(c); state != nil {
    responseBody = redaction.UnmaskBytes(responseBody, state)
}

resp.Body = io.NopCloser(bytes.NewBuffer(responseBody))
```

### 5.5 流式响应恢复

在 `relay/adaptor/openai/main.go` 的 `StreamHandler` 中：

```go
state := redaction.GetState(c)
var unmasker *redaction.StreamingUnmasker
if state != nil {
    unmasker = redaction.NewStreamingUnmasker(state)
}

for scanner.Scan() {
    data := scanner.Text()
    
    // 解析 SSE chunk
    var streamResponse ChatCompletionsStreamResponse
    if json.Unmarshal([]byte(data[dataPrefixLength:]), &streamResponse) == nil {
        for i := range streamResponse.Choices {
            content := conv.AsString(streamResponse.Choices[i].Delta.Content)
            if content != "" && unmasker != nil {
                recovered := unmasker.Write(content)
                streamResponse.Choices[i].Delta.Content = recovered
            }
        }
        newJson, _ := json.Marshal(streamResponse)
        data = dataPrefix + string(newJson)
    }
    
    render.StringData(c, data)
}

// flush 剩余 pending
if unmasker != nil {
    remaining := unmasker.Flush()
    if remaining != "" {
        // 构造最终 chunk 输出
    }
}
```

### 5.6 跨 chunk 截断处理

`StreamingUnmasker` 维护一个 `pending` 缓冲区：

```go
func (u *StreamingUnmasker) Write(input string) string {
    u.pending.WriteString(input)
    output, remaining := u.drainConfirmed(u.pending.String())
    u.pending.Reset()
    u.pending.WriteString(remaining)
    return output
}
```

`drainConfirmed` 从左到右扫描：
- 如果遇到 `` 开标记，查找闭合标记
- 如果能完整匹配一个已知代号 → 还原并输出
- 如果不能完整匹配 → 保留从开标记开始的所有内容到 pending
- 其余内容直接输出

---

## 6. 集成点

### 6.1 新增文件

| 文件 | 说明 |
|------|------|
| `relay/redaction/*.go` | 脱敏模块 |
| `config/redaction.yaml` | 默认脱敏配置 |
| `docs/sentinel-proxy-design.md` | 本设计文档 |

### 6.2 修改文件

| 文件 | 修改内容 |
|------|----------|
| `go.mod` | 模块名改为 `github.com/yourorg/sentinelproxy` |
| `main.go` | 初始化 redaction 模块 |
| `common/config/config.go` | 加载 redaction 配置 |
| `relay/controller/text.go` | 请求脱敏 |
| `relay/adaptor/openai/main.go` | 响应恢复（非流式 + 流式） |
| `relay/meta/meta.go` | 如有需要，增加 session 相关字段 |

---

## 7. 配置

### 7.1 默认配置

```yaml
# config/redaction.yaml
enabled: true
fail_closed: true
score_threshold: 0.0
max_text_length: 1048576      # 1MB
cache_ttl_hours: 24
state_dir: logs/masking

code_style: typed
code_prefix: ENT

built_in_entities:
  - ID_CARD
  - PHONE_NUMBER
  - EMAIL_ADDRESS
  - BANK_CARD
  - LICENSE_PLATE

custom_rules:
  - id: internal_project
    name: 内部项目代号
    entity_type: PROJECT_CODE
    pattern: 'PROJ-[A-Z]{2,4}-\d{4,6}'
    operator:
      type: replace
```

### 7.2 环境变量

| 变量 | 说明 |
|------|------|
| `SENTINEL_REDACTION_ENABLED` | 全局开关 |
| `SENTINEL_REDACTION_CONFIG` | 配置文件路径 |
| `SENTINEL_REDACTION_FAIL_CLOSED` | 是否 fail-closed |

---

## 8. 测试策略

### 8.1 单元测试

覆盖：
- 内置规则命中
- 多实体编号递增
- 保留片段 ` ``内容`` `
- 双向映射正确性
- 流式跨 chunk 恢复
- fail-closed 行为

### 8.2 集成测试

1. 启动 SentinelProxy
2. 配置 DeepSeek/Kimi 渠道
3. 发送非流式请求，验证上游收到脱敏内容、client 收到恢复内容
4. 发送流式请求，验证 SSE 实时恢复
5. 多轮对话，验证同一敏感词保持同一代号

---

## 9. 实施阶段

### Phase 1：项目初始化（1 天）
- 重命名目录和模块
- 更新 import 路径
- 确保编译通过

### Phase 2：核心脱敏模块（1 周）
- 实现 `relay/redaction/` 包
- 内置规则 + 自定义规则
- 会话级 MaskingState

### Phase 3：非流式集成（2–3 天）
- 请求脱敏接入 `RelayTextHelper`
- 响应恢复接入 `Handler`
- 基础测试

### Phase 4：流式集成（3–4 天）
- 流式恢复接入 `StreamHandler`
- 跨 chunk 边界测试

### Phase 5：配置与验证（2–3 天）
- 配置文件 + 环境变量
- 单元测试补全
- 本地集成验证

### Phase 6：Web UI 与高级功能（可选，1–2 周）
- 管理后台增加脱敏规则配置
- 审计日志
- 统计报表

---

## 10. 风险与限制

| 风险 | 影响 | 缓解 |
|------|------|------|
| 正则误报 | 非敏感内容被替换 | 提供白名单、置信度阈值、自定义规则 |
| 占位符与真实文本冲突 | 用户输入恰好包含 `<SENTINEL>CODE</SENTINEL>` | 按 MaskingState 映射优先恢复；无法识别的保持原样 |
| 流式跨 chunk 异常 | 半个标记无法恢复 | StreamingUnmasker pending 缓冲 + flush 兜底 |
| 大文本性能 | 长文本正则匹配慢 | `max_text_length` 限制、规则编译缓存 |
| 非 OpenAI 适配器 | Ali/Baidu/Xunfei 流式格式不同 | 首期覆盖 openai.Adaptor（DeepSeek/Kimi），后续按需扩展 |
| 多副本状态同步 | MaskingState 存在本地磁盘，多实例不一致 | 内网初期单实例；后续可迁移到共享存储 |

---

## 11. 命名约定

- 项目名：`SentinelProxy`
- 模块路径：`github.com/yourorg/sentinelproxy`（部署时替换为实际组织）
- 二进制名：`sentinelproxy`
- 容器镜像：`sentinelproxy:latest`
- 配置文件：`config/redaction.yaml`
- 状态目录：`logs/masking/`

---

## 12. 总结

SentinelProxy 是在 one-api 基础上深度改造的企业内网 LLM 安全网关，核心差异是引入 `relay/redaction/` 脱敏模块：

- **检测层**：纯 Go 正则规则引擎，内置中文 PII + 自定义规则
- **脱敏层**：`<SENTINEL>CODE</SENTINEL>` 格式 + 会话级 MaskingState
- **恢复层**：非流式 JSON 替换 + 流式 SSE 实时恢复
- **管理层**：继承 one-api 的用户/key/配额/计费/Web UI

该方案能覆盖用户主力国产模型（DeepSeek、Kimi/Moonshot），满足企业内网对数据安全和模型服务管理的核心需求。
