# SentinelProxy 脱敏架构设计文档

本文档描述 SentinelProxy 中敏感信息脱敏（Redaction）与还原（Unmasking）的整体架构、状态表设计、操作符语义以及前后端协作方式。

---

## 1. 设计原则

1. **所有脱敏都可还原**  
   维护 `MaskingState` 会话状态表，任何脱敏产生的替换值都必须在状态表中保留到原始值的映射。系统不提供真正不可逆的脱敏算子。

2. **标识仅服务内部使用**  
   脱敏产生的代号、假 IP、掩码值、token 等只用于同一会话内的还原，不暴露给业务系统作为持久标识。

3. **会话一致性**  
   同一会话内，相同的敏感值应映射到相同的替换值，避免模型在多轮对话中无法做实体关联。

4. **流式场景可还原**  
   响应以 SSE chunk 返回时，替换值可能被截断，必须支持在不完整 buffer 情况下安全还原。

---

## 2. 核心抽象：会话状态表

### 2.1 MaskingState

`relay/redaction/state.go` 定义了会话级状态表：

```go
type MaskingState struct {
    SessionID     string            `json:"session_id"`
    UserID        int               `json:"user_id"`        // 关联用户 ID
    TokenID       int               `json:"token_id"`       // 关联 token ID
    Forward       map[string]string `json:"forward"`        // 原词 -> 代号
    Inverse       map[string]string `json:"inverse"`        // 代号 -> 原词
    MaskedInverse map[string]string `json:"masked_inverse"` // 替换值 -> 原词
    ForwardIP     map[string]string `json:"forward_ip"`     // 原IP -> 假IP
    TokenForward  map[string]string `json:"token_forward"`  // 原值 -> token
    Counters      map[string]int    `json:"counters"`       // 各类型计数器
    HitCounts     map[string]int    `json:"hit_counts"`     // 各实体类型命中次数
    UsedCodes     map[string]bool   `json:"used_codes"`
    EntityTypes   map[string]string `json:"entity_types"`
    CreatedAt     time.Time         `json:"created_at"`
    LastAccessed  time.Time         `json:"last_accessed"`
}
```

### 2.2 状态表用途

| 状态表 | 写入时机 | 读取时机 | 适用算子 |
|--------|---------|---------|---------|
| `Forward` / `Inverse` | `symbolize` 生成代号时 | 还原 `<SENTINEL>CODE</SENTINEL>` | `symbolize` |
| `MaskedInverse` | `mask` / `randomize` / `tokenize` 生成替换值时 | 按长度降序字符串替换 | `mask`、`randomize`、`tokenize` |
| `ForwardIP` | `randomize` 生成假 IP 时 | 同一会话复用相同假 IP | `randomize` |
| `TokenForward` | `tokenize` 生成 token 时 | 同一会话复用相同 token | `tokenize` |

### 2.3 持久化

- 每会话一个 JSON 文件：`logs/masking/{session_id}.json`
- 服务重启后可从磁盘加载，保持多轮对话映射一致
- 默认 TTL 24 小时，过期后由会话管理器清理
- 旧状态文件缺失 `TokenForward` 等新增字段时，加载时会自动初始化空表

---

## 3. 操作符体系

所有脱敏算子统一通过 `OperatorConfig` 配置，后端常量定义于 `relay/redaction/types.go`。

### 3.1 算子分类

| 算子 | 说明 | 恢复机制 | 会话一致性 |
|------|------|---------|-----------|
| `symbolize` | 替换为 `<SENTINEL>CODE</SENTINEL>` | `Inverse[code] = original` | 通过 `Forward[original] = code` |
| `mask` | 部分掩码，如 `138****5678` | `MaskedInverse[masked] = original` | 确定性生成，同值同掩码 |
| `randomize` | 格式保持随机化：假 IP、假手机号、假身份证、假邮箱、假银行卡、假车牌等 | `MaskedInverse[fake] = original` | 通过专用 Forward 表或 `MaskedInverse` 反向查找 |
| `tokenize` | 定长随机 token | `MaskedInverse[token] = original` | 通过 `TokenForward[original] = token` |
| `block` | 命中后阻断请求 | 不涉及 | 不涉及 |

### 3.3 贪婪数字位数匹配

对于纯数字类型实体（身份证、手机号、银行卡），规则引擎支持**贪婪位数匹配**：

- 规则可配置 `digit_lengths` 声明期望位数，如身份证 `[18]`、银行卡 `[16,17,18,19]`、手机号 `[11]`。
- 当多个规则匹配到同一位置且长度相同时，优先选择位数期望范围更窄的规则。
- 这样可确保 18 位数字优先识别为身份证而非银行卡，脱敏后仍保持 18 位。

实现位置：`relay/redaction/types.go` 的 `Rule.DigitPrecision` 与 `relay/redaction/rules.go` 的排序/合并逻辑。

### 3.4 向后兼容别名

```go
const (
    OpSymbolize OperatorType = "symbolize"
    OpRandomize OperatorType = "randomize"
    OpMask      OperatorType = "mask"
    OpTokenize  OperatorType = "tokenize"
    OpBlock     OperatorType = "block"

    // 别名
    OpReplace  OperatorType = "replace"   // alias for symbolize
    OpIPRandom OperatorType = "ip_random" // alias for randomize
)
```

配置加载时 `NormalizeConfig()` 会自动把 `replace` → `symbolize`、`ip_random` → `randomize`。保存配置时写回的也是规范名。

## 4. 脱敏流程

### 4.1 非流式请求

```
Client Request
    │
    ▼
[RelayTextHelper]
    │
    ▼
[RedactRequest]
    │ 1. 解析/创建 session_id
    │ 2. 加载或创建 MaskingState
    │ 3. 对 user 消息、tool 参数做脱敏
    │ 4. 将 MaskingState 存入 gin.Context
    ▼
[adaptor.ConvertRequest → 上游 LLM]
```

`RedactRequest` 只处理 `role == "user"` 的消息；`assistant` 历史消息不处理，因为模型之前看到的本就是脱敏态。

### 4.2 脱敏执行步骤

1. **检测**：`Analyzer` 使用规则引擎扫描文本，返回 `Entity` 列表（类型、位置、原始值、操作符）。
2. **生成代号**：`Anonymize` 从右到左替换每个实体，先调用 `state.GetCode()` 获取/复用代号。
3. **应用操作符**：`applyOperator()` 根据算子类型生成最终替换值：
   - `symbolize` → `<SENTINEL>CODE</SENTINEL>`
   - `mask` → 部分掩码，写入 `MaskedInverse`
   - `randomize` → 根据实体类型生成格式保持的假值：
     - `IP_ADDRESS` → 假 IPv4，写入 `ForwardIP` 与 `MaskedInverse`
     - `PHONE_NUMBER` → 假中国大陆手机号（1[3-9] + 8 位），写入 `MaskedInverse`
     - `ID_CARD` → 假 18 位身份证号（含校验码），写入 `MaskedInverse`
     - `EMAIL_ADDRESS` → 假邮箱（`local@domain`），写入 `MaskedInverse`
     - `BANK_CARD` → 假银行卡号（16-19 位，通过 Luhn 校验），写入 `MaskedInverse`
     - `LICENSE_PLATE` → 假中国车牌号，写入 `MaskedInverse`
     - 其他类型 → 回退到 `mask`
   - `tokenize` → 定长 token，写入 `TokenForward` 与 `MaskedInverse`
   - `block` → 在更高层触发阻断
4. **保存状态**：请求处理完成后 `MaskingState.Save()` 写入磁盘。

---

## 5. 还原流程

### 5.1 非流式响应

```
Upstream Response
    │
    ▼
[Handler]
    │ 1. 读取完整 body
    │ 2. 从 gin.Context 取出 MaskingState
    │ 3. UnmaskBytes(body, state)
    ▼
Client Response (含原始值)
```

### 5.2 UnmaskText 算法

`relay/redaction/redaction.go`：

1. **先替换 `MaskedInverse`**：按 key 长度降序，把 `mask` / `randomize` / `tokenize` 产生的替换值还原为原始值。
2. **再替换 `Inverse`**：按代号长度降序，把 `<SENTINEL>CODE</SENTINEL>` 还原为原始值。
3. **兼容旧格式**：同时处理 ``CODE`` 旧标记。

按长度降序是为了避免短替换值误覆盖长替换值中的子串。

---

## 6. 流式还原

### 6.1 数据流

```
Upstream SSE Stream
    │
    ▼
[StreamHandler]
    │ 逐行读取 chunk
    ▼
[StreamingUnmasker]
    │ 解析 delta.content
    │ 调用 DrainUnmaskBuffer 处理跨 chunk 截断
    ▼
Client SSE Stream (含原始值)
```

### 6.2 跨 chunk 截断处理

`DrainUnmaskBuffer(buffer, state)` 做三件事：

1. 输出已确认完整的文本；
2. 检查末尾是否为 `<SENTINEL>` 标记的前缀，如果是则 hold 回 buffer；
3. 检查末尾是否为某个 `MaskedInverse` key（如假 IP）的前缀，如果是也 hold 回 buffer，等待后续 chunk 拼接完整后再做替换。

这保证了极小 chunk（如 SenseNova 每次只返回几个字符）也能正确还原。

---

## 7. 规则与配置

### 7.1 规则来源

1. **内置规则**：`relay/redaction/builtin.go` 提供身份证、手机号、邮箱、银行卡、车牌号、IPv4 等正则。
2. **静态规则**：通过关键词生成正则，适合固定词表。
3. **动态规则**：用户自定义正则，灵活性最高。

规则优先级：动态/静态规则 > 内置规则；重叠时保留最长匹配；长度相同时优先保留**数字位数精确度**更高的匹配（如 18 位数字优先识别为身份证而非银行卡）。

### 7.2 内置实体可复制为自定义规则

前端内置实体表格提供「复制为自定义规则」按钮：

1. 后端 `GET /api/masking/builtin` 返回 `BuiltInEntityConfig`，其中包含只读字段 `Pattern`。
2. 前端点击复制后，构造 Rule 追加到 `config.dynamic_rules`。
3. 用户可进一步编辑正则和操作符，再保存生效。

### 7.3 配置文件

`config/redaction.yaml`：

```yaml
enabled: true
fail_closed: true
score_threshold: 0
max_text_length: 1048576
cache_ttl_hours: 24
state_dir: logs/masking
code_style: typed
code_prefix: ENT
code_length: 6
log_raw_requests: true
default_operator:
    type: symbolize
built_in_entities:
    - type: ID_CARD
      name: 中国大陆身份证
      enabled: true
      operator:
        type: randomize
    - type: PHONE_NUMBER
      name: 中国大陆手机号
      enabled: true
      operator:
        type: randomize
    - type: EMAIL_ADDRESS
      name: 电子邮箱
      enabled: true
      operator:
        type: symbolize
    - type: BANK_CARD
      name: 银行卡号
      enabled: true
      operator:
        type: symbolize
    - type: LICENSE_PLATE
      name: 中国车牌号
      enabled: true
      operator:
        type: symbolize
    - type: IP_ADDRESS
      name: IPv4 地址
      enabled: true
      operator:
        type: randomize
        ip_random_preserve_scope: true
        ip_random_cross_class: true
        ip_random_preserve_bits: 0
static_rules: []
dynamic_rules: []
```

### 7.4 人名/用户名识别（新增）

除正则型 PII 外，系统新增两级人名/用户名识别：

1. **字段名 + 中文姓氏规则**（`relay/redaction/field_analyzer.go`）
   - 识别 JSON / HTTP 头 / JWT claim 中的常见字段名，如 `name`、`real_name`、`userName`、`姓名`、`用户名`。
   - 对自由文本做中文姓氏启发式匹配（常见 100+ 姓氏 + 1~3 个汉字），置信度较低，避免高误报。
   - 默认操作符为 `symbolize`。

2. **本地 NER 服务**（`ner_service/`）
   - FastAPI + spaCy（默认 `zh_core_web_sm`）提供 `POST /analyze`。
   - 支持 LRU + TTL 缓存、多 worker 启动。
   - SentinelProxy 通过 `modelAnalyzer` 调用，超时自动回退到规则引擎，不影响主链路。

配置示例：

```yaml
built_in_entities:
    - type: PERSON_NAME
      name: 姓名
      enabled: false
      operator:
        type: symbolize
    - type: USER_NAME
      name: 用户名
      enabled: false
      operator:
        type: symbolize
ner:
    enabled: false
    endpoint: http://127.0.0.1:8000/analyze
    timeout: 50ms
    cache_ttl: 5m
```

启用方式：在 Web 管理界面打开 `PERSON_NAME` / `USER_NAME` 开关，并将 `ner.enabled` 设为 `true`（如需模型增强）。

### 7.5 原始请求/响应查看

开启 `log_raw_requests: true` 后，系统会在处理请求/响应时把关键阶段的内容写入结构化文件：

```
logs/masking/raw/{request_id}.json
```

每个文件包含以下可选字段：

| 字段 | 含义 |
|------|------|
| `request` | 客户端原始请求（脱敏前） |
| `request_after_redaction` | 脱敏后的请求体 |
| `request_converted` | 转换后发给上游的请求体 |
| `response_from_upstream` | 上游返回的原始响应 |
| `response` | 还原后返回给客户端的响应 |
| `stream_text` | 流式响应累积文本 |

前端日志列表每行提供「查看原始请求/响应」按钮，点击后调用 `GET /api/log/:id/raw` 打开详情弹窗。管理员可查看所有日志，普通用户只能查看自己的日志。

---

### 8.1 API

| 接口 | 作用 | 权限 |
|------|------|------|
| `GET /api/masking/config` | 获取当前配置 | root |
| `POST /api/masking/config` | 保存配置并热加载 | root |
| `GET /api/masking/builtin` | 获取内置实体列表（含 `Pattern`） | root |
| `POST /api/masking/preview` | 预览脱敏/还原效果 | root |
| `GET /api/masking/self/stats` | 当前用户脱敏统计聚合 | 登录用户 |
| `GET /api/masking/self/sessions` | 当前用户会话列表 | 登录用户 |
| `GET /api/masking/self/sessions/:id` | 当前用户指定会话的映射详情 | 登录用户 |
| `GET /api/masking/admin/sessions?user_id=` | 管理员查看会话列表（user_id=0 表示全部） | admin |
| `GET /api/masking/admin/sessions/:id` | 管理员查看任意会话详情 | admin |
| `GET /api/log/:id/raw` | 查看指定日志的原始请求/响应 | 登录用户（仅自己的日志） |

### 8.2 用户映射看板

前端新增「脱敏看板」页面（`/masking/dashboard`），登录用户可以：

1. **实时查看聚合统计**：总会话数、总脱敏命中次数、各实体类型命中分布。
2. **查看会话列表**：每个会话展示安全会话标识、创建/最后访问时间、实体数量、命中次数。
3. **查看会话详情**：点击会话后展示：
   - 符号化映射（`<SENTINEL>CODE</SENTINEL>` ↔ 原始值）
   - 掩码 / 格式保持随机化映射（假值 ↔ 原始值）
   - IP 映射（原 IP ↔ 假 IP）
   - Token 映射（原值 ↔ token）

页面每 5 秒自动轮询 `/api/masking/self/stats` 和 `/api/masking/self/sessions`，实现近实时更新。会话 ID 在后端做了一次 SHA-256 摘要后返回给前端，避免暴露原始 `session_id`（可能包含授权头哈希或 IP 信息）。

实现位置：
- 后端：`controller/masking.go` 的 `GetMaskingSessions` / `GetMaskingSessionDetail` / `GetMaskingSelfStats`
- 后端：`relay/redaction/session_manager.go` 的 `ListUserSessions` / `GetUserStats`
- 前端：`web/default/src/components/MaskingDashboard.js`

### 8.3 前端操作符下拉

`web/default/src/components/MaskingSetting.js` 中定义：

```js
const operatorOptions = [
  { key: 'symbolize', text: '可恢复 — 符号化（替换为代号）', value: 'symbolize', description: '可恢复' },
  { key: 'mask',      text: '可恢复 — 掩码化（部分掩码）',     value: 'mask',      description: '可恢复' },
  { key: 'randomize', text: '可恢复 — 格式保持随机化',         value: 'randomize', description: '可恢复' },
  { key: 'tokenize',  text: '可恢复 — 定长 Token 化',          value: 'tokenize',  description: '可恢复' },
  { key: 'block',     text: '阻断 — 阻断请求',                 value: 'block',     description: '阻断' },
];
```

前端 `normalizeOperatorType()` 负责把旧名 `replace` / `ip_random` 映射为规范名，保证旧配置加载后下拉框正确显示。

---

## 9. 关键文件索引

| 文件 | 职责 |
|------|------|
| `relay/redaction/types.go` | 配置结构、操作符常量、规范化逻辑 |
| `relay/redaction/config.go` | 配置加载、保存、热加载 |
| `relay/redaction/state.go` | `MaskingState` 及持久化 |
| `relay/redaction/builtin.go` | 内置 PII 规则 |
| `relay/redaction/rules.go` | 规则引擎 |
| `relay/redaction/analyzer.go` | PII 检测器 |
| `relay/redaction/anonymizer.go` | 脱敏器、代号/token 生成 |
| `relay/redaction/redaction.go` | 入口：`MaskText`、`UnmaskText`、`DrainUnmaskBuffer` |
| `relay/redaction/streaming.go` | 流式还原器 |
| `relay/redaction/randomize_format.go` | 手机号、身份证号的格式保持随机化 |
| `relay/redaction/ip_random.go` | IP 格式保持随机化 |
| `controller/masking.go` | Web API：配置、内置实体、预览 |
| `web/default/src/components/MaskingSetting.js` | 前端脱敏策略配置页 |

---

## 10. 兼容性

- 旧配置中的 `replace` / `ip_random` 仍可加载并自动规范化为 `symbolize` / `randomize`。
- 旧状态文件加载时会自动初始化新增的 `TokenForward` 等字段。
- 已移除 `hash` 操作符；需要定长可恢复替换的场景请使用 `tokenize`。
