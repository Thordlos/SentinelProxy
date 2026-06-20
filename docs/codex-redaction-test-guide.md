# SentinelProxy + Codex 脱敏还原闭环测试指南

本文档记录如何使用 OpenAI Codex CLI 对 SentinelProxy 的脱敏（redaction）和还原功能进行端到端测试。

## 测试目的

验证 SentinelProxy 在流式（streaming）响应场景下：
1. 能正确识别用户消息中的敏感信息（手机号、IP、邮箱等）
2. 能将其替换为内部标识（如 `<SENTINEL>PHONE_NUMBER_1</SENTINEL>`）后发送给上游模型
3. 能在模型返回的响应中识别这些标识并还原为原始值

## 环境要求

- SentinelProxy 已编译（`SentinelProxy` 二进制）
- CCswitch 已启动（默认监听 `127.0.0.1:15721`）
- Codex CLI 已安装（`~/.npm-global/bin/codex`）
- Codex 配置中 `model_providers.LongCat.base_url` 指向 CCswitch

## 目录结构

```text
/home/meliodas/文档/proxy/SentinelProxy/
├── SentinelProxy              # 编译后的二进制
├── config/redaction.yaml      # 脱敏配置文件
├── logs/                      # 运行日志
│   ├── oneapi-YYYYMMDD.log
│   └── masking/               # 脱敏状态文件
└── docs/
    └── codex-redaction-test-guide.md  # 本文档
```

## 操作步骤

### 1. 编译 SentinelProxy

```bash
cd /home/meliodas/文档/proxy/SentinelProxy
/home/meliodas/.local/go/bin/go build -o SentinelProxy main.go
```

### 2. 启动 SentinelProxy

```bash
cd /home/meliodas/文档/proxy/SentinelProxy
pkill -f "./SentinelProxy"
nohup ./SentinelProxy --port 3000 --log-dir ./logs > /tmp/sentinelproxy.out 2>&1 &
```

确认服务已启动：

```bash
ps aux | grep SentinelProxy | grep -v grep
```

### 3. 确认 CCswitch 配置

CCswitch 负责把 Codex 的 Responses API 请求转换为 Chat Completions 请求转发给 SentinelProxy。

检查 CCswitch 是否在运行：

```bash
ss -tlnp | grep 15721
# 或
ps aux | grep cc-switch | grep -v grep
```

检查 Codex 配置指向 CCswitch：

```bash
grep base_url /home/meliodas/.codex/config.toml
# 应输出：base_url = "http://127.0.0.1:15721/v1"
```

### 4. 开启原始请求/响应日志（可选但推荐）

进入 SentinelProxy Web 管理界面：`http://localhost:3000/`

1. 登录（默认 root / 123456）
2. 进入「脱敏策略配置」
3. 勾选「记录原始请求/响应（仅调试使用，会记录敏感信息）」
4. 保存配置

> 安全提示：测试完成后关闭此开关，并删除包含敏感信息的日志。

### 5. 执行 Codex 测试

在受信任的目录下执行（如 `/home/meliodas/文档/proxy/testmask`）：

```bash
cd /home/meliodas/文档/proxy/testmask
echo "请帮我生成一封给客户的确认邮件草稿，内容包括：告知客户他的账号已完成进门登记报备，请他在今天之内回复确认。客户的资料如下：姓名赵飞燕，注册手机13925671352，常用登录IP 112.128.10.120，联系邮箱feiyan@gmail.com。邮件语气要正式礼貌，落款用客服部。" | codex exec --skip-git-repo-check
```

### 6. 验证结果

如果脱敏还原正常工作，响应中应显示原始敏感信息：

```text
- 注册手机：13925671352
- 常用登录IP：112.128.10.120
- 联系邮箱：feiyan@gmail.com
```

如果失败，响应中会保留内部标识：

```text
- 注册手机：<SENTINEL>PHONE_NUMBER_1</SENTINEL>
```

### 7. 查看日志

实时查看原始请求/响应日志：

```bash
tail -f /home/meliodas/文档/proxy/SentinelProxy/logs/oneapi-$(date +%Y%m%d).log | grep -E "\[RAW REQUEST|RAW RESPONSE\]"
```

关键日志标记：

- `[RAW REQUEST]`：客户端原始请求（脱敏前）
- `[RAW REQUEST AFTER REDACTION]`：脱敏后发给上游模型的请求
- `[RAW RESPONSE FROM UPSTREAM]`：上游返回的原始响应
- `[RAW RESPONSE]`：还原后返回给客户端的响应
- `[RAW RESPONSE STREAM]`：流式响应的累积文本

### 8. 清理

测试完成后：

```bash
# 关闭原始请求/响应日志开关（在 Web 界面操作）

# 删除包含敏感信息的日志
rm -f /home/meliodas/文档/proxy/SentinelProxy/logs/oneapi-*.log
rm -rf /home/meliodas/文档/proxy/SentinelProxy/logs/masking/*

# 停止服务
pkill -f "./SentinelProxy"
```

## 常见问题

### Q: Codex 提示 `Invalid URL (POST /v1/responses)`
A: SentinelProxy 不支持 Responses API。需要通过 CCswitch 转换，确保 Codex 配置中 `base_url` 指向 CCswitch（`http://127.0.0.1:15721/v1`），而不是直接指向 SentinelProxy。

### Q: 响应中保留了 `<SENTINEL>PHONE_NUMBER_1</SENTINEL>` 没有还原
A: 可能是流式响应中标签被拆成多个 chunk，而 `DrainUnmaskBuffer` 没有正确处理不完整标签前缀。检查是否运行了最新版本的 SentinelProxy。

### Q: 日志中没有 `[RAW REQUEST]` 等标记
A: 确认已在 Web 界面开启「记录原始请求/响应」开关，并且服务已重启。

## 相关代码文件

- `relay/redaction/anonymizer.go`：脱敏标识生成
- `relay/redaction/redaction.go`：`UnmaskText`、`DrainUnmaskBuffer`
- `relay/redaction/streaming.go`：`StreamingUnmasker`
- `relay/adaptor/openai/main.go`：流式响应处理
- `controller/relay.go`：原始请求日志
- `relay/controller/text.go`：脱敏后请求日志
