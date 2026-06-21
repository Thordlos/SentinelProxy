#!/usr/bin/env bash
set -euo pipefail

# SentinelProxy + Codex 脱敏/还原端到端问答测试
# 通过 Codex CLI 发送带敏感信息的 prompt，验证模型返回中是否还原为原始值，
# 而不是残留 <SENTINEL>xxx</SENTINEL> 等内部标识。
#
# 前置条件：
#   1. SentinelProxy 已启动（默认 http://127.0.0.1:3000）
#   2. CCswitch 已启动（默认 http://127.0.0.1:15721）
#   3. Codex CLI 已安装并指向 CCswitch
#   4. ~/.codex/config.toml 中 base_url = "http://127.0.0.1:15721/v1"
#
# 用法：
#   ./scripts/codex_redaction_test.sh
#   CODEX_BIN=/path/to/codex TIMEOUT=180 ./scripts/codex_redaction_test.sh

CODEX_BIN="${CODEX_BIN:-$HOME/.npm-global/bin/codex}"
SENTINEL_URL="${SENTINEL_URL:-http://127.0.0.1:3000}"
WORK_DIR="${WORK_DIR:-/home/meliodas/文档/proxy/testmask}"
TIMEOUT="${TIMEOUT:-180}"

PASS=0
FAIL=0
RESULTS=()

log() {
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"
}

check_prerequisites() {
  if [[ ! -x "$CODEX_BIN" ]]; then
    log "错误：未找到可执行的 Codex CLI：$CODEX_BIN"
    exit 1
  fi

  if ! curl -fs "$SENTINEL_URL/api/status" >/dev/null 2>&1; then
    log "错误：SentinelProxy 未在 $SENTINEL_URL 响应"
    exit 1
  fi

  if ! ss -tln 2>/dev/null | grep -q '127.0.0.1:15721'; then
    log "错误：CCswitch 未在 127.0.0.1:15721 监听"
    exit 1
  fi

  local base_url
  base_url=$(grep -E '^base_url\s*=' "$HOME/.codex/config.toml" 2>/dev/null | sed 's/.*= *//; s/"//g' || true)
  if [[ "$base_url" != "http://127.0.0.1:15721/v1" ]]; then
    log "警告：~/.codex/config.toml 中的 base_url 不是 http://127.0.0.1:15721/v1（当前值：$base_url）"
  fi

  mkdir -p "$WORK_DIR"
}

# 运行单个测试用例
# $1: 用例名称
# $2: prompt 文件路径
# $3...: 期望在输出中看到的原始子串
run_case() {
  local name="$1"
  local prompt_file="$2"
  shift 2
  local expected=("$@")

  local out="$WORK_DIR/${name}_out.txt"
  local err="$WORK_DIR/${name}_err.txt"

  log ">>> [$name] 开始 Codex 问答测试"

  if ! timeout "$TIMEOUT" "$CODEX_BIN" \
       exec \
       --skip-git-repo-check \
       --ephemeral \
       --color never \
       -o "$out" \
       < "$prompt_file" \
       > "$err" 2>&1; then
    log "[$name] 错误：codex exec 失败或超时"
    tail -n 50 "$err" || true
    FAIL=$((FAIL + 1))
    RESULTS+=("$name: FAIL (exec error)")
    return 1
  fi

  local missing=()
  for s in "${expected[@]}"; do
    if ! grep -qF "$s" "$out"; then
      missing+=("$s")
    fi
  done

  local sentinel_count=0
  sentinel_count=$(grep -cE '<SENTINEL>[^<]+</SENTINEL>' "$out" || true)

  if [[ ${#missing[@]} -gt 0 || $sentinel_count -gt 0 ]]; then
    log "[$name] FAIL"
    for m in "${missing[@]}"; do
      log "  期望出现但未找到: $m"
    done
    if [[ $sentinel_count -gt 0 ]]; then
      log "  残留的 SENTINEL 标记数: $sentinel_count"
      grep -E '<SENTINEL>[^<]+</SENTINEL>' "$out" | head -n 5 || true
    fi
    log "  完整输出见: $out"
    FAIL=$((FAIL + 1))
    RESULTS+=("$name: FAIL")
    return 1
  fi

  log "[$name] PASS"
  PASS=$((PASS + 1))
  RESULTS+=("$name: PASS")
  return 0
}

main() {
  check_prerequisites

  local run_id
  run_id=$(date +%Y%m%d_%H%M%S)
  log "测试运行 ID: $run_id，工作目录: $WORK_DIR"

  # 用例 1：综合 PII 问答
  # 要求模型列出资料中的敏感字段，验证脱敏后仍能还原为原始值。
  cat > "$WORK_DIR/case1_prompt.txt" <<'EOF'
以下是客户资料，请按顺序列出其中的手机号、IP地址、邮箱、身份证号、车牌号，不要省略任何信息：
姓名：赵飞燕
手机号：13925671352
登录IP：112.128.10.120
邮箱：feiyan@gmail.com
身份证号：110101199001011234
车牌号：京A12345
EOF

  run_case "综合PII问答" "$WORK_DIR/case1_prompt.txt" \
    "13925671352" \
    "112.128.10.120" \
    "feiyan@gmail.com" \
    "110101199001011234" \
    "京A12345"

  echo
  log "========== 测试结果 =========="
  for r in "${RESULTS[@]}"; do
    log "$r"
  done
  log "通过: $PASS，失败: $FAIL"

  if [[ $FAIL -gt 0 ]]; then
    exit 1
  fi
}

main "$@"
