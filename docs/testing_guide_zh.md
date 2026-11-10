# EdgeCat 本地测试与验证指南 (Testing & Verification Guide)

<p align="center">
  <a href="testing_guide.md">English</a> •
  <b>中文</b>
</p>

本文档指导开发者在本地（Windows / macOS / Linux）环境下对 **EdgeCat** 网关进行从单元测试、模拟全链路演示到真实客户端接入的全维度验证。

---

## 目录
1. [方式一：全自动单元与集成测试 (Go Test)](#方式一全自动单元与集成测试-go-test)
2. [方式二：轻量全链路模拟演示 (Mock Upstream + PowerShell)](#方式二轻量全链路模拟演示-mock-upstream--powershell)
3. [方式三：命令行手动端到端验证 (cURL / PowerShell)](#方式三命令行手动端到端验证-curl--powershell)
4. [方式四：对接真实第三方客户端 (Cherry Studio / Chatbox / Python SDK)](#方式四对接真实第三方客户端-cherry-studio--chatbox--python-sdk)

---

## 方式一：全自动单元与集成测试 (Go Test)

最快速、最严谨的测试方式。覆盖了流式滑动窗口脱敏、TTFT 首字超时降级、协议无损透传、Fail-Closed 自检、多设备 Token 鉴权、CORS/PNA 预检及云端配额熔断。

### 1. 运行全仓库测试
```bash
go test -v ./...
```

### 2. 按核心特性定向测试
- **测试 Phase 2 新特性**（动态模型发现、Token 鉴权、CORS/Chrome PNA 预检、云端配额熔断）：
  ```bash
  go test -v ./internal/proxy -run "TestProxy_Phase2"
  ```
- **测试 Fail-Closed 局域网自检门卫**（验证绑定非回环地址时强制要求鉴权）：
  ```bash
  go test -v ./internal/config
  ```
- **测试 SQLite 配额持久化与自然日重置**：
  ```bash
  go test -v ./internal/quota
  ```
- **测试滑动窗口跨 Chunk 拼接还原**（验证占位符被拆包时自动缝合）：
  ```bash
  go test -v ./internal/filter
  ```
- **静态代码合规检查**：
  ```bash
  gofmt -l .
  go vet ./...
  ```

---

## 方式二：轻量全链路模拟演示 (Mock Upstream + PowerShell)

无需真实安装 Ollama，也不需要消耗云端 API Key。项目内置了 `mock_upstream`（轻量模拟本地大模型服务）与端到端自动化验证脚本。

### 步骤 1：启动模拟本地大模型服务 (终端 ①)
```powershell
go run ./cmd/mock_upstream
```
> 控制台将输出：`[Mock Upstream] Listening on http://127.0.0.1:11434 (Simulating Ollama / vLLM)...`

### 步骤 2：启动 EdgeCat 网关 (终端 ②)
```powershell
go run ./cmd/edgecat -config configs/edgecat.example.yaml
```
> 控制台将打印 EdgeCat 启动 Banner，显示初始化本地/云端端点、SQLite WAL 审计日志与配额管理器。

### 步骤 3：运行全链路测试脚本 (终端 ③)
```powershell
.\scripts\test_gateway.ps1
```

#### 脚本执行验收效果：
1. **探活与健康检查**：获取 `/health`，展示本地端点槽位与审计统计；
2. **非流式 PII 脱敏实测**：客户端发送含手机号与邮箱的内容，`mock_upstream` 终端显示收到的请求已被遮蔽为 `{{EC_PII_PHONE_1}}` 和 `{{EC_PII_EMAIL_1}}`，而客户端收到的最终响应被网关自动无感还原为明文；
3. **SSE 流式实时还原**：以流式打字机模式逐 Chunk 接收回复，验证跨分包还原；
4. **SQLite 异步落盘检验**：查询批量写盘的审计记录总数。

---

## 方式三：命令行手动端到端验证 (cURL / PowerShell)

启动 EdgeCat 后，可直接使用系统内置的 `curl.exe` 验证各治理机制：

### 1. 验证动态模型发现（隐藏内部物理名）
```powershell
curl.exe -s http://127.0.0.1:8080/v1/models
```
**期望结果**：返回由配置中的映射派生的逻辑模型列表（如 `default`, `gpt-4o-mini`, `qwen2.5:7b`），且内部物理模型名（如带有特定本地路径或云端私有名字的端点）绝不泄露。

### 2. 验证 Chrome PNA 局域网跨域预检（供 PatchCat 直连）
```powershell
curl.exe -i -X OPTIONS http://127.0.0.1:8080/v1/chat/completions `
  -H "Origin: https://patchcat.dev" `
  -H "Access-Control-Request-Method: POST" `
  -H "Access-Control-Request-Private-Network: true"
```
**期望结果**：HTTP 状态码返回 `204 No Content`，并且包含：
- `Access-Control-Allow-Origin: https://patchcat.dev`
- `Access-Control-Allow-Private-Network: true`

### 3. 查看 `/health` 分账与配额视图
```powershell
curl.exe -s http://127.0.0.1:8080/health
```
**期望结果**：JSON 返回中包含 `status: "healthy"`、并发信号量占用、`clients_usage`（各设备今日云端调用量与剩余额度）及 `next_quota_reset`。

---

## 方式四：对接真实第三方客户端 (Cherry Studio / Chatbox / Python SDK)

将 EdgeCat 作为透明中继网关：

### 1. 桌面客户端接入配置 (Chatbox / Cherry Studio / NextChat)
- **API 提供商 (Provider)**：选择 `OpenAI API`
- **API 地址 (Base URL)**：`http://127.0.0.1:8080/v1`
- **API Key**：
  - 若 `configs/edgecat.example.yaml` 中启用了 `auth.enabled: true`，填入对应客户端的令牌（例如 `ec-dev-token-abc`）；
  - 若未启用鉴权，可随意填写（如 `none`）。
- **模型名称**：填写 `default` 或 `gpt-4o-mini`。

### 2. 官方 Python SDK 接入验证
```python
from openai import OpenAI

# 将 base_url 指向本地 EdgeCat 网关
client = OpenAI(
    base_url="http://127.0.0.1:8080/v1",
    api_key="ec-dev-token-abc"  # 或未开鉴权时填 "none"
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[
        {"role": "user", "content": "我的电话是 13800138000，请复述我的电话"}
    ],
    stream=True
)

for chunk in response:
    if chunk.choices and chunk.choices[0].delta.content:
        print(chunk.choices[0].delta.content, end="", flush=True)
print()
```
