# 项目工作说明

## 项目概述

硕士论文工程：**Real-Time AI-Assisted Alert Triage for Smart-Grid Networks Using Go-Based Telemetry and Evidence-Grounded LLMs**。

- 双轨架构：Go 快车道（毫秒级拦截 + 时窗聚合）+ Python 慢车道（RAG + 声明验证），NATS JetStream 解耦。
- 技术栈：Go 1.25（`nats.go`）+ Python 3.12（`uv` + `ruff`）+ NATS JetStream（`nats:2.10-alpine`）。
- 代码在 `go-telemetry/`（Go）和 `ai-agent/`（Python）。Day 1 已打通 Go→NATS→Python 管道，后续在现有骨架上扩展，优先遵循现有代码风格。

## 系统架构与数据流

```
[PCAP/流量] -> Go(capture) -> Go(features) -> Go(aggregator)
                                                    |
                                              Go(producer)
                                                    |  Publish: alerts.<severity>
                                                [NATS JetStream]
                                                    |  Subscribe: alerts.* (queue=ai-agent)
                                           Python(consumer) -> Python(sanitizer)
                                                    |
                                           Python(rag) -> Python(llm) -> Python(verifier)
                                                    |
                                           Python(feedback) -> 分级工单 / 反向通知 Go
```

- **核心契约**：`AlertSnapshot`（Go struct / Python dict，JSON over NATS）。当前在 `main.go` / `main.py`，后续迁移到 `go-telemetry/pkg/contract/` 与 `ai-agent/src/ai_agent/consumer/`。
- **NATS subject**：`alerts.<severity>`，severity ∈ {low, medium, high, critical}。Python 用 `alerts.*` 通配订阅，`queue="ai-agent"` 消费组实现削峰填谷。
- **三个创新点（导师关注，改动谨慎）**：
  1. 双重校验（`verifier/`）：LLM 输出 JSON + Python 硬编码强匹配溯源，0 幻觉弃权机制。
  2. Prompt 注入防护（`sanitizer/`）：外部输入只作只读数据块，永不作指令。
  3. 时窗聚合降噪（`aggregator/`）：滑动窗口打包告警上下文快照，防告警风暴冲垮 LLM。

## 常用命令

workdir 为项目根（`Myproject/`）。

```bash
# NATS
docker compose -f deployments/docker-compose.yml up -d   # 启动（监控: http://localhost:8222）
docker compose -f deployments/docker-compose.yml ps      # 状态
docker compose -f deployments/docker-compose.yml down    # 停止

# Go
go run ./cmd/telemetry              # 运行 publisher
go build -o bin/telemetry ./cmd/telemetry
go test ./...                       # 测试
go mod tidy                         # 整理依赖

# Python（只用 uv，不要用 pip）
uv sync                             # 同步依赖
uv run python -m ai_agent.main      # 运行 subscriber
uv run pytest                       # 测试
uv run ruff check src tests && uv run ruff format src tests  # lint + 格式化
```

**端到端联调**：终端 1 起 NATS，终端 2 `uv run python -m ai_agent.main`，终端 3 `go run ./cmd/telemetry`，预期终端 2 打印 `[收到告警 #1]`。

## 目录结构

```
Myproject/
├── go-telemetry/                  # Go 快车道
│   ├── cmd/telemetry/main.go      # 入口（NATS publisher）
│   ├── internal/                  # capture/ features/ aggregator/ producer/（按 Sprint 填充）
│   ├── pkg/contract/              # 跨语言契约（AlertSnapshot 等）
│   └── go.mod                     # module 名 = masterproject（注意不是 go-telemetry）
├── ai-agent/                      # Python 慢车道
│   ├── src/ai_agent/              # main.py + consumer/ sanitizer/ rag/ llm/ verifier/ api/
│   ├── tests/
│   └── pyproject.toml             # uv + hatchling, py312, ruff line-length=100
├── datasets/                      # SWaT 等，不入库，仅 .gitkeep
├── deployments/docker-compose.yml # NATS JetStream
├── docs/                          # 文档
└── proto/                         # 预留 protobuf（当前用 JSON 契约）
```

## 编码规范

### 数据契约（最高优先级）

- `AlertSnapshot` 是 Go/Python **唯一权威契约**。改字段必须同步两端：Go struct tag ↔ Python dict key ↔ JSON 字段名三者一致。
- Go 用 `json:"snake_case"` tag，Python 用 snake_case key，与现有 `alert_id`、`source_ip` 风格一致。
- **不要单方面改契约**，否则管道断裂。

### Go

- module 名是 `masterproject`（不是 `go-telemetry`），import path 写 `masterproject/internal/xxx`。
- 私有逻辑放 `internal/`，契约放 `pkg/contract/`。错误处理用 `if err != nil`，不要 panic（`log.Fatalf` 仅限启动阶段）。
- 并发用 goroutine + channel，context 要传递不要存 struct。

### Python

- `src/` layout，包名 `ai_agent`。包管理**只用 uv**，不要用 pip/poetry/requirements.txt。
- `ruff` 格式化，line-length=100（不是 88），target py312。提交前跑 `ruff check` + `ruff format`。
- 类型注解必填（verifier 层尤其需要强类型）。异步入口用 `asyncio.run(main())`。

### NATS

- subject：`alerts.<severity>`。消费组固定 `queue="ai-agent"`，不要改。
- Payload 统一 JSON（`json.Marshal` ↔ `json.loads`），不要用裸字符串。
- `Publish` 后必须 `Flush()` 确认发出；subscriber 退出要 `nc.drain()`，不要直接 kill。

## 禁止事项

- 不要入库数据集（`datasets/` 已 gitignore，SWaT/CICICS2019 涉密且体积大）。
- 不要提交 `.env` / API key / LLM token。
- 不要升级核心依赖版本（Go 1.25、Python 3.12、NATS 2.10），除非用户明确要求。
- 不要删 `verifier/` 和 `sanitizer/` 的架构位置——论文核心创新点，即便实现简单也要保留。
- 不要在没 NATS 的情况下跑端到端（Go/Python 都依赖 `nats://localhost:4222`）。

## 验证要求

- **改契约后**：`go build ./...` + `uv run python -c "import ai_agent"` + 端到端联调确认 NATS 消息能正确解析。
- **改 Go 后**：`go build ./...` + `go test ./...` 通过。
- **改 Python 后**：`uv run ruff check src tests` + `uv run pytest` 通过。
- **改 docker-compose 后**：`docker compose up -d` 能起，`http://localhost:8222/healthz` 返回 200。
- **改 verifier/sanitizer 后**：必须有测试用例覆盖（幻觉拦截、注入防护），不能只靠手动验证。
- 测试无法运行时（缺数据集/API key），在回复里说明原因，不要跳过验证。

## 常见坑

- **Go module 名是 `masterproject` 不是 `go-telemetry`**：import 路径写错会编译失败。
- **NATS 必须先于 Go/Python 启动**：NATS 没起会直接 FatalError。
- **Windows Python stdout 全缓冲**：长运行脚本要加 `sys.stdout.reconfigure(line_buffering=True)`，否则日志看不到。
- **`internal/` 子目录目前是空骨架**：按 Sprint 填充，不是 bug。`datasets/` 和 `proto/` 同理目前为空。
