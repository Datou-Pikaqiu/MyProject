# 项目工作说明

## 项目概述

硕士论文工程：**Real-Time AI-Assisted Alert Triage for Smart-Grid Networks Using Go-Based Telemetry and Evidence-Grounded LLMs**。

- 双轨架构：Go 快车道（时窗聚合 + JetStream 发布）+ Python 慢车道（sanitizer → RAG → LLM → verifier → metrics），NATS JetStream 解耦。
- 技术栈：Go 1.25（`nats.go`）+ Python 3.12（`uv` + `pydantic v2` + `ruff`）+ NATS JetStream（`nats:2.10-alpine`）。
- 代码在 `go-telemetry/`（Go）和 `ai-agent/`（Python）。Day 8 已完成全链路指标采集。

## 系统架构与数据流

```
[JSONL/PCAP] -> Go(capture) -> Go(aggregator) -> Go(producer)
                                    |  时间窗口聚合 (5s / 10条阈值)
                                    |  Publish: alerts.bundle.<severity>
                              [NATS JetStream]
                                    |  Subscribe: alerts.bundle.* (queue=ai-agent)
                           Python(consumer) → Python(sanitizer)
                                    |
                           Python(rag) → Python(llm) → Python(verifier)
                                    |
                           Python(metrics) → 指标报表（文本 + JSON）
```

- **两个核心契约**（都在 `pkg/contract/` + `consumer/models.py`）：
  - `AlertSnapshot`：单条告警（15 字段：基础元数据 + 上下文特征 + 设备状态 + 拓扑）
  - `AlertContextBundle`：时窗聚合包（Day 3 新增，含去重 IP、最高严重度、风暴检测、根因节点）
- **NATS subject**：
  - `alerts.<severity>` — 单条告警（Day 1-2，目前 producer 不再用）
  - `alerts.bundle.<severity>` — 聚合 Bundle（Day 3+，当前使用）
  - stream 名 `ALERTS`，subjects=`["alerts.*", "alerts.bundle.*"]`，消费组 `queue="ai-agent"`
- **三个创新点（论文核心，均已实现）**：
  1. 双重校验（`verifier/` ✅ Day 5）：LLM 输出 JSON + Python 硬编码强匹配溯源，0 幻觉弃权机制。
  2. Prompt 注入防护（`sanitizer/` ✅ Day 6）：外部输入只作只读数据块，永不作指令。
  3. 时窗聚合降噪（`aggregator/` ✅ Day 3）：滑动窗口打包告警上下文快照，防告警风暴冲垮 LLM。

## 常用命令

workdir 为项目根（`Myproject/`）。

```bash
# NATS
docker compose -f deployments/docker-compose.yml up -d        # 启动（监控: http://localhost:8222）
docker compose -f deployments/docker-compose.yml down         # 停止
docker compose -f deployments/docker-compose.yml down -v      # 清空 JetStream 数据（改 stream 配置时用）

# Go（workdir: go-telemetry/）
go run ./cmd/telemetry --file ../datasets/synthetic_alerts.jsonl --interval 200ms
# 可选参数：--window 5s（聚合窗口）--max-alerts 10（风暴阈值）
go build -o bin/telemetry ./cmd/telemetry
go test ./...

# Python（workdir: ai-agent/，只用 uv）
uv sync                                    # 同步依赖
uv run python -m ai_agent.main             # 运行 subscriber（订阅 Bundle，Ctrl+C 退出）
uv run python -m ai_agent.main --exit-after-bundles=41  # 实验模式：收 41 Bundle 后自动退出 + 打印指标
uv run python -m ai_agent.main --exit-after-bundles=41 --no-rag       # 消融：无 RAG
uv run python -m ai_agent.main --exit-after-bundles=41 --no-verifier  # 消融：无 Verifier
uv run python scripts/run_ablation.py               # 一键跑全部消融实验
uv run python -m ai_agent.scripts.generate_alerts  # 生成合成数据
uv run ruff check src tests; uv run ruff format src tests
uv run python tests/test_verifier.py       # verifier 单测
uv run python tests/test_sanitizer.py      # sanitizer 单测
uv run python tests/test_rag.py            # RAG 单测
```

**端到端联调**：终端 1 起 NATS，终端 2 `uv run python -m ai_agent.main`，终端 3 `go run ./cmd/telemetry --file ../datasets/synthetic_alerts.jsonl --interval 200ms`，预期终端 2 打印 41 个 Bundle（含 1 个 `[STORM]`）。

## 目录结构

```
Myproject/
├── go-telemetry/
│   ├── cmd/telemetry/main.go       # 入口（管道组装：读文件→聚合→发布）
│   ├── internal/
│   │   ├── aggregator/             # ✅ 时窗聚合器（Day 3）
│   │   ├── producer/               # ✅ JetStream 发布（Day 3）
│   │   ├── capture/                # 待实现（PCAP 重放）
│   │   └── features/               # 待实现（特征提取）
│   ├── pkg/contract/               # ✅ alert.go + bundle.go
│   └── go.mod                      # module 名 = masterproject
├── ai-agent/
│   ├── src/ai_agent/
│   │   ├── main.py                 # 入口（订阅 → sanitizer → RAG → LLM → verifier → metrics）
│   │   ├── consumer/models.py      # ✅ AlertSnapshot + AlertContextBundle
│   │   ├── llm/                    # ✅ LLM 分诊（Day 4）
│   │   │   ├── models.py           #    TriageReport 分诊报告模型
│   │   │   ├── prompts.py          #    提示词模板（系统/用户分离）
│   │   │   └── client.py           #    DeepSeek API 异步客户端
│   │   ├── verifier/               # ✅ 声明验证（Day 5，创新点1）
│   │   │   ├── models.py           #    VerificationResult 验证结果模型
│   │   │   └── verifier.py         #    硬编码强匹配 + 弃权机制
│   │   ├── sanitizer/             # ✅ Prompt 注入防护（Day 6，创新点2）
│   │   │   ├── models.py           #    SanitizationResult 净化结果模型
│   │   │   └── sanitizer.py        #    注入检测 + 净化（5 类 × 23 条正则）
│   │   ├── rag/                    # ✅ RAG 知识库（Day 7）
│   │   │   ├── models.py           #    KnowledgeDocument + RAGContext 模型
│   │   │   ├── knowledge.py        #    10 条电网安全领域文档 + 标签索引
│   │   │   └── retriever.py        #    关键词提取 + Top-K 检索
│   │   ├── metrics/                # ✅ 指标采集（Day 8）
│   │   │   └── collector.py        #    MetricsCollector + 文本/JSON 报表
│   │   ├── scripts/generate_alerts.py  # ✅ 合成数据生成器
│   │   ├── api/                    # 待实现
│   ├── tests/
│   └── pyproject.toml              # uv + hatchling, py312, pydantic v2, ruff
├── datasets/synthetic_alerts.jsonl # ✅ 合成数据（100 条，5 种攻击 + 风暴）
├── deployments/docker-compose.yml  # NATS JetStream
├── docs/  proto/                   # 预留
```

## 编码规范

### 数据契约（最高优先级）

- `AlertSnapshot` 和 `AlertContextBundle` 是 Go/Python **唯一权威契约**。改字段必须同步两端：Go struct tag ↔ Python Pydantic field ↔ JSON 字段名三者一致。
- Go 契约在 `pkg/contract/`（`alert.go` + `bundle.go`），Python 在 `consumer/models.py`。
- Go 用 `json:"snake_case"` tag，Python 用 snake_case key，与现有 `alert_id`、`source_ip` 风格一致。
- **不要单方面改契约**，否则管道断裂。

### Go

- module 名是 `masterproject`（不是 `go-telemetry`），import path 写 `masterproject/internal/xxx`。
- 私有逻辑放 `internal/`，契约放 `pkg/contract/`。错误处理用 `if err != nil`，不要 panic（`log.Fatalf` 仅限启动阶段）。
- main.go 只负责管道组装，业务逻辑在 `internal/` 包里。

### Python

- `src/` layout，包名 `ai_agent`。包管理**只用 uv**，不要用 pip/poetry/requirements.txt。
- 数据模型用 Pydantic v2（`BaseModel`），JSON 解析用 `model_validate_json()`。
- `ruff` 格式化，line-length=100（不是 88），target py312。提交前跑 `ruff check` + `ruff format`。
- 类型注解必填。异步入口用 `asyncio.run(main())`。

### NATS / JetStream

- subject：`alerts.bundle.<severity>`（当前用）。消费组固定 `queue="ai-agent"`，不要改。
- stream 名 `ALERTS`，subjects 必须包含 `alerts.*` 和 `alerts.bundle.*`。
- JetStream publish 是同步的（有 ack），不需要 Flush。subscriber 退出要 `nc.drain()`。
- 改 stream 配置后必须 `down -v` 清空 volume，否则旧配置残留。

## 禁止事项

- 不要入库数据集（`datasets/` 已 gitignore，SWaT 涉密）。
- 不要提交 `.env` / API key / LLM token。
- 不要升级核心依赖版本（Go 1.25、Python 3.12、NATS 2.10）。
- 不要删 `verifier/` 和 `sanitizer/` 的架构位置——论文核心创新点。
- 不要在没 NATS 的情况下跑端到端。

## 验证要求

- **改契约后**：`go build ./...` + `uv run python -c "from ai_agent.consumer.models import *"` + 端到端联调。
- **改 Go 后**：`go build ./...` + `go test ./...` 通过。
- **改 Python 后**：`uv run ruff check src tests` + `uv run pytest` 通过。
- **改 aggregator/producer 后**：跑端到端联调，确认 Bundle 数和风暴检测正常。
- **改 docker-compose 后**：`docker compose up -d` 能起，`http://localhost:8222/healthz` 返回 200。
- 测试无法运行时（缺 API key 等），在回复里说明原因，不要跳过验证。

## 常见坑

- **Go module 名是 `masterproject`**：import 路径写 `go-telemetry/...` 会编译失败。
- **NATS 必须先于 Go/Python 启动**：NATS 没起会直接 FatalError。
- **改 stream 配置要 `down -v`**：`docker compose down` 不删 volume，旧 stream 配置残留会导致新 subject 订阅失败。
- **遗留 python 进程**：`uv run` 启动的 python 子进程可能不会被 `Stop-Process` 杀干净，多个 subscriber 在同一 queue group 会平分消息。用 `Get-Process python` 检查。
- **Windows Python stdout 全缓冲**：长运行脚本要加 `sys.stdout.reconfigure(line_buffering=True)`。
- **跨语言时间戳**：Go `time.Time` 要求 RFC 3339（带时区），Python 必须用 `datetime.now().astimezone()`，naive datetime 会被 Go 拒绝。

## 研发阶段（对照提案）

- [x] **Day 1**：Go→NATS→Python 管道打通（hello world AlertSnapshot）。
- [x] **Day 2**：契约细化（15 字段）+ 合成数据生成器 + JetStream 持久化 + 持续流转验证。
- [x] **Day 3**：时窗聚合器（`internal/aggregator/`）+ Go 代码重构（`internal/producer/`）+ AlertContextBundle + 风暴检测。
- [x] **Day 4**：LLM 接入（DeepSeek API + JSON Mode）+ TriageReport 分诊报告模型 + 提示词模板（系统/用户分离，防注入基础）+ 异步分诊（Semaphore 并发控制）。端到端验证：100 条告警 → 41 Bundle → 41 分诊报告，LLM 完美识别 DDoS 攻击（malicious/ddos/block/0.95）。
- [x] **Day 5**：verifier 声明验证层（论文创新点1：双重校验）+ 硬编码强匹配 evidence + 弃权机制（0 幻觉）。端到端验证：41 报告 → 38 验证通过（92.7%）+ 3 弃权（7.3%），风暴 Bundle 5/5 evidence 全部验证通过。
- [x] **Day 6**：sanitizer 注入防护（论文创新点2）+ 5 类注入模式（中英双语）× 23 条正则 + 占位符替换。端到端验证：3 条注入告警全被检测（instruction_override / role_hijacking / jailbreak），净化后 LLM 无法被注入操控。
- [x] **Day 7**：RAG 知识库 + 10 条电网安全领域文档 + 关键词标签检索 + Top-K 注入 prompt。端到端验证：41/41 Bundle 全部检索到领域知识，LLM 推理引用"工程站安全""Modbus 协议"等专业知识。
- [x] **Day 8**：metrics 指标采集模块 + 结构化报表（文本/JSON）+ NATS 管道完整实验。100 条告警 → 41 Bundle（压缩比 2.4:1，降噪 59%），LLM 平均延迟 1892ms，verifier 弃权率 2.4%（1/41），RAG 命中率 3.0 条/Bundle。新增 `--exit-after-bundles=N` 实验模式。
- [x] **Day 9**：修复 LLM token 追踪（`client.last_*_tokens`）+ 消融实验框架（`--no-rag` / `--no-verifier`）+ 自动运行器 `scripts/run_ablation.py`（串行 3 组实验 → 对比表 + JSON）。
- [ ] **Day 10+**：SWaT 数据实验 + 论文图表生成 + 终稿。
