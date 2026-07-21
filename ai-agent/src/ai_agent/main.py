"""AI Agent - Subscriber（Day 4 版本，接收 Bundle + LLM 分诊）。

Day 4 变化：收到 Bundle 后，不只是打印聚合信息，还调用 DeepSeek API 进行 LLM 分诊。
分诊是异步的（asyncio.create_task），不阻塞 NATS callback，避免消息积压。

演进历史：
  Day 2: alerts.*          → 接收单条 AlertSnapshot，打印
  Day 3: alerts.bundle.*   → 接收聚合 AlertContextBundle，打印聚合上下文
  Day 4: alerts.bundle.*   → 接收 Bundle → 异步调 LLM → 打印分诊报告

数据流：
  [Go publisher] → [NATS JetStream] → [on_message]
                                            ↓
                                  asyncio.create_task(triage_and_print)
                                            ↓
                                  [LLMClient.triage] → [DeepSeek API]
                                            ↓
                                  打印 TriageReport
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)

STREAM_NAME = "ALERTS"
MAX_CONCURRENT_LLM = 3  # 最多 3 个并发 LLM 调用（防止 API 限流）


async def main() -> None:
    import nats

    from ai_agent.consumer.models import AlertContextBundle
    from ai_agent.llm.client import LLMClient

    # 1. 连接 NATS
    nc = await nats.connect("nats://localhost:4222")
    print("[OK] Python subscriber 已连接 NATS")

    # 2. 确保 JetStream stream 存在且 subjects 包含 alerts.bundle.*
    js = nc.jetstream()
    try:
        await js.stream_info(STREAM_NAME)
        try:
            await js.update_stream(name=STREAM_NAME, subjects=["alerts.*", "alerts.bundle.*"])
        except Exception:
            pass  # Go 端可能已经更新了，忽略
        print(f"[OK] JetStream stream 就绪: {STREAM_NAME}")
    except Exception:
        try:
            await js.add_stream(name=STREAM_NAME, subjects=["alerts.*", "alerts.bundle.*"])
            print(f"[OK] 已创建 JetStream stream: {STREAM_NAME}")
        except Exception:
            print(f"[OK] stream {STREAM_NAME} 已被 Go 端创建")

    # 3. 初始化 LLM 客户端 + 并发控制
    print("[OK] 初始化 LLM 客户端...")
    llm_client = LLMClient()
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_LLM)
    print(f"[OK] LLM 就绪（最多 {MAX_CONCURRENT_LLM} 个并发分诊）")

    # 4. 统计计数器
    bundles_received = 0
    reports_generated = 0
    total_alerts = 0
    storm_bundles = 0
    by_max_severity: dict[str, int] = defaultdict(int)
    by_classification: dict[str, int] = defaultdict(int)
    start_time = datetime.now()

    # 5. LLM 分诊函数（异步，用 semaphore 限制并发）
    async def triage_and_print(bundle: AlertContextBundle, bundle_num: int) -> None:
        nonlocal reports_generated

        async with semaphore:
            print(f"\n[Bundle #{bundle_num}] 开始 LLM 分诊...")
            report = await llm_client.triage(bundle)

            if report is None:
                print(f"[Bundle #{bundle_num}] LLM 分诊失败")
                return

            reports_generated += 1
            by_classification[report.classification.value] += 1

            # 打印分诊报告
            print(f"\n{'=' * 60}")
            print(f"[分诊报告] Bundle #{bundle_num} ({bundle.bundle_id})")
            print(f"{'=' * 60}")
            print(f"  分类:     {report.classification.value}")
            print(f"  攻击类型: {report.attack_type.value}")
            print(f"  置信度:   {report.confidence:.2f}")
            print(f"  处置:     {report.recommended_action.value}")
            print(f"  推理:     {report.reasoning}")
            print("  证据:")
            for ev in report.evidence:
                print(f"    - {ev}")
            if report.severity_override:
                print(f"  严重度覆盖: {report.severity_override}")
            print(f"{'=' * 60}")

    # 6. 消息回调（收到 Bundle 后异步启动 LLM 分诊）
    async def on_message(msg) -> None:
        nonlocal bundles_received, total_alerts, storm_bundles

        try:
            bundle = AlertContextBundle.model_validate_json(msg.data)
        except Exception as e:
            print(f"[!] 解析失败 (subject={msg.subject}): {e}")
            return

        bundles_received += 1
        total_alerts += bundle.alert_count
        by_max_severity[bundle.max_severity.value] += 1

        if bundle.is_alert_storm:
            storm_bundles += 1

        # 打印 Bundle 摘要（保留 Day 3 的功能）
        storm_tag = " [STORM]" if bundle.is_alert_storm else ""
        window_ms = (bundle.window_end - bundle.window_start).total_seconds() * 1000

        print(
            f"\n[Bundle #{bundles_received:3d}] {bundle.bundle_id}\n"
            f"  告警数: {bundle.alert_count} | 最高严重度: "
            f"{bundle.max_severity.value:8s}{storm_tag}\n"
            f"  窗口时长: {window_ms:.0f}ms | 平均速率: {bundle.avg_packet_rate:.0f} pps"
        )

        if bundle.is_alert_storm:
            print("  *** 告警风暴检测 ***")
            print(f"  风暴中心节点: {bundle.storm_node_id}")
            print(f"  子网: {bundle.subnet}")
            print(f"  总连接失败: {bundle.total_failed_conn}")

        # 异步启动 LLM 分诊（不阻塞 callback，NATS 继续接收下一个消息）
        asyncio.create_task(triage_and_print(bundle, bundles_received))

    # 7. 订阅 alerts.bundle.*
    await js.subscribe("alerts.bundle.*", cb=on_message, queue="ai-agent")
    print("[OK] 已订阅 alerts.bundle.* (JetStream)，等待 Go 端发布 Bundle...")
    print("     (按 Ctrl+C 退出)\n")

    # 8. 保持运行
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        elapsed = (datetime.now() - start_time).total_seconds()
        print("\n\n[退出] 统计汇总")
        print(f"  接收 Bundle:    {bundles_received}")
        print(f"  LLM 分诊报告:   {reports_generated}")
        print(f"  告警总数:       {total_alerts}")
        print(f"  风暴 Bundle:    {storm_bundles}")
        print(f"  按最高严重度:   {dict(by_max_severity)}")
        print(f"  按分诊分类:     {dict(by_classification)}")
        if elapsed > 0:
            print(f"  耗时:           {elapsed:.1f}s")
        await nc.drain()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[退出] Bye")
        sys.exit(0)
