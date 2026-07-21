"""AI Agent - Subscriber（Day 3 版本，接收聚合 Bundle）。

Day 3 变化：不再接收单条 AlertSnapshot，而是接收聚合后的 AlertContextBundle。
Go 端把一个时间窗口内的多条告警打包成 Bundle，避免告警风暴冲垮 LLM。

订阅 subject 变化：
  Day 2: alerts.*           （单条告警）
  Day 3: alerts.bundle.*    （聚合 Bundle）
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from datetime import datetime

sys.stdout.reconfigure(line_buffering=True)

STREAM_NAME = "ALERTS"


async def main() -> None:
    import nats

    from ai_agent.consumer.models import AlertContextBundle

    # 1. 连接 NATS
    nc = await nats.connect("nats://localhost:4222")
    print("[OK] Python subscriber 已连接 NATS")

    # 2. 确保 JetStream stream 存在且 subjects 包含 alerts.bundle.*
    # Day 2 的旧 stream 可能只有 alerts.*，需要更新
    js = nc.jetstream()
    try:
        await js.stream_info(STREAM_NAME)
        # stream 已存在，更新配置确保 subjects 完整
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

    # 3. 统计计数器
    bundles_received = 0       # 接收的 Bundle 数
    total_alerts = 0           # 所有 Bundle 里的告警总数
    storm_bundles = 0          # 风暴 Bundle 数
    by_max_severity: dict[str, int] = defaultdict(int)
    start_time = datetime.now()

    # 4. 消息回调
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

        # 详细输出每个 Bundle
        storm_tag = " [STORM]" if bundle.is_alert_storm else ""
        window_ms = (bundle.window_end - bundle.window_start).total_seconds() * 1000

        print(
            f"\n[Bundle #{bundles_received:3d}] {bundle.bundle_id}\n"
            f"  告警数: {bundle.alert_count} | 最高严重度: {bundle.max_severity.value:8s}{storm_tag}\n"
            f"  源IP: {len(bundle.source_ips)} 个 {bundle.source_ips[:3]}{'...' if len(bundle.source_ips) > 3 else ''}\n"
            f"  目的IP: {len(bundle.dest_ips)} 个 {bundle.dest_ips[:3]}{'...' if len(bundle.dest_ips) > 3 else ''}\n"
            f"  窗口时长: {window_ms:.0f}ms | 平均速率: {bundle.avg_packet_rate:.0f} pps"
        )

        if bundle.is_alert_storm:
            print("  *** 告警风暴检测 ***")
            print(f"  风暴中心节点: {bundle.storm_node_id}")
            print(f"  子网: {bundle.subnet}")
            print(f"  总连接失败: {bundle.total_failed_conn}")
            # 显示前 3 条告警摘要
            print("  前 3 条告警:")
            for a in bundle.alerts[:3]:
                print(f"    - {a.alert_id} | {a.severity.value:8s} | {a.source_ip} -> {a.dest_ip}")
            if bundle.alert_count > 3:
                print(f"    ... 还有 {bundle.alert_count - 3} 条")

        # 每 5 个 Bundle 打印一次汇总
        if bundles_received % 5 == 0:
            print(
                f"\n  --- 汇总: {bundles_received} 个 Bundle, "
                f"{total_alerts} 条告警, "
                f"{storm_bundles} 个风暴 | "
                f"分布: {dict(by_max_severity)}\n"
            )

    # 5. 订阅 alerts.bundle.* （聚合 Bundle，不是单条告警）
    await js.subscribe("alerts.bundle.*", cb=on_message, queue="ai-agent")
    print("[OK] 已订阅 alerts.bundle.* (JetStream)，等待 Go 端发布 Bundle...")
    print("     (按 Ctrl+C 退出)\n")

    # 6. 保持运行
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n[退出] 共接收 {bundles_received} 个 Bundle ({total_alerts} 条告警)")
        print(f"       风暴 Bundle: {storm_bundles} 个")
        print(f"       按最高严重度: {dict(by_max_severity)}")
        if elapsed > 0:
            print(f"       耗时 {elapsed:.1f}s")
        await nc.drain()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[退出] Bye")
        sys.exit(0)
