"""AI Agent - Subscriber（Day 2 版本，JetStream 持久化消费）。

用 JetStream 代替 core NATS 订阅，确保消息不丢：
  - core NATS：fire-and-forget，subscriber 没及时收就丢
  - JetStream：消息持久化到磁盘，subscriber 断线重连后能收到未读消息
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from datetime import datetime

# Windows 下 stdout 重定向到文件时默认全缓冲，强制行缓冲让日志实时可见
sys.stdout.reconfigure(line_buffering=True)

# JetStream stream 名称，必须和 Go 端一致
STREAM_NAME = "ALERTS"


async def main() -> None:
    import nats

    from ai_agent.consumer.models import AlertSnapshot

    # 1. 连接 NATS
    nc = await nats.connect("nats://localhost:4222")
    print("[OK] Python subscriber 已连接 NATS")

    # 2. 创建 JetStream context + 确保 stream 存在
    js = nc.jetstream()
    try:
        await js.stream_info(STREAM_NAME)
        print(f"[OK] JetStream stream 已存在: {STREAM_NAME}")
    except Exception:
        try:
            await js.add_stream(name=STREAM_NAME, subjects=["alerts.*"])
            print(f"[OK] 已创建 JetStream stream: {STREAM_NAME}")
        except Exception:
            # Go 端可能已经创建了，忽略错误
            print(f"[OK] stream {STREAM_NAME} 已被 Go 端创建")

    # 3. 统计计数器
    received = 0
    by_severity: dict[str, int] = defaultdict(int)
    start_time = datetime.now()
    last_stat_time = start_time

    # 4. 消息回调（JetStream 自动 ack：回调完成后自动确认消息）
    async def on_message(msg) -> None:
        nonlocal received, last_stat_time
        received += 1

        try:
            alert = AlertSnapshot.model_validate_json(msg.data)
        except Exception as e:
            print(f"[!] 解析失败 (subject={msg.subject}): {e}")
            return  # 不 ack，消息会被重新投递

        by_severity[alert.severity.value] += 1

        # 详细输出 critical/high，简要输出其他（避免正常流量刷屏）
        sev = alert.severity.value
        if sev in ("critical", "high"):
            msg_short = alert.raw_message[:40] + ("..." if len(alert.raw_message) > 40 else "")
            print(
                f"[#{received:3d}] {alert.alert_id:20s} | {sev:8s} | "
                f"{alert.source_ip} -> {alert.dest_ip} | {msg_short}"
            )

        # 每 10 条打印一次速率统计
        if received % 10 == 0:
            now = datetime.now()
            elapsed = (now - last_stat_time).total_seconds()
            rate = 10 / elapsed if elapsed > 0 else 0
            print(
                f"  --- 已接收 {received:3d} 条 | "
                f"最近 10 条 {rate:.1f} 条/秒 | 分布: {dict(by_severity)}"
            )
            last_stat_time = now

    # 5. 用 JetStream 订阅（持久化消费，消息不丢）
    # queue="ai-agent" 消费组：多 worker 负载均衡
    # manual_ack 默认 False：回调完成后自动 ack
    await js.subscribe("alerts.*", cb=on_message, queue="ai-agent")
    print("[OK] 已订阅 alerts.* (JetStream)，等待告警...")
    print("     (按 Ctrl+C 退出)\n")

    # 6. 保持运行
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        elapsed = (datetime.now() - start_time).total_seconds()
        print(f"\n[退出] 共接收 {received} 条，耗时 {elapsed:.1f}s")
        print(f"       按严重度: {dict(by_severity)}")
        if elapsed > 0:
            print(f"       平均速率: {received / elapsed:.1f} 条/秒")
        await nc.drain()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[退出] Bye")
        sys.exit(0)
