"""AI Agent - Hello World Subscriber.

Day 1 目标：验证 NATS -> Python 管道打通。
从 NATS 接收 Go 端发来的告警快照，解析并打印。

后续这里会演化成：
  NATS 消费 -> 日志清洗/注入防护 -> RAG 检索 -> LLM 推理 -> 双重验证 -> 工单输出
"""
import asyncio
import json
import sys

# Windows 下 stdout 重定向到文件时默认全缓冲，强制行缓冲让日志实时可见
sys.stdout.reconfigure(line_buffering=True)


async def main() -> None:
    # 延迟导入 nats，让上面的 docstring 在缺依赖时也能看
    import nats

    # 1. 连接 NATS
    nc = await nats.connect("nats://localhost:4222")
    print("[OK] Python subscriber 已连接 NATS")

    received_count = 0

    # 2. 定义收到消息的回调
    async def on_message(msg) -> None:
        nonlocal received_count
        received_count += 1

        # 解析 JSON（Go 端 Marshal 的结构 <-> Python dict）
        data = json.loads(msg.data.decode("utf-8"))

        print(f"\n[收到告警 #{received_count}] subject: {msg.subject}")
        print(f"  AlertID:  {data['alert_id']}")
        print(f"  时间:     {data['timestamp']}")
        print(f"  源->目的: {data['source_ip']} -> {data['dest_ip']}:{data['port']}")
        print(f"  协议:     {data['protocol']}")
        print(f"  严重度:   {data['severity']}")
        print(f"  原始消息: {data['raw_message']}")

    # 3. 订阅 alerts.* （通配符，接收所有严重度的告警）
    # queue="ai-agent" 表示消费组：
    #   后续起多个 AI worker 时，同一条告警只会被一个 worker 消费（负载均衡）
    #   这是"削峰填谷"的关键 —— 提案第 2 节
    await nc.subscribe("alerts.*", cb=on_message, queue="ai-agent")
    print("[OK] 已订阅 alerts.* ，等待 Go 端发布告警...")
    print("     (按 Ctrl+C 退出)")

    # 4. 保持运行，直到被中断
    try:
        await asyncio.Event().wait()
    except (KeyboardInterrupt, asyncio.CancelledError):
        print("\n[退出] 正在关闭 NATS 连接...")
        await nc.drain()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[退出] Bye")
        sys.exit(0)
