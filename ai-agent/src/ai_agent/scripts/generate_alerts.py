"""合成告警数据生成器。

生成 JSONL 格式的模拟告警，用于在 SWaT 数据集申请期间跑通 pipeline。

用法：
    uv run python -m ai_agent.scripts.generate_alerts
    uv run python -m ai_agent.scripts.generate_alerts --count 200 --output ../../datasets/alerts.jsonl

生成三类数据（按 count 比例分配）：
    - 60% 正常流量（low）
    - 30% 攻击流量（medium / high / critical，5 种 ICS 典型攻击）
    - 10% 告警风暴（2 秒内爆发 10 条 critical，测试抗压）

每行一个 AlertSnapshot JSON，Go 端按行读取持续发送。
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

from ai_agent.consumer.models import AlertSnapshot, DeviceRole, Severity

# ===== 电网设备资产清单 =====
# 模拟一个小型变电站网络：2 个 PLC + 1 个 HMI + 1 个 SCADA + 1 个工程师站
DEVICES = [
    {
        "ip": "192.168.1.50",
        "role": DeviceRole.PLC,
        "node_id": "PLC-001",
        "subnet": "192.168.1.0/24",
    },
    {
        "ip": "192.168.1.51",
        "role": DeviceRole.PLC,
        "node_id": "PLC-002",
        "subnet": "192.168.1.0/24",
    },
    {
        "ip": "192.168.1.100",
        "role": DeviceRole.HMI,
        "node_id": "HMI-001",
        "subnet": "192.168.1.0/24",
    },
    {
        "ip": "192.168.2.10",
        "role": DeviceRole.SCADA,
        "node_id": "SCADA-001",
        "subnet": "192.168.2.0/24",
    },
    {
        "ip": "192.168.3.5",
        "role": DeviceRole.ENGINEERING_WORKSTATION,
        "node_id": "EWS-001",
        "subnet": "192.168.3.0/24",
    },
]

# 外部攻击源 IP（模拟从不可信网络发起的攻击）
ATTACKER_IPS = ["10.0.0.66", "10.0.0.99", "172.16.5.100", "203.0.113.50"]

# Modbus 默认端口
MODBUS_PORT = 502


# ===== 攻击模板 =====
# 每种模板对应一种典型 ICS 攻击，字段值反映该攻击的特征
ATTACK_TEMPLATES = [
    {
        "name": "unauthorized_modbus_write",
        "severity": Severity.HIGH,
        "protocol": "Modbus",
        "port": MODBUS_PORT,
        "raw_message": "未授权 Modbus 写入：尝试修改 PLC 保持寄存器 HR=40001",
        "abnormal_payload_len": 256,
        "packet_rate": 150.0,
        "failed_connections_5m": 3,
    },
    {
        "name": "port_scan",
        "severity": Severity.MEDIUM,
        "protocol": "TCP",
        "port": 0,  # 多端口扫描
        "raw_message": "检测到端口扫描：顺序探测子网端口 1-1024",
        "abnormal_payload_len": 0,
        "packet_rate": 500.0,
        "failed_connections_5m": 50,
    },
    {
        "name": "abnormal_payload",
        "severity": Severity.HIGH,
        "protocol": "Modbus",
        "port": MODBUS_PORT,
        "raw_message": "Modbus 异常载荷：载荷长度超出协议规范，疑似恶意指令注入",
        "abnormal_payload_len": 1024,
        "packet_rate": 80.0,
        "failed_connections_5m": 1,
    },
    {
        "name": "replay_attack",
        "severity": Severity.CRITICAL,
        "protocol": "Modbus",
        "port": MODBUS_PORT,
        "raw_message": "重放攻击检测：捕获到时序异常的合法命令序列，疑似重放",
        "abnormal_payload_len": 64,
        "packet_rate": 30.0,
        "failed_connections_5m": 0,
    },
    {
        "name": "dos_flood",
        "severity": Severity.CRITICAL,
        "protocol": "TCP",
        "port": MODBUS_PORT,
        "raw_message": "DoS 洪水攻击：PLC 收到每秒 5000+ 连接请求，响应延迟激增",
        "abnormal_payload_len": 0,
        "packet_rate": 5000.0,
        "failed_connections_5m": 200,
    },
]


def _pick_device() -> dict:
    return random.choice(DEVICES)


def _pick_attacker() -> str:
    return random.choice(ATTACKER_IPS)


def _make_alert(
    alert_id: str,
    timestamp: datetime,
    source_ip: str,
    dest_ip: str,
    source_role: DeviceRole,
    dest_role: DeviceRole,
    severity: Severity,
    protocol: str,
    port: int,
    raw_message: str,
    failed_connections_5m: int = 0,
    abnormal_payload_len: int = 0,
    packet_rate: float = 0.0,
    node_id: str = "",
    subnet: str = "",
) -> AlertSnapshot:
    """构造一个 AlertSnapshot。参数多但语义清晰，避免 random 散落在各处。"""
    return AlertSnapshot(
        alert_id=alert_id,
        timestamp=timestamp,
        source_ip=source_ip,
        dest_ip=dest_ip,
        port=port,
        protocol=protocol,
        severity=severity,
        raw_message=raw_message,
        failed_connections_5m=failed_connections_5m,
        abnormal_payload_len=abnormal_payload_len,
        packet_rate=packet_rate,
        source_role=source_role,
        dest_role=dest_role,
        node_id=node_id,
        subnet=subnet,
    )


def gen_normal(idx: int, ts: datetime) -> AlertSnapshot:
    """生成一条正常流量告警（low severity）。"""
    src = _pick_device()
    dst = _pick_device()
    while dst["ip"] == src["ip"]:
        dst = _pick_device()
    return _make_alert(
        alert_id=f"alert-normal-{idx:04d}",
        timestamp=ts,
        source_ip=src["ip"],
        dest_ip=dst["ip"],
        source_role=src["role"],
        dest_role=dst["role"],
        severity=Severity.LOW,
        protocol="Modbus",
        port=MODBUS_PORT,
        raw_message="常规 Modbus 读取操作：HMI 轮询 PLC 寄存器状态",
        packet_rate=random.uniform(5.0, 20.0),
        node_id=dst["node_id"],
        subnet=dst["subnet"],
    )


def gen_attack(idx: int, ts: datetime) -> AlertSnapshot:
    """生成一条攻击告警（从模板随机选一种）。"""
    tpl = random.choice(ATTACK_TEMPLATES)
    target = _pick_device()  # 攻击目标都是内部设备
    attacker = _pick_attacker()
    return _make_alert(
        alert_id=f"alert-attack-{idx:04d}",
        timestamp=ts,
        source_ip=attacker,
        dest_ip=target["ip"],
        source_role=DeviceRole.UNKNOWN,  # 外部攻击者角色未知
        dest_role=target["role"],
        severity=tpl["severity"],
        protocol=tpl["protocol"],
        port=tpl["port"] if tpl["port"] else random.randint(20, 1024),
        raw_message=tpl["raw_message"],
        failed_connections_5m=tpl["failed_connections_5m"],
        abnormal_payload_len=tpl["abnormal_payload_len"],
        packet_rate=tpl["packet_rate"],
        node_id=target["node_id"],
        subnet=target["subnet"],
    )


def gen_storm(idx: int, ts: datetime) -> AlertSnapshot:
    """生成一条告警风暴中的 critical 告警。"""
    # 风暴场景：DoS 攻击引发级联告警，多个设备同时告警
    target = _pick_device()
    attacker = _pick_attacker()
    return _make_alert(
        alert_id=f"alert-storm-{idx:04d}",
        timestamp=ts,
        source_ip=attacker,
        dest_ip=target["ip"],
        source_role=DeviceRole.UNKNOWN,
        dest_role=target["role"],
        severity=Severity.CRITICAL,
        protocol="Modbus",
        port=MODBUS_PORT,
        raw_message="告警风暴：DoS 引发级联故障，PLC 响应超时，上下游设备连锁告警",
        failed_connections_5m=random.randint(100, 500),
        packet_rate=random.uniform(2000.0, 8000.0),
        node_id=target["node_id"],
        subnet=target["subnet"],
    )


def generate(count: int = 100, seed: int = 42) -> list[AlertSnapshot]:
    """生成 count 条告警：60% 正常 + 30% 攻击 + 10% 风暴。"""
    random.seed(seed)
    n_normal = int(count * 0.6)
    n_attack = int(count * 0.3)
    n_storm = count - n_normal - n_attack  # 剩余给风暴

    alerts: list[AlertSnapshot] = []
    # 用 astimezone() 让 datetime 带本地时区（+08:00）
    # Go 的 time.Time 要求 RFC 3339 格式（必须带时区），naive datetime 会被 Go 拒绝
    base_ts = datetime.now().astimezone()
    ts = base_ts

    # 1. 正常流量：每条间隔 3-8 秒
    for i in range(n_normal):
        alerts.append(gen_normal(i + 1, ts))
        ts += timedelta(seconds=random.uniform(3, 8))

    # 2. 攻击流量：每条间隔 5-15 秒
    for i in range(n_attack):
        alerts.append(gen_attack(i + 1, ts))
        ts += timedelta(seconds=random.uniform(5, 15))

    # 3. 告警风暴：10 条在 2 秒内爆发（每条间隔 0.1-0.3 秒）
    for i in range(n_storm):
        alerts.append(gen_storm(i + 1, ts))
        ts += timedelta(seconds=random.uniform(0.1, 0.3))

    # 按时间戳排序，让 Go 端按时间顺序回放
    alerts.sort(key=lambda a: a.timestamp)
    return alerts


def write_jsonl(alerts: list[AlertSnapshot], output: Path) -> None:
    """写到 JSONL 文件（每行一个 JSON）。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        for a in alerts:
            f.write(a.model_dump_json() + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="生成合成告警数据（JSONL）")
    parser.add_argument("--output", default="../datasets/synthetic_alerts.jsonl",
                        help="输出文件路径（默认 ../datasets/synthetic_alerts.jsonl，相对于 ai-agent/）")
    parser.add_argument("--count", type=int, default=100, help="总告警数（默认 100）")
    parser.add_argument("--seed", type=int, default=42, help="随机种子（默认 42，可复现）")
    args = parser.parse_args()

    alerts = generate(count=args.count, seed=args.seed)
    output = Path(args.output)
    write_jsonl(alerts, output)

    # 统计
    by_severity = {}
    for a in alerts:
        by_severity[a.severity.value] = by_severity.get(a.severity.value, 0) + 1

    print(f"[OK] 生成 {len(alerts)} 条告警 -> {output}")
    print(f"     按严重度: {by_severity}")
    print(f"     时间跨度: {alerts[0].timestamp.strftime('%H:%M:%S')} -> "
          f"{alerts[-1].timestamp.strftime('%H:%M:%S')}")

    # 检测风暴（2 秒内超过 5 条）
    storm_count = sum(
        1 for a in alerts
        if (a.timestamp - alerts[0].timestamp).total_seconds() > 0
        and a.severity == Severity.CRITICAL
    )
    print(f"     critical 告警: {storm_count} 条（含告警风暴）")


if __name__ == "__main__":
    main()
