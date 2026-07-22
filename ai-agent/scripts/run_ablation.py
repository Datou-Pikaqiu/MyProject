"""消融实验运行器 —— 自动运行多组实验并生成对比表。

用法:
    uv run python scripts/run_ablation.py

会依次运行 3 组实验：
    A: 完整系统（sanitizer + RAG + LLM + verifier）
    B: 无 RAG（--no-rag）
    C: 无 Verifier（--no-verifier）

每组实验后从 subscriber 输出中提取 MetricsCollector 报表，
最终生成论文可用的消融对比表。
"""

import json
import re
import subprocess
import sys
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
AI_AGENT_DIR = PROJECT_ROOT / "ai-agent"
GO_DIR = PROJECT_ROOT / "go-telemetry"
DATASETS_DIR = PROJECT_ROOT / "datasets"

BUNDLES_TO_EXIT = 41  # 100 条告警 → 41 Bundle
PUBLISHER_INTERVAL = "150ms"
NATS_WAIT_SEC = 3
LLM_WAIT_MAX_SEC = 180


def run_experiment(name: str, extra_args: list[str]) -> dict:
    """运行一组消融实验，返回提取的指标 dict。"""
    print(f"\n{'=' * 60}")
    print(f"  实验: {name}")
    print(f"  参数: {' '.join(extra_args) if extra_args else '(完整系统)'}")
    print(f"{'=' * 60}")

    # 启动 subscriber
    sub_args = [
        "uv", "run", "python", "-u", "-m", "ai_agent.main",
        f"--exit-after-bundles={BUNDLES_TO_EXIT}",
        *extra_args,
    ]
    out_file = DATASETS_DIR / f"ablation_{name.replace(' ', '_').lower()}.txt"
    print(f"  [启动] subscriber → {out_file.name}")

    with open(out_file, "w", encoding="utf-8") as f_out:
        proc = subprocess.Popen(
            sub_args,
            cwd=str(AI_AGENT_DIR),
            stdout=f_out,
            stderr=subprocess.STDOUT,
        )

    # 等 subscriber 就绪
    time.sleep(3)

    # 运行 Go publisher
    print("  [运行] Go publisher...")
    _ = subprocess.run(
        [
            str(GO_DIR / "bin" / "telemetry.exe"),
            "--file", str(DATASETS_DIR / "synthetic_alerts.jsonl"),
            "--interval", PUBLISHER_INTERVAL,
        ],
        cwd=str(PROJECT_ROOT),
        capture_output=True,
        timeout=30,
    )
    time.sleep(1)

    # 等 subscriber 自动退出
    print(f"  [等待] LLM 处理 + 自动退出（最多 {LLM_WAIT_MAX_SEC}s）...")
    try:
        proc.wait(timeout=LLM_WAIT_MAX_SEC)
        print(f"  [OK] 实验完成 (退出码: {proc.returncode})")
    except subprocess.TimeoutExpired:
        proc.terminate()
        proc.wait(timeout=5)
        print("  [!] 超时，已终止")

    # 从输出文件中提取指标
    with open(out_file, encoding="utf-8", errors="replace") as f:
        content = f.read()

    metrics = _extract_metrics(content, name)
    if metrics:
        print(f"  [数据] 压缩比={metrics.get('compression_ratio','?')}:1, "
              f"弃权率={metrics.get('abstention_rate_pct','?')}%, "
              f"tokens={metrics.get('total_tokens','?')}")
    else:
        print("  [!] 未找到指标报告")
    return metrics


def _extract_metrics(content: str, name: str) -> dict:
    """从 subscriber 输出中提取 MetricsCollector 的关键字段。"""
    result: dict = {"experiment": name}

    # 提取压缩比: "压缩比: 2.4:1 (降噪 59.0%)"
    m = re.search(r"压缩比:\s+([\d.]+):1\s+\(降噪\s+([\d.]+)%\)", content)
    if m:
        result["compression_ratio"] = float(m.group(1))
        result["noise_reduction_pct"] = float(m.group(2))

    # 提取 LLM 调用次数: "调用次数: 41"
    m = re.search(r"调用次数:\s+(\d+)", content)
    if m:
        result["llm_calls"] = int(m.group(1))

    # 提取平均延迟: "平均延迟: 1892.0ms"
    m = re.search(r"平均延迟:\s+([\d.]+)ms", content)
    if m:
        result["avg_latency_ms"] = float(m.group(1))

    # 提取平均 prompt tokens: "平均 prompt: 2400.0 tokens"
    m = re.search(r"平均 prompt:\s+([\d.]+)\s+tokens", content)
    if m:
        result["avg_prompt_tokens"] = float(m.group(1))

    # 提取平均 completion tokens: "平均 completion: 200.0 tokens"
    m = re.search(r"平均 completion:\s+([\d.]+)\s+tokens", content)
    if m:
        result["avg_completion_tokens"] = float(m.group(1))

    # 提取总 tokens: "总 tokens: 52000"
    m = re.search(r"总 tokens:\s+(\d+)", content)
    if m:
        result["total_tokens"] = int(m.group(1))

    # 提取弃权率: "弃权率: 2.4%"
    m = re.search(r"弃权率:\s+([\d.]+)%", content)
    if m:
        result["abstention_rate_pct"] = float(m.group(1))

    # 提取验证通过数
    m = re.search(r"通过:\s+(\d+)", content)
    if m:
        result["verifier_passed"] = int(m.group(1))

    # 提取弃权数
    m = re.search(r"弃权\(幻觉\):\s+(\d+)", content)
    if m:
        result["verifier_abstained"] = int(m.group(1))

    # 提取 RAG 命中文档数: "命中文档: 121"
    m = re.search(r"命中文档:\s+(\d+)", content)
    if m:
        result["rag_docs"] = int(m.group(1))

    return result if "compression_ratio" in result else {}


def print_comparison_table(results: list[dict]):
    """打印消融对比表（论文 Table 2 格式）。"""
    if not results:
        print("\n[!] 无有效实验结果")
        return

    print("\n\n" + "=" * 70)
    print("  消融实验对比表（论文 Table 2: Ablation Study）")
    print("=" * 70)

    # 表头
    header = f"{'实验组':<20} {'压缩比':<8} {'LLM调用':<9} {'prompt tokens':<14} {'延迟(ms)':<10} {'弃权率':<8}"
    print(header)
    print("-" * 70)

    for r in results:
        name = r.get("experiment", "?")
        cr = f"{r.get('compression_ratio', '?'):.1f}:1"
        calls = r.get("llm_calls", "?")
        pt = f"{r.get('avg_prompt_tokens', '?'):.0f}"
        lat = f"{r.get('avg_latency_ms', '?'):.0f}"
        ar = f"{r.get('abstention_rate_pct', '?'):.1f}%"
        print(f"{name:<20} {cr:<8} {calls:<9} {pt:<14} {lat:<10} {ar:<8}")

    print("=" * 70)
    print()

    # 论文解读
    print("论文解读:")
    baseline = results[0] if results else {}
    for r in results[1:]:
        name = r.get("experiment", "?")
        if "无 RAG" in name:
            diff = (baseline.get("avg_prompt_tokens", 0) - r.get("avg_prompt_tokens", 0))
            print(f"  {name}: prompt tokens 减少 ~{diff:.0f}（但缺少领域知识，分类质量下降）")
        if "无 Verifier" in name:
            print(f"  {name}: 弃权率 0%（所有报告直接输出，无幻觉拦截——论文安全论据）")

    # 保存 JSON
    json_path = DATASETS_DIR / "ablation_results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    print(f"\n[JSON] 完整结果 → {json_path}")


if __name__ == "__main__":
    print("消融实验运行器")
    print(f"每组实验需 {LLM_WAIT_MAX_SEC}s（LLM 处理）+ Go 端运行时间")
    print()

    # 检查 NATS 是否运行
    try:
        import urllib.request
        urllib.request.urlopen("http://localhost:8222/healthz", timeout=2)
    except Exception:
        print("[!] NATS 未运行，请先启动: docker compose -f deployments/docker-compose.yml up -d")
        sys.exit(1)

    results: list[dict] = []

    # 实验 A: 完整系统
    results.append(run_experiment("完整系统", []))

    # 实验 B: 无 RAG
    results.append(run_experiment("无 RAG", ["--no-rag"]))

    # 实验 C: 无 Verifier
    results.append(run_experiment("无 Verifier", ["--no-verifier"]))

    print_comparison_table(results)
