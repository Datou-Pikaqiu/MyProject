"""实验指标采集模块 —— 论文数据采集。

统一采集管道各阶段的量化指标，支持结构化报表输出（JSON/文本）。
论文需要的关键指标：
- 压缩率（alerts → bundles）
- LLM token 开销（prompt/completion）
- verifier 弃权率
- sanitizer 拦截率
- RAG 知识命中率
- 端到端延迟
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field


@dataclass
class MetricsCollector:
    """管道指标采集器。

    用法：
        m = MetricsCollector()
        m.record_bundle()           # 每收到一个 Bundle
        m.record_llm_call(1500, 200, 3.5)  # prompt_tokens, completion_tokens, latency_s
        m.record_verifier(True)     # True=通过, False=弃权
        ...
        report = m.report()
        print(report.to_markdown())
    """

    # === 管道吞吐 ===
    bundles_received: int = 0
    alerts_total: int = 0
    storm_bundles: int = 0
    start_time: float = 0.0
    end_time: float = 0.0

    # === LLM ===
    llm_calls: int = 0
    total_prompt_tokens: int = 0
    total_completion_tokens: int = 0
    total_llm_latency_ms: float = 0.0

    # === verifier ===
    verifier_passed: int = 0
    verifier_abstained: int = 0

    # === sanitizer ===
    injections_detected: int = 0

    # === RAG ===
    rag_retrievals: int = 0
    rag_docs_retrieved: int = 0

    # === 分类分布 ===
    severity_counts: dict[str, int] = field(default_factory=dict)
    classification_counts: dict[str, int] = field(default_factory=dict)

    def __post_init__(self):
        if self.start_time == 0.0:
            self.start_time = time.monotonic()

    # ---- 记录方法 ----

    def record_bundle(self, alert_count: int, severity: str, is_storm: bool = False):
        self.bundles_received += 1
        self.alerts_total += alert_count
        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1
        if is_storm:
            self.storm_bundles += 1

    def record_llm_call(self, prompt_tokens: int, completion_tokens: int, latency_ms: float):
        self.llm_calls += 1
        self.total_prompt_tokens += prompt_tokens
        self.total_completion_tokens += completion_tokens
        self.total_llm_latency_ms += latency_ms

    def record_verifier(self, passed: bool):
        if passed:
            self.verifier_passed += 1
        else:
            self.verifier_abstained += 1

    def record_injections(self, count: int):
        self.injections_detected += count

    def record_rag(self, docs_found: int):
        self.rag_retrievals += 1
        self.rag_docs_retrieved += docs_found

    def record_classification(self, classification: str):
        self.classification_counts[classification] = (
            self.classification_counts.get(classification, 0) + 1
        )

    def finish(self):
        self.end_time = time.monotonic()

    # ---- 计算指标 ----

    @property
    def compression_ratio(self) -> float:
        """告警→Bundle 压缩比（越高越好，表示聚合越有效）。"""
        return self.alerts_total / self.bundles_received if self.bundles_received > 0 else 0.0

    @property
    def compression_reduction(self) -> float:
        """降噪率：LLM 处理的消息数减少百分比。"""
        if self.alerts_total == 0:
            return 0.0
        return (1 - self.bundles_received / self.alerts_total) * 100

    @property
    def avg_prompt_tokens(self) -> float:
        return self.total_prompt_tokens / self.llm_calls if self.llm_calls > 0 else 0.0

    @property
    def avg_completion_tokens(self) -> float:
        return self.total_completion_tokens / self.llm_calls if self.llm_calls > 0 else 0.0

    @property
    def avg_llm_latency_ms(self) -> float:
        return self.total_llm_latency_ms / self.llm_calls if self.llm_calls > 0 else 0.0

    @property
    def abstention_rate(self) -> float:
        total = self.verifier_passed + self.verifier_abstained
        return self.verifier_abstained / total * 100 if total > 0 else 0.0

    @property
    def rag_hit_rate(self) -> float:
        return self.rag_docs_retrieved / self.rag_retrievals if self.rag_retrievals > 0 else 0.0

    @property
    def runtime_s(self) -> float:
        return self.end_time - self.start_time if self.end_time > 0 else 0.0

    @property
    def throughput_bundles_per_s(self) -> float:
        return self.bundles_received / self.runtime_s if self.runtime_s > 0 else 0.0

    # ---- 报表 ----

    def to_dict(self) -> dict:
        """导出为 Python dict（可用于 JSON 序列化）。"""
        return {
            "pipeline": {
                "alerts_total": self.alerts_total,
                "bundles_received": self.bundles_received,
                "compression_ratio": round(self.compression_ratio, 1),
                "compression_reduction_pct": round(self.compression_reduction, 1),
                "storm_bundles": self.storm_bundles,
                "runtime_s": round(self.runtime_s, 1),
                "throughput_bundles_per_s": round(self.throughput_bundles_per_s, 1),
            },
            "llm": {
                "calls": self.llm_calls,
                "avg_prompt_tokens": round(self.avg_prompt_tokens, 0),
                "avg_completion_tokens": round(self.avg_completion_tokens, 0),
                "total_tokens": self.total_prompt_tokens + self.total_completion_tokens,
                "avg_latency_ms": round(self.avg_llm_latency_ms, 0),
            },
            "verifier": {
                "passed": self.verifier_passed,
                "abstained": self.verifier_abstained,
                "abstention_rate_pct": round(self.abstention_rate, 1),
            },
            "sanitizer": {
                "injections_detected": self.injections_detected,
            },
            "rag": {
                "retrievals": self.rag_retrievals,
                "docs_retrieved": self.rag_docs_retrieved,
                "avg_docs_per_bundle": round(self.rag_hit_rate, 1),
            },
            "classification_distribution": dict(self.classification_counts),
            "severity_distribution": dict(self.severity_counts),
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)

    def to_text(self) -> str:
        """论文友好的文本报表。"""
        d = self.to_dict()
        lines = ["=" * 60, "实验指标报告", "=" * 60, ""]

        # 管道
        p = d["pipeline"]
        lines.append("【管道吞吐】")
        lines.append(f"  原始告警:        {p['alerts_total']}")
        lines.append(f"  聚合 Bundle:      {p['bundles_received']}")
        lines.append(f"  压缩比:          {p['compression_ratio']}:1 (降噪 {p['compression_reduction_pct']}%)")
        lines.append(f"  风暴 Bundle:      {p['storm_bundles']}")
        lines.append(f"  总耗时:          {p['runtime_s']}s")
        lines.append(f"  吞吐量:          {p['throughput_bundles_per_s']} Bundle/s")
        lines.append("")

        # LLM
        llm = d["llm"]
        lines.append("【LLM 分诊】")
        lines.append(f"  调用次数:        {llm['calls']}")
        lines.append(f"  平均 prompt:     {llm['avg_prompt_tokens']} tokens")
        lines.append(f"  平均 completion: {llm['avg_completion_tokens']} tokens")
        lines.append(f"  总 tokens:       {llm['total_tokens']}")
        lines.append(f"  平均延迟:        {llm['avg_latency_ms']}ms")
        lines.append("")

        # verifier
        v = d["verifier"]
        lines.append("【Verifier 验证】")
        lines.append(f"  通过:            {v['passed']}")
        lines.append(f"  弃权(幻觉):      {v['abstained']}")
        lines.append(f"  弃权率:          {v['abstention_rate_pct']}%")
        lines.append("")

        # sanitizer
        s = d["sanitizer"]
        lines.append("【Sanitizer 注入防护】")
        lines.append(f"  检测到注入:      {s['injections_detected']}")
        lines.append("")

        # RAG
        r = d["rag"]
        lines.append("【RAG 知识检索】")
        lines.append(f"  检索次数:        {r['retrievals']}")
        lines.append(f"  命中文档:        {r['docs_retrieved']}")
        lines.append(f"  平均每 Bundle:   {r['avg_docs_per_bundle']} 条")
        lines.append("")

        # 分布
        lines.append("【分诊分类分布】")
        for cls, count in sorted(d["classification_distribution"].items()):
            lines.append(f"  {cls}: {count}")
        lines.append("")
        lines.append("【严重度分布】")
        for sev, count in sorted(d["severity_distribution"].items()):
            lines.append(f"  {sev}: {count}")
        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
