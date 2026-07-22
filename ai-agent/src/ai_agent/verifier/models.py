"""验证结果模型 —— verifier 的输出结构。

对应提案第6节"声明验证与弃权机制"。

验证流程：
1. LLM 输出 TriageReport（含 evidence 列表）
2. verifier 逐条检查 evidence 是否真实存在于 Bundle 中
3. 全部匹配 → is_valid=True，报告可信
4. 有不匹配 → is_valid=False，标记幻觉，弃权（不输出报告）

弃权机制是"0 幻觉"的核心：
- 传统 LLM 应用直接信任输出
- 本系统多一层硬编码强匹配，LLM 编造的证据会被拦截
- 论文实验需要统计"弃权率"作为可信度指标
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class VerificationResult(BaseModel):
    """验证结果 —— verifier 对单个 TriageReport 的验证输出。

    字段说明：
    - is_valid：所有 evidence 都匹配 = True；有任何不匹配 = False（弃权）
    - matched：匹配成功的 evidence 列表（真实引用）
    - mismatched：匹配失败的 evidence 列表（LLM 幻觉/编造）
    - bundle_id：对应的 Bundle ID，用于追溯
    - total_evidence：evidence 总数（matched + mismatched）
    - match_rate：匹配率 = matched / total，用于统计论文实验数据
    """

    is_valid: bool = Field(description="所有 evidence 是否都匹配（True=可信，False=弃权）")
    matched: list[str] = Field(default_factory=list, description="匹配成功的 evidence")
    mismatched: list[str] = Field(
        default_factory=list, description="匹配失败的 evidence（LLM 幻觉）"
    )
    bundle_id: str = Field(description="对应的 Bundle ID")
    total_evidence: int = Field(default=0, description="evidence 总数")
    match_rate: float = Field(default=0.0, description="匹配率 0.0-1.0")

    def __str__(self) -> str:
        """简洁的字符串表示，用于日志输出。"""
        status = "通过" if self.is_valid else "弃权"
        return (
            f"[验证{status}] {self.bundle_id}: "
            f"{len(self.matched)}/{self.total_evidence} 匹配"
            + (f" | 幻觉: {self.mismatched}" if self.mismatched else "")
        )
