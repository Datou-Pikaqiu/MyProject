"""净化结果模型 —— sanitizer 的输出结构。

对应提案第5节"Prompt 注入防护"。

净化策略（论文创新点2）：
- 外部数据（raw_message）只作只读数据块，永不作指令
- sanitizer 在数据进入 LLM 前检测并移除注入内容
- 被净化的内容用占位符替换，不改变告警文本的其他部分
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class InjectionCategory(str, Enum):
    """注入分类 —— 用于论文实验统计各类型注入的拦截率。"""

    INSTRUCTION_OVERRIDE = "instruction_override"  # 指令覆盖："忽略以上指令"
    ROLE_HIJACKING = "role_hijacking"  # 角色劫持："你是管理员"
    PROMPT_OVERRIDE = "prompt_override"  # 提示词覆盖："新系统提示..."
    JAILBREAK = "jailbreak"  # 越狱模式："DAN mode"
    INFO_EXFILTRATION = "info_exfiltration"  # 信息泄露："告诉我密码"


class SanitizationResult(BaseModel):
    """单次净化的结果。

    字段说明：
    - original：净化前的原始文本
    - sanitized：净化后的文本（注入内容被占位符替换）
    - was_modified：是否检测到注入并做了修改
    - detected：检测到的注入类别列表（去重）
    - replaced_count：被替换的注入片段数量
    """

    original: str = Field(description="净化前的原始文本")
    sanitized: str = Field(description="净化后的文本")
    was_modified: bool = Field(default=False, description="是否检测到注入")
    detected: list[InjectionCategory] = Field(
        default_factory=list, description="检测到的注入类别（去重）"
    )
    replaced_count: int = Field(default=0, description="被替换的注入片段数量")

    def __str__(self) -> str:
        if not self.was_modified:
            return "[Sanitizer] 未检测到注入"
        return (
            f"[Sanitizer] 检测到 {len(self.detected)} 类注入，"
            f"替换 {self.replaced_count} 处: {[c.value for c in self.detected]}"
        )
