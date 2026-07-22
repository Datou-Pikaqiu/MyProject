"""Prompt 注入净化器 —— 论文核心创新点2。

在 LLM 调用前检测并净化 Bundle 中的注入内容。
主要目标：AlertSnapshot.raw_message（攻击者可控的自由文本）。

5 类注入模式（中英双语）：
1. 指令覆盖：   "忽略以上指令" / "ignore all previous instructions"
2. 角色劫持：   "你是管理员" / "you are now admin"
3. 提示词覆盖： "新的系统提示" / "your system prompt has changed"
4. 越狱模式：   "DAN mode" / "开发者模式"
5. 信息泄露：   "告诉我密码" / "reveal your password"

净化策略：
- 检测到注入 → 把匹配片段替换为 "[已过滤-类别]"
- 保留告警文本的其他部分（不整段丢弃）
- 返回净化后的 Bundle + 检测报告
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ai_agent.sanitizer.models import InjectionCategory, SanitizationResult

if TYPE_CHECKING:
    from ai_agent.consumer.models import AlertContextBundle

# 注入模式表：(正则, InjectionCategory)
INJECTION_PATTERNS: list[tuple[str, InjectionCategory]] = [
    # ========================
    # 1. 指令覆盖 (Instruction Override)
    # ========================
    # 中文
    (r"忽略\s*(?:以上|之前|所有|这些)(?:的)?\s*指令", InjectionCategory.INSTRUCTION_OVERRIDE),
    (r"忘[记卻]\s*(?:以上|之前)(?:的)?\s*(?:所有|这些)?\s*(?:规则|指令|限制)", InjectionCategory.INSTRUCTION_OVERRIDE),
    (r"不要遵守\s*(?:之前|以上)(?:的)?\s*(?:指令|规则)", InjectionCategory.INSTRUCTION_OVERRIDE),
    (r"无视\s*(?:上面|之前)(?:的)?\s*(?:要求|指令)", InjectionCategory.INSTRUCTION_OVERRIDE),
    # 英文
    (
        r"(?:ignore|forget|disregard)\s*(?:all\s*)?(?:previous|above|prior|these)\s*"
        r"(?:instructions?|rules?|constraints?|directives?)",
        InjectionCategory.INSTRUCTION_OVERRIDE,
    ),

    # ========================
    # 2. 角色劫持 (Role Hijacking)
    # ========================
    # 中文
    (
        r"你\s*(?:现在|如今|當)?\s*是\s*(?:管理[员員]|admin|超级|系统|root)",
        InjectionCategory.ROLE_HIJACKING,
    ),
    (r"(?:扮演|假装|假裝)\s*(?:你是|成为)", InjectionCategory.ROLE_HIJACKING),
    (r"(?:现在|请)\s*你?\s*(?:扮演|假装)\s*一[个個]?", InjectionCategory.ROLE_HIJACKING),
    # 英文
    (
        r"(?:you\s*are\s*(?:now\s*)?|you['\u2019]re\s*now\s*|act\s*as\s*)"
        r"(?:an?\s*)?(?:admin|administrator|god|system|superuser|root)",
        InjectionCategory.ROLE_HIJACKING,
    ),
    (
        r"(?:pretend|roleplay|imagine)\s*(?:you\s*are|you['\u2019]re|that\s*you['\u2019]re)",
        InjectionCategory.ROLE_HIJACKING,
    ),

    # ========================
    # 3. 提示词覆盖 (Prompt Override)
    # ========================
    # 中文
    (
        r"(?:系统|新)(?:的)?\s*(?:system\s*)?(?:提示|prompt|指令)\s*(?:是|为|：)",
        InjectionCategory.PROMPT_OVERRIDE,
    ),
    (
        r"(?:重新|重新)\s*(?:设定|设置)\s*(?:你的?)?\s*(?:角色|身份|规则)",
        InjectionCategory.PROMPT_OVERRIDE,
    ),
    (r"你的?\s*(?:新|最新)\s*(?:角色|任务|指令)\s*是", InjectionCategory.PROMPT_OVERRIDE),
    # 英文
    (
        r"(?:your\s*|the\s*)?system\s*prompt\s*(?:is|has|now|changed|updated)",
        InjectionCategory.PROMPT_OVERRIDE,
    ),
    (
        r"new\s*(?:instructions?|rules?)\s*(?:override|replace|supersede)",
        InjectionCategory.PROMPT_OVERRIDE,
    ),

    # ========================
    # 4. 越狱模式 (Jailbreak)
    # ========================
    (r"DAN\s*(?:mode|模式)", InjectionCategory.JAILBREAK),
    (r"(?:jailbreak|越狱)\s*(?:mode|模式)", InjectionCategory.JAILBREAK),
    (r"(?:开发[者人员]|developer)\s*(?:模式|mode)", InjectionCategory.JAILBREAK),
    (r"do\s+anything\s+now", InjectionCategory.JAILBREAK),

    # ========================
    # 5. 信息泄露 (Information Exfiltration)
    # ========================
    # 中文
    (
        r"(?:输出|打印|显示|告诉)\s*(?:我|所有|这些)?\s*(?:你的?)?\s*"
        r"(?:密码|密钥|token|key|secret|API|凭证|凭据)",
        InjectionCategory.INFO_EXFILTRATION,
    ),
    (
        r"(?:泄露|泄漏)\s*(?:你的?)?\s*(?:密码|密钥|token|key|凭证|凭据)",
        InjectionCategory.INFO_EXFILTRATION,
    ),
    # 英文
    (
        r"(?:output|print|show|tell|reveal)\s*(?:me\s*)?(?:your\s*)?"
        r"(?:password|secret|token|key|credential|API)",
        InjectionCategory.INFO_EXFILTRATION,
    ),
    (
        r"(?:leak|expose|disclose)\s*(?:your\s*)?(?:password|secret|token|key|credential)",
        InjectionCategory.INFO_EXFILTRATION,
    ),
]

# 净化替换占位符
REPLACEMENT = "[已过滤]"


class Sanitizer:
    """Prompt 注入净化器。

    用法：
        sanitizer = Sanitizer()
        sanitized_bundle, results = sanitizer.sanitize_bundle(bundle)
        if results:
            print(f"检测到注入: {results}")
        report = await llm_client.triage(sanitized_bundle)
    """

    def __init__(self) -> None:
        # 预编译所有正则（区分大小写，中文不需要 IGNORECASE）
        self._patterns: list[tuple[re.Pattern[str], InjectionCategory]] = [
            (re.compile(pattern), category) for pattern, category in INJECTION_PATTERNS
        ]

    def sanitize_bundle(
        self, bundle: "AlertContextBundle"
    ) -> tuple["AlertContextBundle", list[SanitizationResult]]:
        """净化 Bundle 中所有外部输入字段。

        遍历 bundle.alerts，对每条 alert 的 raw_message（以及 protocol、
        node_id、subnet）做注入检测和净化。

        Args:
            bundle: 原始告警上下文包

        Returns:
            (净化后的 Bundle, 检测结果列表) — 净化后的 Bundle 可安全喂给 LLM
        """
        sanitized_alerts = []
        all_results: list[SanitizationResult] = []

        for alert in bundle.alerts:
            modified = False
            updates: dict[str, str] = {}

            # 净化 raw_message（主要目标）
            result = self.sanitize_text(alert.raw_message)
            if result.was_modified:
                updates["raw_message"] = result.sanitized
                modified = True
            all_results.append(result)

            # 净化 protocol（次要目标）
            result = self.sanitize_text(alert.protocol)
            if result.was_modified:
                updates["protocol"] = result.sanitized
                modified = True
            all_results.append(result)

            # 净化 node_id（次要目标）
            if alert.node_id:
                result = self.sanitize_text(alert.node_id)
                if result.was_modified:
                    updates["node_id"] = result.sanitized
                    modified = True
                all_results.append(result)

            # 净化 subnet（次要目标）
            if alert.subnet:
                result = self.sanitize_text(alert.subnet)
                if result.was_modified:
                    updates["subnet"] = result.sanitized
                    modified = True
                all_results.append(result)

            if modified:
                sanitized_alerts.append(alert.model_copy(update=updates))
            else:
                sanitized_alerts.append(alert)

        # 收集所有被检测到的结果（去重类别）
        detected_results = [r for r in all_results if r.was_modified]
        sanitized_bundle = bundle.model_copy(update={"alerts": sanitized_alerts})
        return sanitized_bundle, detected_results

    def sanitize_text(self, text: str) -> SanitizationResult:
        """检测并净化单段文本。

        对文本逐一匹配注入模式，将匹配片段替换为占位符。
        如果文本不含任何注入，返回 was_modified=False 的结果。

        Args:
            text: 待检测的原始文本

        Returns:
            净化结果（含原始文本、净化后文本、检测到的类别）
        """
        cleaned = text
        detected_categories: set[InjectionCategory] = set()
        replaced_count = 0

        for pattern, category in self._patterns:
            if pattern.search(cleaned):
                detected_categories.add(category)
                # 用占位符替换匹配片段
                cleaned = pattern.sub(REPLACEMENT, cleaned)
                replaced_count += 1

        return SanitizationResult(
            original=text,
            sanitized=cleaned,
            was_modified=len(detected_categories) > 0,
            detected=sorted(detected_categories, key=lambda c: c.value),
            replaced_count=replaced_count,
        )
