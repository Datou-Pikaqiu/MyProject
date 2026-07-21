"""LLM 客户端 —— 调用 DeepSeek API 进行告警分诊。

对应提案第5节"证据接地的 LLM 分诊"。

使用 DeepSeek API（OpenAI 兼容 SDK）：
- 模型：deepseek-chat（.env 可配）
- JSON Mode：response_format={"type": "json_object"}
- 异步调用：AsyncOpenAI（不阻塞 NATS subscriber）

设计原则：
1. 异步——不阻塞 NATS subscriber 的消息处理
2. JSON Mode——强制 LLM 输出合法 JSON，配合 Pydantic 严格校验
3. 低 temperature（0.1）——减少随机性，提高可复现性（论文实验要求）
4. 错误不崩溃——打印错误返回 None，后续 verifier 处理弃权（Sprint 3）
5. 记录 token 使用量——论文实验需要统计成本
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from dotenv import load_dotenv
from openai import AsyncOpenAI

from ai_agent.llm.models import TriageReport
from ai_agent.llm.prompts import SYSTEM_PROMPT, build_user_prompt

if TYPE_CHECKING:
    from ai_agent.consumer.models import AlertContextBundle


class LLMClient:
    """DeepSeek API 异步客户端。

    用法：
        client = LLMClient()
        report = await client.triage(bundle)
        if report:
            print(f"分类: {report.classification}, 置信度: {report.confidence}")
    """

    def __init__(self) -> None:
        # 从 .env 加载环境变量（ai-agent/.env）
        load_dotenv()

        api_key = os.getenv("DEEPSEEK_API_KEY")
        if not api_key or api_key == "sk-YOUR_KEY_HERE":
            raise ValueError(
                "DEEPSEEK_API_KEY 未设置，请在 ai-agent/.env 文件中填入你的 API key"
            )

        base_url = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
        self.model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

        self.client = AsyncOpenAI(api_key=api_key, base_url=base_url)

    async def triage(self, bundle: "AlertContextBundle") -> TriageReport | None:
        """对 AlertContextBundle 进行 LLM 分诊。

        Args:
            bundle: Go 端聚合后发来的告警上下文包

        Returns:
            TriageReport 分诊报告；API 调用失败或 JSON 解析失败时返回 None
        """
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": build_user_prompt(bundle)},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,  # 低温度，减少随机性（论文实验要求可复现）
                max_tokens=1024,  # 分诊报告不需要太长
                timeout=30.0,  # 30 秒超时
            )

            content = response.choices[0].message.content
            if not content:
                print("[LLM] 警告：API 返回空内容")
                return None

            # 记录 token 使用量（论文实验需要统计成本）
            if response.usage:
                print(
                    f"  [LLM] tokens: prompt={response.usage.prompt_tokens}, "
                    f"completion={response.usage.completion_tokens}, "
                    f"total={response.usage.total_tokens}"
                )

            # 用 Pydantic 严格校验 JSON（字段缺失/类型错误会抛 ValidationError）
            report = TriageReport.model_validate_json(content)
            return report

        except Exception as e:
            # Day 4 基础版：打印错误，返回 None
            # Sprint 3 的 verifier 会实现完整的弃权机制
            print(f"[LLM] 错误：{type(e).__name__}: {e}")
            return None
