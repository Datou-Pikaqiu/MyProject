"""Prompt 注入防护模块 —— 论文核心创新点2。

净化外部输入（raw_message 等），防止攻击者通过告警文本向 LLM 注入恶意指令。

sanitizer + verifier 构成论文的两层防线：
- sanitizer：LLM 之前，防注入（不让恶意指令进入 LLM）
- verifier：LLM 之后，防幻觉（不让 LLM 编造的证据输出给操作员）
"""
