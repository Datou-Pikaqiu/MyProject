"""RAG 数据模型 —— 知识文档 + 检索结果。"""

from __future__ import annotations

from pydantic import BaseModel, Field


class KnowledgeDocument(BaseModel):
    """知识库中的一条文档。

    tags 用于关键词匹配检索——Retriever 提取 Bundle 的关键词后，
    和文档的 tags 做交集匹配。tags 越多越容易被检索到。
    """

    id: str = Field(description="文档唯一标识")
    title: str = Field(description="文档标题（注入 prompt 时作为标题行）")
    content: str = Field(description="文档正文（领域知识，注入 SYSTEM_PROMPT）")
    tags: list[str] = Field(description="检索标签（全小写），如 ['modbus', 'protocol', 'plc']")


class RAGContext(BaseModel):
    """一次检索的结果——包含检索到的文档 + 检索诊断信息。"""

    documents: list[KnowledgeDocument] = Field(default_factory=list)
    bundle_keywords: list[str] = Field(
        default_factory=list, description="从 Bundle 提取的关键词（诊断用）"
    )
    document_count: int = Field(default=0, description="检索到的文档数")

    def to_prompt_block(self) -> str:
        """将检索结果转换为可注入 prompt 的文本块。"""
        if not self.documents:
            return ""

        lines = ["## 领域知识参考（RAG）\n"]
        lines.append("以下是与当前告警相关的电网安全领域知识，请在分析时参考：\n")
        for i, doc in enumerate(self.documents, 1):
            lines.append(f"### {doc.title}")
            lines.append(doc.content)
            lines.append("")
        return "\n".join(lines)

    def __str__(self) -> str:
        if not self.documents:
            return f"[RAG] 未检索到相关知识 (关键词: {self.bundle_keywords})"
        titles = [d.title for d in self.documents]
        return f"[RAG] 检索到 {len(self.documents)} 条 ({', '.join(titles)})"
