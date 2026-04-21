from __future__ import annotations

from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class LLMConfig:
    enabled: bool = False
    provider: str = "openai_compatible"
    model: str = "gpt-4o-mini"
    api_key_env: str = "OPENAI_API_KEY"
    base_url: str = "https://api.openai.com/v1"
    temperature: float = 0.0
    max_tokens: int = 1200

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "LLMConfig":
        if not data:
            return cls()
        return cls(
            enabled=bool(data.get("enabled", False)),
            provider=str(data.get("provider", "openai_compatible")),
            model=str(data.get("model", "gpt-4o-mini")),
            api_key_env=str(data.get("api_key_env", "OPENAI_API_KEY")),
            base_url=str(data.get("base_url", "https://api.openai.com/v1")),
            temperature=float(data.get("temperature", 0.0)),
            max_tokens=int(data.get("max_tokens", 1200)),
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class ScanOptions:
    max_hotspots: int = 30
    max_knowledge_records: int = 6
    max_attack_poc_records: int = 4
    include_source_context: bool = True
    llm: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScanOptions":
        if not data:
            return cls()
        return cls(
            max_hotspots=int(data.get("max_hotspots", 30)),
            max_knowledge_records=int(data.get("max_knowledge_records", 6)),
            max_attack_poc_records=int(data.get("max_attack_poc_records", 4)),
            include_source_context=bool(data.get("include_source_context", True)),
            llm=LLMConfig.from_dict(data.get("llm")),
        )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["llm"] = self.llm.to_dict()
        return data


@dataclass(slots=True)
class ScanRequest:
    target: str
    out_dir: str = "reports"
    report_prefix: str = "arithmetic_scan"
    documents: list[str] = field(default_factory=list)
    scope_files: list[str] = field(default_factory=list)
    audit_sources: list[str] = field(default_factory=lambda: ["code4rena", "sherlock"])
    attack_sources: list[str] = field(default_factory=lambda: ["defihack"])
    output_formats: list[str] = field(default_factory=lambda: ["markdown", "json"])
    options: ScanOptions = field(default_factory=ScanOptions)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanRequest":
        return cls(
            target=str(data["target"]),
            out_dir=str(data.get("out_dir", "reports")),
            report_prefix=str(data.get("report_prefix", "arithmetic_scan")),
            documents=[str(item) for item in data.get("documents", [])],
            scope_files=[str(item) for item in data.get("scope_files", [])],
            audit_sources=[str(item) for item in data.get("audit_sources", ["code4rena", "sherlock"])],
            attack_sources=[str(item) for item in data.get("attack_sources", ["defihack"])],
            output_formats=[str(item) for item in data.get("output_formats", ["markdown", "json"])],
            options=ScanOptions.from_dict(data.get("options")),
        )

    def resolve(self, base_dir: str | Path | None = None) -> "ScanRequest":
        base = Path(base_dir).resolve() if base_dir else Path.cwd()
        target = Path(self.target)
        out_dir = Path(self.out_dir)
        documents = [
            str(path if path.is_absolute() else (base / path).resolve())
            for item in self.documents
            for path in [Path(item)]
        ]
        scope_files = [
            str(path if path.is_absolute() else (base / path).resolve())
            for item in self.scope_files
            for path in [Path(item)]
        ]
        return ScanRequest(
            target=str(target if target.is_absolute() else (base / target).resolve()),
            out_dir=str(out_dir if out_dir.is_absolute() else (base / out_dir).resolve()),
            report_prefix=self.report_prefix,
            documents=documents,
            scope_files=scope_files,
            audit_sources=self.audit_sources,
            attack_sources=self.attack_sources,
            output_formats=self.output_formats,
            options=self.options,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "out_dir": self.out_dir,
            "report_prefix": self.report_prefix,
            "documents": self.documents,
            "scope_files": self.scope_files,
            "audit_sources": self.audit_sources,
            "attack_sources": self.attack_sources,
            "output_formats": self.output_formats,
            "options": self.options.to_dict(),
        }


@dataclass(slots=True)
class ScanArtifacts:
    markdown_report: str | None = None
    json_report: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
