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
    include_source_context: bool = True
    llm: LLMConfig = field(default_factory=LLMConfig)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "ScanOptions":
        if not data:
            return cls()
        return cls(
            max_hotspots=int(data.get("max_hotspots", 30)),
            max_knowledge_records=int(data.get("max_knowledge_records", 6)),
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
    options: ScanOptions = field(default_factory=ScanOptions)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ScanRequest":
        return cls(
            target=str(data["target"]),
            out_dir=str(data.get("out_dir", "reports")),
            report_prefix=str(data.get("report_prefix", "arithmetic_scan")),
            options=ScanOptions.from_dict(data.get("options")),
        )

    def resolve(self, base_dir: str | Path | None = None) -> "ScanRequest":
        base = Path(base_dir).resolve() if base_dir else Path.cwd()
        target = Path(self.target)
        out_dir = Path(self.out_dir)
        return ScanRequest(
            target=str(target if target.is_absolute() else (base / target).resolve()),
            out_dir=str(out_dir if out_dir.is_absolute() else (base / out_dir).resolve()),
            report_prefix=self.report_prefix,
            options=self.options,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "out_dir": self.out_dir,
            "report_prefix": self.report_prefix,
            "options": self.options.to_dict(),
        }


@dataclass(slots=True)
class ScanArtifacts:
    markdown_report: str
    json_report: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
