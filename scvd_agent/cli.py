from __future__ import annotations

import argparse
import json
from pathlib import Path

from .io_contracts import build_io_envelope
from .orchestrator import ArithmeticAuditAgent
from .reporting import write_json_report, write_markdown_report
from .schemas import LLMConfig, ScanArtifacts, ScanOptions, ScanRequest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Agentic detector for smart contract vulnerabilities using RAG and business-flow reasoning."
    )
    parser.add_argument("target", nargs="?", help="Path to the contract project or contract file directory.")
    parser.add_argument(
        "--request",
        help="Optional JSON request file. If provided, it supplies target/out_dir/options.",
    )
    parser.add_argument(
        "--out-dir",
        default="reports",
        help="Output directory for Markdown and JSON reports.",
    )
    parser.add_argument(
        "--prefix",
        default="arithmetic_scan",
        help="Report file prefix.",
    )
    parser.add_argument(
        "--formats",
        default="markdown,json",
        help="Comma-separated output formats. Supported: markdown,json.",
    )
    parser.add_argument(
        "--documents",
        default="",
        help="Comma-separated extra Markdown/RST/TXT documentation paths to include.",
    )
    parser.add_argument(
        "--scope-files",
        default="",
        help="Comma-separated contract files to prioritize in the scan request.",
    )
    parser.add_argument(
        "--audit-sources",
        default="code4rena,sherlock",
        help="Comma-separated audit-report RAG source labels.",
    )
    parser.add_argument(
        "--attack-sources",
        default="defihack",
        help="Comma-separated historical attack PoC source labels.",
    )
    parser.add_argument(
        "--max-hotspots",
        type=int,
        default=30,
        help="Maximum number of arithmetic hotspots passed to later agents.",
    )
    parser.add_argument(
        "--max-knowledge-records",
        type=int,
        default=6,
        help="Maximum number of retrieved audit knowledge records used for business reasoning.",
    )
    parser.add_argument(
        "--max-attack-poc-records",
        type=int,
        default=4,
        help="Maximum number of retrieved historical attack PoC records used for root-cause and PoC planning.",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable optional LLM review/refinement layer.",
    )
    parser.add_argument(
        "--llm-model",
        default="gpt-4o-mini",
        help="Model name for the OpenAI-compatible chat API.",
    )
    parser.add_argument(
        "--llm-api-key-env",
        default="OPENAI_API_KEY",
        help="Environment variable containing the API key.",
    )
    parser.add_argument(
        "--llm-base-url",
        default="https://api.openai.com/v1",
        help="OpenAI-compatible base URL.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.request:
        request_path = Path(args.request).resolve()
        request_data = json.loads(request_path.read_text(encoding="utf-8"))
        request = ScanRequest.from_dict(request_data).resolve(request_path.parent)
    else:
        if not args.target:
            parser.error("target is required unless --request is provided")
        request = ScanRequest(
            target=args.target,
            out_dir=args.out_dir,
            report_prefix=args.prefix,
            output_formats=_parse_output_formats(args.formats),
            documents=_parse_csv(args.documents),
            scope_files=_parse_csv(args.scope_files),
            audit_sources=_parse_csv(args.audit_sources) or ["code4rena", "sherlock"],
            attack_sources=_parse_csv(args.attack_sources) or ["defihack"],
            options=ScanOptions(
                max_hotspots=args.max_hotspots,
                max_knowledge_records=args.max_knowledge_records,
                max_attack_poc_records=args.max_attack_poc_records,
                llm=LLMConfig(
                    enabled=args.llm,
                    model=args.llm_model,
                    api_key_env=args.llm_api_key_env,
                    base_url=args.llm_base_url,
                ),
            ),
        ).resolve()

    target = Path(request.target).resolve()
    out_dir = Path(request.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    agent = ArithmeticAuditAgent(options=request.options)
    memory = agent.run(
        target,
        document_paths=request.documents,
        scope_files=request.scope_files,
    )

    markdown_path = out_dir / f"{request.report_prefix}.md" if "markdown" in request.output_formats else None
    json_path = out_dir / f"{request.report_prefix}.json" if "json" in request.output_formats else None
    artifacts = ScanArtifacts(
        markdown_report=str(markdown_path) if markdown_path is not None else None,
        json_report=str(json_path) if json_path is not None else None,
    )
    envelope = build_io_envelope(request=request, artifacts=artifacts, memory=memory)
    envelope_dict = envelope.to_dict()

    if markdown_path is not None:
        write_markdown_report(memory, markdown_path)
        print(f"Wrote Markdown report to {markdown_path}")
    if json_path is not None:
        write_json_report(memory, json_path, envelope=envelope_dict)
        print(f"Wrote JSON report to {json_path}")

    print(f"Generated {len(memory.findings)} findings from {len(memory.hotspots)} hotspots.")
    return 0


def _parse_output_formats(value: str) -> list[str]:
    formats = [item.strip().lower() for item in value.split(",") if item.strip()]
    supported = {"markdown", "json"}
    unknown = sorted(set(formats) - supported)
    if unknown:
        raise argparse.ArgumentTypeError(f"unsupported output format(s): {', '.join(unknown)}")
    return formats or ["markdown", "json"]


def _parse_csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


if __name__ == "__main__":
    raise SystemExit(main())
