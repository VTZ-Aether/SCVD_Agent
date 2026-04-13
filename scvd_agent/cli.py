from __future__ import annotations

import argparse
import json
from pathlib import Path

from .orchestrator import ArithmeticAuditAgent
from .reporting import write_json_report, write_markdown_report
from .schemas import LLMConfig, ScanOptions, ScanRequest


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
            options=ScanOptions(
                max_hotspots=args.max_hotspots,
                max_knowledge_records=args.max_knowledge_records,
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
    memory = agent.run(target)

    markdown_path = out_dir / f"{request.report_prefix}.md"
    json_path = out_dir / f"{request.report_prefix}.json"
    write_markdown_report(memory, markdown_path)
    write_json_report(memory, json_path)

    print(f"Wrote Markdown report to {markdown_path}")
    print(f"Wrote JSON report to {json_path}")
    print(f"Generated {len(memory.findings)} findings from {len(memory.hotspots)} hotspots.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
