# SCVD Multi-Agent IO Contract

The framework exposes a stable request/response envelope for CLI, API, and downstream agents.

## Input

```json
{
  "target": "contracts-or-project-path",
  "documents": ["docs/whitepaper.md"],
  "scope_files": ["src/Vault.sol"],
  "audit_sources": ["code4rena", "sherlock"],
  "attack_sources": ["defihack"],
  "out_dir": "reports",
  "report_prefix": "scan",
  "output_formats": ["markdown", "json"],
  "options": {
    "max_hotspots": 30,
    "max_knowledge_records": 6,
    "max_attack_poc_records": 4,
    "include_source_context": true,
    "llm": {
      "enabled": false,
      "provider": "openai_compatible",
      "model": "gpt-4o-mini",
      "api_key_env": "OPENAI_API_KEY",
      "base_url": "https://api.openai.com/v1",
      "temperature": 0.0,
      "max_tokens": 1200
    }
  }
}
```

Required field:

- `target`: project or directory containing Solidity/Vyper files.

Optional fields:

- `documents`: extra Markdown/RST/TXT paths included in RAG context.
- `scope_files`: files to prioritize in UI/downstream routing.
- `audit_sources`: audit-report knowledge labels.
- `attack_sources`: historical attack PoC source labels.
- `output_formats`: `markdown`, `json`, or both.

## Output

The JSON report top-level envelope:

```json
{
  "schema_version": "scvd.multiagent.io.v1",
  "input_contract": {},
  "output_contract": {},
  "inputs": {},
  "artifacts": {},
  "summary": {},
  "outputs": {
    "project": {},
    "rag": {},
    "analysis": {},
    "poc": {},
    "patches": {}
  },
  "working_memory": {}
}
```

Stable output groups:

- `project`: profile, source files, documents, call edges, inheritance edges, business flows, business logic units.
- `rag`: retrieved audit knowledge and attack PoC records.
- `analysis`: business constraints, findings, validation results, root causes.
- `poc`: PoC drafts and Foundry sandbox feedback.
- `patches`: patch candidates, dynamic validation results, security patch plans.

`working_memory` is intentionally more verbose and may grow faster than the stable `outputs` groups.
