# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Attack Graph Visualizer** — Parses cybersecurity attack session logs and visualizes them as interactive, multi-layer attack graphs. Commands are classified by three agents: raw parsing, MITRE ATT&CK, and an **actions/effects** model. Output is deployed to Vercel as a static site.

## Running the Pipeline

```bash
# Full pipeline: parse → AI classification → visualize → public/
python pipeline.py --input data/ --output public/

# Skip AI agents (heuristics only; good for testing)
python pipeline.py --skip-agents

# Re-render existing graph data without re-running agents
python pipeline.py --from-json public/graph_data.json

# Custom batch size for agent calls
python pipeline.py --batch-size 10
```

Default output directory is `public/` (Vercel's static output dir).

**Runtime requirements:**
- Python 3.x (no external packages — stdlib only)
- `claude` CLI must be in PATH with valid API access (used for AI classification)
- D3.js loaded from CDN at visualization time

## Vercel Deployment

Vercel is configured via `vercel.json` to serve `public/` as static output with no build step. Workflow:
1. Run `python pipeline.py` locally to regenerate `public/index.html` + `public/graph_data.json`
2. Commit and push — Vercel auto-deploys from git

## Architecture

```
parser.py → agents/ → visualizer.py (build) → visualizer.py (render) → public/
```

1. **`parser.py`** — Converts raw logs to normalized entries. Supports:
   - JSON: array of `{command, reasoning, output, exit_code, agent}` objects
   - TXT: shell session logs; detects commands by prompt patterns and 60+ tool heuristics
   - Assigns `entry_id` sequentially across all source files

2. **`agents/`** — Runs three Claude CLI agents in parallel (`ThreadPoolExecutor`):
   - **`actions_effects` agent**: Maps each command to a named action (`scanAllPorts`, `bruteForceSSH`, …), the effects it produces (`openPortsKnown`), and the effects it requires
   - **`mitre` agent**: Maps commands to ATT&CK techniques/tactics
   - **`raw` agent**: Extracts `{tool, action, target, phase}` and flags noise
   - `runner.py` calls `claude -p <batch_json> --system-prompt <prompt>`, extracts JSON from output, falls back to null values on error

3. **`visualizer.py`** — Builds a three-layer graph and renders self-contained HTML:
   - **Command layer**: one node per log entry
   - **Actions & Effects layer**: action nodes (circles, colored by phase) + effect nodes (diamonds, purple); edges: `produces` (green dashed) and `enables` (blue solid)
   - **MITRE layer**: technique nodes aggregated across commands
   - Output is a standalone `public/index.html` with D3.js force-directed graph; no server needed

## Actions & Effects Model

The core classification concept (replaces coreLang/MAL):
- **Action** — a deliberate step an attacker consciously chooses (`| action` in MAL simulator terms). Multiple log entries doing the same conceptual thing share one action node.
- **Effect** — an automatic consequence that becomes true after an action succeeds (`& effect`). Effects connect actions causally: `scanAllPorts` → produces `openPortsKnown` → enables `bruteForceCredentials`.

## Key Data Structures

**Enriched entry** (merged output before graph build):
```json
{
  "entry_id": 0,
  "command": "nmap -Pn -T4 -p- 10.10.10.5",
  "actions_effects": {
    "action_name": "scanAllPorts",
    "action_description": "Scan all TCP ports on target",
    "phase": "reconnaissance",
    "produces_effects": ["openPortsKnown"],
    "requires_effects": [],
    "is_noise": false
  },
  "mitre": {"technique_id": "T1046", "tactic": "discovery", ...},
  "raw": {"tool": "nmap", "phase": "reconnaissance", "is_noise": false, ...}
}
```

**`public/graph_data.json`** — intermediate artifact:
```json
{
  "nodes": [...],                  // command nodes
  "actions_effects_nodes": [...],  // action + effect nodes (node_type: "action"|"effect")
  "mitre_nodes": [...],
  "edges": [...],                  // type: sequence|produces|enables|maps_to
  "color_maps": {...}
}
```

## Agent Prompts

All three system prompts live in `agents/prompts.py`. Each returns a JSON array keyed by `entry_id` with exactly as many items as the input batch. The runner validates array length and re-assigns `entry_id` values to prevent hallucination.
