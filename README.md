# Attack Graph Visualizer

A research tool for automated construction of causal attack graphs from empirical adversarial session logs. Built at MIT CSAIL, Cyber Attack Modelling group.

---

## What It Does

Takes raw cybersecurity attack logs (CTF writeups, pentest sessions) and produces an interactive, multi-layer attack graph that shows:

- **What** each command was doing (MITRE ATT&CK technique)
- **Why** it was done (causal action in the attack chain)
- **How** each step enabled the next (effects as preconditions/postconditions)

Three Claude-powered AI agents classify each command in parallel. The result is rendered as a D3.js force-directed graph and deployed as a static site.

---

## Research Context

This tool operationalizes a MAL-style (Meta Attack Language) model of attacker behaviour:

- **Actions** (`|` in MAL) — deliberate attacker choices, e.g. `scanNetwork`, `exploitSQLInjection`. Multiple log entries doing the same conceptual thing collapse into one node.
- **Effects** (`&` in MAL) — automatic postconditions, e.g. `openPortsKnown`, `shellAccessGained`. Effects are the causal links between actions.

**Dataset:** 10 EN2720 CTF attack scenarios — 55 commands, 41 unique actions, 49 unique effects, spanning 6 attack phases. The full formal model (actions, effects, chains, cross-scenario dependencies) is documented in [`MAL_MODEL.md`](MAL_MODEL.md).

---

## Architecture

```
data/*.json
    │
    ▼
parser.py          — normalize logs → entry list (entry_id, command, reasoning, output)
    │
    ▼ (parallel, 3 agents per batch)
agents/
  ├── actions_effects  — action name, phase, produces_effects, requires_effects
  ├── mitre            — ATT&CK technique ID + tactic
  └── raw              — tool, target, cleaned command, noise flag
    │
    ▼
visualizer.py      — build_graph() → 3-layer node/edge structure
    │
    ▼
public/
  ├── graph_data.json  — serialized graph (reproducible artefact)
  └── index.html       — self-contained D3.js visualization
```

---

## Running the Pipeline

**Requirements:** Python 3.x (stdlib only), `claude` CLI in PATH with valid API access, internet for D3.js CDN.

```bash
# Full run: parse → classify → build → render
python pipeline.py --input data/ --output public/

# Skip AI agents (heuristic classification — no API calls)
python pipeline.py --skip-agents

# Re-render HTML from existing graph data
python pipeline.py --from-json public/graph_data.json

# Smaller batches if hitting agent timeouts
python pipeline.py --batch-size 10
```

Output: `public/index.html` (open in browser) + `public/graph_data.json` (reproducible artefact).

---

## Graph Layers

The visualization has three independently togglable layers:

| Layer | Nodes | Edges |
|---|---|---|
| Command | One per log entry, colored by attack phase | `sequence` (time order) |
| Actions & Effects | Action nodes (circles) + Effect nodes (diamonds, purple) | `produces` (green dashed), `enables` (blue solid) |
| MITRE ATT&CK | One per unique technique ID | `maps_to` (cross-layer) |

---

## Dataset

10 attack scenarios in `data/`, each as a JSON array of `{command, reasoning, output, exit_code, agent}`:

| File | Scenario | Key techniques |
|---|---|---|
| `flag14ce18.json` | Network Traffic Capture | tcpdump, pcap analysis |
| `flag3b2000.json` | Web Server File Enumeration | sqlmap OS shell, filesystem traversal |
| `flag521bce.json` | Web Application Source Inspection | account creation, page source |
| `flag59ecca.json` | Active Directory Metadata Query | PowerShell AD modules |
| `flag90b353.json` | Tomcat Manager Brute-Force | hydra HTTP-GET, web app auth |
| `flag9f1f16.json` | Cron Job Privilege Escalation | writable cron, passwd modification |
| `flagadcb1f.json` | FTP Credential Brute-Force | hydra FTP, credential reuse |
| `flagcd699a.json` | Tomcat Exploit + File Exfiltration | Metasploit, meterpreter, file download |
| `flagcfcec8.json` | AD ACL Abuse + Domain Admin Escalation | ACL manipulation, RDP lateral movement |
| `flagde3b1c.json` | SQL Injection Database Dump | sqlmap, multi-step DB enumeration |

Cross-scenario dependencies (where one scenario's effects are preconditions for another) are documented in `MAL_MODEL.md`.

---

## Project Structure

```
AGV/
├── pipeline.py          — pipeline orchestrator
├── parser.py            — log parsing (JSON + TXT)
├── visualizer.py        — graph construction + HTML rendering
├── agents/
│   ├── runner.py        — claude CLI subprocess wrapper
│   └── prompts.py       — system prompts for all 3 agents
├── data/                — ground truth CTF scenario logs
├── public/              — Vercel static output
│   ├── index.html
│   └── graph_data.json
├── MAL_MODEL.md         — formal actions/effects model
├── vercel.json          — static site config
└── CLAUDE.md            — AI assistant context
```

---

## Deployment

Vercel serves `public/` as static output with no build step. Push to `main` → auto-deploy.

```bash
python pipeline.py          # regenerate public/
git add public/ && git commit -m "regenerate graph"
git push                    # Vercel picks it up
```

---

## Formal Model Reference

See [`MAL_MODEL.md`](MAL_MODEL.md) for:
- Complete action table (41 actions) with preconditions and postconditions
- Complete effect table (49 effects) with producer and consumer mappings
- Per-scenario attack chains
- Cross-scenario dependency graph
- Command-to-action mapping examples
