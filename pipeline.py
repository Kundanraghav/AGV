#!/usr/bin/env python3
"""
MAL Attack Graph Visualizer — Main Pipeline
Usage: python pipeline.py [--input data/] [--output output/] [--batch-size 20] [--skip-agents]
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import parser as session_parser
import visualizer
from agents import runner


def chunk(lst, size):
    """Split list into chunks of at most `size`."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def merge_classifications(entries, corelang_results, mitre_results, raw_results):
    """
    Merge the three agent result lists back into the entries by entry_id.
    Returns enriched entries.
    """
    cl_map = {r["entry_id"]: r for r in corelang_results}
    mi_map = {r["entry_id"]: r for r in mitre_results}
    ra_map = {r["entry_id"]: r for r in raw_results}

    enriched = []
    for e in entries:
        eid = e["entry_id"]
        enriched_entry = dict(e)
        enriched_entry["corelang"] = cl_map.get(eid, {
            "entry_id": eid, "asset": "Unknown", "step": "unknown",
            "full": "Unknown.unknown", "confidence": 0.0, "notes": "missing"
        })
        enriched_entry["mitre"] = mi_map.get(eid, {
            "entry_id": eid, "technique_id": "T0000", "technique_name": "Unknown",
            "tactic": "none", "confidence": 0.0
        })
        enriched_entry["raw"] = ra_map.get(eid, {
            "entry_id": eid, "tool": "", "action": "", "target": "",
            "phase": "noise", "is_noise": True,
            "cleaned_command": e.get("command", "")
        })
        enriched.append(enriched_entry)
    return enriched


def run_agents_parallel(batches):
    """
    Run all 3 agents on all batches. Returns (corelang_list, mitre_list, raw_list).
    Within each batch, the 3 agents run in parallel.
    Batches are processed sequentially.
    """
    all_corelang = []
    all_mitre    = []
    all_raw      = []

    total = len(batches)
    for i, batch in enumerate(batches):
        print(f"  Batch {i+1}/{total} ({len(batch)} entries)...")

        with ThreadPoolExecutor(max_workers=3) as ex:
            f_cl = ex.submit(runner.run_agent, "corelang", batch)
            f_mi = ex.submit(runner.run_agent, "mitre",    batch)
            f_ra = ex.submit(runner.run_agent, "raw",      batch)

        all_corelang.extend(f_cl.result())
        all_mitre.extend(f_mi.result())
        all_raw.extend(f_ra.result())

    return all_corelang, all_mitre, all_raw


def make_dummy_classifications(entries):
    """
    Generate placeholder classifications (for --skip-agents mode / testing).
    Uses simple heuristics so the graph still renders with real structure.
    """
    import re

    TOOL_PHASE = {
        'nmap': ('reconnaissance', 'T1046', 'discovery', 'Network', 'networkScanning'),
        'masscan': ('reconnaissance', 'T1046', 'discovery', 'Network', 'networkScanning'),
        'gobuster': ('reconnaissance', 'T1083', 'discovery', 'Application', 'accessApplication'),
        'dirb': ('reconnaissance', 'T1083', 'discovery', 'Application', 'accessApplication'),
        'ffuf': ('reconnaissance', 'T1083', 'discovery', 'Application', 'accessApplication'),
        'nikto': ('reconnaissance', 'T1190', 'discovery', 'NetworkService', 'networkServiceScanning'),
        'hydra': ('exploitation', 'T1110', 'credential-access', 'Credentials', 'bruteForce'),
        'medusa': ('exploitation', 'T1110', 'credential-access', 'Credentials', 'bruteForce'),
        'john': ('exploitation', 'T1110', 'credential-access', 'Credentials', 'bruteForce'),
        'hashcat': ('exploitation', 'T1110', 'credential-access', 'Credentials', 'bruteForce'),
        'sqlmap': ('exploitation', 'T1190', 'initial-access', 'Application', 'exploitVulnerableApplication'),
        'msfconsole': ('exploitation', 'T1059', 'execution', 'Host', 'exploit'),
        'meterpreter': ('post-exploitation', 'T1059', 'execution', 'Host', 'compromise'),
        'ssh': ('exploitation', 'T1078', 'initial-access', 'Credentials', 'authenticate'),
        'nc': ('exploitation', 'T1059.004', 'execution', 'Host', 'exploit'),
        'python': ('post-exploitation', 'T1059.006', 'execution', 'Host', 'codeExecution'),
        'wget': ('post-exploitation', 'T1105', 'command-and-control', 'Host', 'connect'),
        'curl': ('post-exploitation', 'T1105', 'command-and-control', 'Host', 'connect'),
        'whoami': ('post-exploitation', 'T1033', 'discovery', 'Host', 'compromise'),
        'id': ('post-exploitation', 'T1033', 'discovery', 'Host', 'compromise'),
        'cat': ('post-exploitation', 'T1083', 'discovery', 'Data', 'read'),
        'find': ('post-exploitation', 'T1083', 'discovery', 'Data', 'read'),
        'scp': ('exfiltration', 'T1048', 'exfiltration', 'Data', 'exfiltrate'),
        'rsync': ('exfiltration', 'T1048', 'exfiltration', 'Data', 'exfiltrate'),
    }

    corelang, mitre, raw = [], [], []
    for e in entries:
        eid = e["entry_id"]
        cmd = e.get("command", "").strip()
        first_word = cmd.split()[0].lower().lstrip('./') if cmd.split() else ""

        if not cmd or e.get("is_noise_hint"):
            corelang.append({"entry_id": eid, "asset": "Unknown", "step": "noise", "full": "Unknown.noise", "confidence": 0.0, "notes": "noise"})
            mitre.append({"entry_id": eid, "technique_id": "T0000", "technique_name": "Noise", "tactic": "none", "confidence": 0.0})
            raw.append({"entry_id": eid, "tool": "", "action": "noise", "target": "", "phase": "noise", "is_noise": True, "cleaned_command": cmd})
            continue

        defaults = TOOL_PHASE.get(first_word, ('post-exploitation', 'T1059', 'execution', 'Host', 'compromise'))
        phase, tid, tactic, asset, step = defaults

        corelang.append({"entry_id": eid, "asset": asset, "step": step, "full": f"{asset}.{step}", "confidence": 0.7, "notes": "heuristic"})
        mitre.append({"entry_id": eid, "technique_id": tid, "technique_name": tid, "tactic": tactic, "confidence": 0.7})
        raw.append({"entry_id": eid, "tool": first_word, "action": phase, "target": "", "phase": phase, "is_noise": False, "cleaned_command": cmd})

    return corelang, mitre, raw


def main():
    ap = argparse.ArgumentParser(description="MAL Attack Graph Visualizer")
    ap.add_argument("--input",       default="data",   help="Path to data file or folder (default: data/)")
    ap.add_argument("--output",      default="output", help="Output directory (default: output/)")
    ap.add_argument("--batch-size",  type=int, default=20, help="Entries per agent batch (default: 20)")
    ap.add_argument("--skip-agents", action="store_true", help="Skip Claude agents, use heuristic classification (for testing)")
    ap.add_argument("--from-json",   default=None,     help="Load existing graph_data.json and just re-render HTML")
    args = ap.parse_args()

    # ── Re-render only mode ────────────────────────────────────────────────
    if args.from_json:
        print(f"Loading existing graph from {args.from_json}...")
        with open(args.from_json, encoding="utf-8") as f:
            graph = json.load(f)
        _, html_path = visualizer.write_outputs(graph, args.output)
        print(f"\nDone. Open: {html_path}")
        return

    # ── Parse input ────────────────────────────────────────────────────────
    print(f"\n[1/4] Parsing input: {args.input}")
    entries = session_parser.parse(args.input)

    if not entries:
        print("ERROR: No entries found. Check your input path.")
        sys.exit(1)

    batches = list(chunk(entries, args.batch_size))
    print(f"       {len(entries)} entries -> {len(batches)} batch(es) of up to {args.batch_size}")

    # ── Run agents ─────────────────────────────────────────────────────────
    if args.skip_agents:
        print("\n[2/4] Skipping agents (--skip-agents flag). Using heuristic classification.")
        cl_results, mi_results, ra_results = make_dummy_classifications(entries)
    else:
        print(f"\n[2/4] Running 3 agents in parallel across {len(batches)} batch(es)...")
        cl_results, mi_results, ra_results = run_agents_parallel(batches)

    # ── Merge & build graph ────────────────────────────────────────────────
    print("\n[3/4] Merging classifications and building graph...")
    enriched = merge_classifications(entries, cl_results, mi_results, ra_results)
    graph = visualizer.build_graph(enriched)

    n_cmd  = len(graph["nodes"])
    n_cl   = len(graph["corelang_nodes"])
    n_mi   = len(graph["mitre_nodes"])
    n_edge = len(graph["edges"])
    print(f"       {n_cmd} command nodes, {n_cl} coreLang nodes, {n_mi} MITRE nodes, {n_edge} edges")

    # ── Write outputs ──────────────────────────────────────────────────────
    print(f"\n[4/4] Writing output to {args.output}/")
    json_path, html_path = visualizer.write_outputs(graph, args.output)

    print(f"\nDone. Open in browser:\n  {os.path.abspath(html_path)}\n")


if __name__ == "__main__":
    main()
