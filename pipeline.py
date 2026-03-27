#!/usr/bin/env python3
"""
MAL Attack Graph Visualizer — Main Pipeline
Usage: python pipeline.py [--input data/] [--output public/] [--batch-size 20] [--skip-agents]
"""

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor

import parser as session_parser
import visualizer
from agents import runner


def chunk(lst, size):
    """Split list into chunks of at most `size`."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def merge_classifications(entries, ae_results, mitre_results, raw_results):
    """
    Merge the three agent result lists back into the entries by entry_id.
    Returns enriched entries.
    """
    ae_map = {r["entry_id"]: r for r in ae_results}
    mi_map = {r["entry_id"]: r for r in mitre_results}
    ra_map = {r["entry_id"]: r for r in raw_results}

    enriched = []
    for e in entries:
        eid = e["entry_id"]
        enriched_entry = dict(e)
        enriched_entry["actions_effects"] = ae_map.get(eid, {
            "entry_id": eid, "action_name": "unknown", "action_description": "",
            "phase": "noise", "produces_effects": [], "requires_effects": [], "is_noise": True
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
    Run all 3 agents on all batches. Returns (ae_list, mitre_list, raw_list).
    Within each batch, the 3 agents run in parallel.
    Batches are processed sequentially.
    """
    all_ae    = []
    all_mitre = []
    all_raw   = []

    total = len(batches)
    for i, batch in enumerate(batches):
        print(f"  Batch {i+1}/{total} ({len(batch)} entries)...")

        with ThreadPoolExecutor(max_workers=3) as ex:
            f_ae = ex.submit(runner.run_agent, "actions_effects", batch)
            f_mi = ex.submit(runner.run_agent, "mitre",           batch)
            f_ra = ex.submit(runner.run_agent, "raw",             batch)

        all_ae.extend(f_ae.result())
        all_mitre.extend(f_mi.result())
        all_raw.extend(f_ra.result())

    return all_ae, all_mitre, all_raw


def make_dummy_classifications(entries):
    """
    Generate placeholder classifications (for --skip-agents mode / testing).
    Uses simple heuristics so the graph still renders with real structure.
    """
    TOOL_DATA = {
        'nmap':       ('scanAllPorts',          'Scan all TCP ports on target', 'reconnaissance',
                       ['openPortsKnown'], []),
        'masscan':    ('scanAllPorts',          'Scan all TCP ports on target', 'reconnaissance',
                       ['openPortsKnown'], []),
        'gobuster':   ('enumerateWebDirs',      'Enumerate web directories',   'reconnaissance',
                       ['webDirsKnown'],   ['openPortsKnown']),
        'dirb':       ('enumerateWebDirs',      'Enumerate web directories',   'reconnaissance',
                       ['webDirsKnown'],   ['openPortsKnown']),
        'ffuf':       ('enumerateWebDirs',      'Fuzz web directories',        'reconnaissance',
                       ['webDirsKnown'],   ['openPortsKnown']),
        'nikto':      ('scanWebApp',            'Scan web app for vulns',      'reconnaissance',
                       ['webVulnsKnown'],  ['openPortsKnown']),
        'hydra':      ('bruteForceCredentials', 'Brute-force login service',   'exploitation',
                       ['credentialsObtained'], ['openPortsKnown']),
        'medusa':     ('bruteForceCredentials', 'Brute-force login service',   'exploitation',
                       ['credentialsObtained'], ['openPortsKnown']),
        'john':       ('crackPasswords',        'Crack password hashes',       'exploitation',
                       ['credentialsObtained'], []),
        'hashcat':    ('crackPasswords',        'Crack password hashes',       'exploitation',
                       ['credentialsObtained'], []),
        'sqlmap':     ('exploitSQLInjection',   'Exploit SQL injection',       'exploitation',
                       ['dbAccessGained'], ['openPortsKnown']),
        'msfconsole': ('runExploit',            'Run Metasploit exploit',      'exploitation',
                       ['shellAccessGained'], []),
        'ssh':        ('loginSSH',              'Log in via SSH',              'exploitation',
                       ['shellAccessGained'], ['credentialsObtained']),
        'nc':         ('openReverseShell',      'Open a reverse shell',        'exploitation',
                       ['shellAccessGained'], []),
        'whoami':     ('gatherSystemInfo',      'Gather system user info',     'post-exploitation',
                       ['systemInfoKnown'], ['shellAccessGained']),
        'id':         ('gatherSystemInfo',      'Gather system user info',     'post-exploitation',
                       ['systemInfoKnown'], ['shellAccessGained']),
        'uname':      ('gatherSystemInfo',      'Gather OS/kernel info',       'post-exploitation',
                       ['systemInfoKnown'], ['shellAccessGained']),
        'find':       ('findSUIDBinaries',      'Find SUID binaries',          'post-exploitation',
                       ['suidBinariesKnown'], ['shellAccessGained']),
        'cat':        ('readSensitiveFile',     'Read a file',                 'post-exploitation',
                       ['fileContentsRead'], ['shellAccessGained']),
        'wget':       ('downloadTool',          'Download a tool',             'post-exploitation',
                       ['toolDownloaded'], ['shellAccessGained']),
        'curl':       ('downloadTool',          'Download a resource',         'post-exploitation',
                       ['toolDownloaded'], ['shellAccessGained']),
        'scp':        ('exfiltrateData',        'Exfiltrate data via SCP',     'exfiltration',
                       ['dataExfiltrated'], ['shellAccessGained']),
        'rsync':      ('exfiltrateData',        'Exfiltrate data via rsync',   'exfiltration',
                       ['dataExfiltrated'], ['shellAccessGained']),
    }

    TOOL_MITRE = {
        'nmap':       ('T1046', 'Network Service Discovery',    'discovery'),
        'masscan':    ('T1046', 'Network Service Discovery',    'discovery'),
        'gobuster':   ('T1083', 'File and Directory Discovery', 'discovery'),
        'dirb':       ('T1083', 'File and Directory Discovery', 'discovery'),
        'hydra':      ('T1110', 'Brute Force',                  'credential-access'),
        'medusa':     ('T1110', 'Brute Force',                  'credential-access'),
        'john':       ('T1110', 'Brute Force',                  'credential-access'),
        'hashcat':    ('T1110', 'Brute Force',                  'credential-access'),
        'sqlmap':     ('T1190', 'Exploit Public-Facing App',    'initial-access'),
        'msfconsole': ('T1059', 'Command and Scripting',        'execution'),
        'ssh':        ('T1078', 'Valid Accounts',               'initial-access'),
        'nc':         ('T1059.004', 'Unix Shell',               'execution'),
        'whoami':     ('T1033', 'System Owner/User Discovery',  'discovery'),
        'id':         ('T1033', 'System Owner/User Discovery',  'discovery'),
        'uname':      ('T1082', 'System Information Discovery', 'discovery'),
        'find':       ('T1083', 'File and Directory Discovery', 'discovery'),
        'cat':        ('T1083', 'File and Directory Discovery', 'discovery'),
        'wget':       ('T1105', 'Ingress Tool Transfer',        'command-and-control'),
        'curl':       ('T1105', 'Ingress Tool Transfer',        'command-and-control'),
        'scp':        ('T1048', 'Exfiltration Over Alt Proto',  'exfiltration'),
    }

    ae, mitre, raw = [], [], []
    for e in entries:
        eid = e["entry_id"]
        cmd = e.get("command", "").strip()
        first_word = cmd.split()[0].lower().lstrip('./') if cmd.split() else ""

        if not cmd:
            ae.append({"entry_id": eid, "action_name": "noise", "action_description": "",
                       "phase": "noise", "produces_effects": [], "requires_effects": [], "is_noise": True})
            mitre.append({"entry_id": eid, "technique_id": "T0000", "technique_name": "Noise",
                          "tactic": "none", "confidence": 0.0})
            raw.append({"entry_id": eid, "tool": "", "action": "", "target": "",
                        "phase": "noise", "is_noise": True, "cleaned_command": cmd})
            continue

        ad = TOOL_DATA.get(first_word)
        if ad:
            aname, adesc, aphase, produces, requires = ad
        else:
            aname, adesc, aphase = "executeCommand", f"Execute {first_word}", "post-exploitation"
            produces, requires = ["commandExecuted"], ["shellAccessGained"]

        md = TOOL_MITRE.get(first_word, ('T1059', 'Command and Scripting', 'execution'))
        tid, tname, tactic = md

        ae.append({"entry_id": eid, "action_name": aname, "action_description": adesc,
                   "phase": aphase, "produces_effects": produces, "requires_effects": requires,
                   "is_noise": False})
        mitre.append({"entry_id": eid, "technique_id": tid, "technique_name": tname,
                      "tactic": tactic, "confidence": 0.7})
        raw.append({"entry_id": eid, "tool": first_word, "action": aname, "target": "",
                    "phase": aphase, "is_noise": False, "cleaned_command": cmd})

    return ae, mitre, raw


def main():
    ap = argparse.ArgumentParser(description="Attack Graph Visualizer")
    ap.add_argument("--input",       default="notes",  help="Path to data file or folder (default: notes/)")
    ap.add_argument("--output",      default="public", help="Output directory (default: public/)")
    ap.add_argument("--batch-size",  type=int, default=20, help="Entries per agent batch (default: 20)")
    ap.add_argument("--skip-agents", action="store_true", help="Skip Claude agents, use heuristic classification")
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
        ae_results, mi_results, ra_results = make_dummy_classifications(entries)
    else:
        print(f"\n[2/4] Running 3 agents in parallel across {len(batches)} batch(es)...")
        ae_results, mi_results, ra_results = run_agents_parallel(batches)

    # ── Merge & build graph ────────────────────────────────────────────────
    print("\n[3/4] Merging classifications and building graph...")
    enriched = merge_classifications(entries, ae_results, mi_results, ra_results)
    graph = visualizer.build_graph(enriched)

    n_cmd  = len(graph["nodes"])
    n_ae   = len(graph["actions_effects_nodes"])
    n_mi   = len(graph["mitre_nodes"])
    n_edge = len(graph["edges"])
    print(f"       {n_cmd} command nodes, {n_ae} action/effect nodes, {n_mi} MITRE nodes, {n_edge} edges")

    # ── Write outputs ──────────────────────────────────────────────────────
    print(f"\n[4/4] Writing output to {args.output}/")
    json_path, html_path = visualizer.write_outputs(graph, args.output)

    print(f"\nDone. Open in browser:\n  {os.path.abspath(html_path)}\n")


if __name__ == "__main__":
    main()
