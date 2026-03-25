"""
Flexible input parser for attack session data.
Handles two formats:
  1. session.json — list of dicts with at minimum a "command" key
  2. .txt files — mixed prose + shell commands, one or more files in a folder
"""

import json
import os
import re

# Shell prompt prefixes to detect command lines in text files
PROMPT_PATTERNS = [
    r'^\$\s+',
    r'^>\s+',
    r'^#\s+',
    r'^os-shell>\s*',
    r'^meterpreter>\s*',
    r'^msf\d*>\s*',
    r'^shell>\s*',
    r'^cmd>\s*',
    r'^C:\\[^>]*>\s*',  # Windows prompt
]
PROMPT_RE = re.compile('|'.join(PROMPT_PATTERNS), re.IGNORECASE)

# Heuristics: lines that look like shell commands even without a prompt
COMMAND_KEYWORDS = [
    'nmap', 'masscan', 'netdiscover', 'hydra', 'medusa', 'john', 'hashcat',
    'sqlmap', 'msfconsole', 'msfvenom', 'meterpreter', 'ssh', 'ftp', 'nc',
    'netcat', 'curl', 'wget', 'python', 'python3', 'perl', 'ruby', 'php',
    'bash', 'sh', 'zsh', 'ls', 'cat', 'find', 'grep', 'awk', 'sed',
    'ps', 'whoami', 'id', 'uname', 'ifconfig', 'ip ', 'route', 'arp',
    'sudo', 'su ', 'chmod', 'chown', 'passwd', 'shadow', 'scp', 'rsync',
    'gobuster', 'dirb', 'dirbuster', 'nikto', 'wfuzz', 'ffuf', 'burp',
    'enum4linux', 'smbclient', 'rpcclient', 'ldapsearch', 'snmpwalk',
    'mysql', 'psql', 'mongo', 'redis-cli', 'nc -', 'socat',
    'proxychains', 'chisel', 'ligolo',
]


def _looks_like_command(line):
    """Return True if a line looks like a shell command."""
    if PROMPT_RE.match(line):
        return True
    stripped = line.strip().lower()
    for kw in COMMAND_KEYWORDS:
        if stripped.startswith(kw):
            return True
    return False


def _strip_prompt(line):
    """Remove shell prompt prefix from a command line."""
    return PROMPT_RE.sub('', line).strip()


def _parse_txt_file(filepath):
    """
    Parse a single .txt file into a list of entry dicts.
    Strategy: group consecutive lines into segments, classify each as
    command or prose, then bundle prose context with adjacent commands.
    """
    with open(filepath, encoding='utf-8', errors='replace') as f:
        lines = f.readlines()

    source_name = os.path.splitext(os.path.basename(filepath))[0]
    entries = []

    i = 0
    prose_buffer = []

    while i < len(lines):
        line = lines[i].rstrip('\n')
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        if _looks_like_command(stripped):
            # Collect multi-line command (backslash continuation)
            cmd_lines = [_strip_prompt(stripped)]
            while stripped.endswith('\\') and i + 1 < len(lines):
                i += 1
                next_line = lines[i].rstrip('\n').strip()
                cmd_lines.append(next_line.lstrip())
                stripped = next_line

            command = ' '.join(cmd_lines)
            reasoning = ' '.join(prose_buffer).strip()
            prose_buffer = []

            entries.append({
                "command": command,
                "reasoning": reasoning,
                "output": "",
                "exit_code": None,
                "agent": source_name,
                "source_file": os.path.basename(filepath),
            })
        else:
            prose_buffer.append(stripped)

        i += 1

    # Any trailing prose with no command is a noise entry
    if prose_buffer:
        entries.append({
            "command": "",
            "reasoning": ' '.join(prose_buffer).strip(),
            "output": "",
            "exit_code": None,
            "agent": source_name,
            "source_file": os.path.basename(filepath),
            "is_noise_hint": True,
        })

    return entries


def _parse_json_file(filepath):
    """Parse a session.json file."""
    with open(filepath, encoding='utf-8') as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"{filepath}: expected a JSON array at the top level")

    entries = []
    for item in data:
        entry = {
            "command": str(item.get("command", "")),
            "reasoning": str(item.get("reasoning", "")),
            "output": str(item.get("output", "")),
            "exit_code": item.get("exit_code"),
            "agent": str(item.get("agent", "")),
            "source_file": os.path.basename(filepath),
        }
        entries.append(entry)
    return entries


def parse(input_path):
    """
    Parse input_path into a normalized list of entry dicts with entry_id.

    input_path can be:
      - a .json file
      - a .txt file
      - a directory containing .json and/or .txt files

    Returns: list of dicts, each with:
      entry_id, command, reasoning, output, exit_code, agent, source_file
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input path not found: {input_path}")

    raw_entries = []

    if os.path.isfile(input_path):
        if input_path.endswith('.json'):
            raw_entries = _parse_json_file(input_path)
        elif input_path.endswith('.txt'):
            raw_entries = _parse_txt_file(input_path)
        else:
            raise ValueError(f"Unsupported file type: {input_path}. Use .json or .txt")

    elif os.path.isdir(input_path):
        json_files = sorted([
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.endswith('.json')
        ])
        txt_files = sorted([
            os.path.join(input_path, f)
            for f in os.listdir(input_path)
            if f.endswith('.txt')
        ])

        for fp in json_files:
            print(f"  Parsing JSON: {fp}")
            raw_entries.extend(_parse_json_file(fp))

        for fp in txt_files:
            print(f"  Parsing TXT:  {fp}")
            raw_entries.extend(_parse_txt_file(fp))

        if not raw_entries:
            raise ValueError(f"No .json or .txt files found in {input_path}")

    # Assign entry_ids
    for i, entry in enumerate(raw_entries):
        entry["entry_id"] = i

    print(f"  Parsed {len(raw_entries)} entries total")
    return raw_entries
