"""
Subprocess wrapper for Claude agent calls.
Each call runs `claude -p` with a system prompt and returns parsed JSON.
"""

import json
import os
import subprocess
import sys
import re
from agents.prompts import ACTIONS_EFFECTS_SYSTEM_PROMPT, MITRE_SYSTEM_PROMPT, RAW_SYSTEM_PROMPT


def _claude_cmd(args):
    """
    Build the claude CLI command.
    On Windows, calls node.exe + cli.js directly to avoid cmd.exe quote-mangling.
    """
    if sys.platform == "win32":
        cli = os.path.join(os.environ.get("APPDATA", ""), "npm",
                           "node_modules", "@anthropic-ai", "claude-code", "cli.js")
        if os.path.exists(cli):
            return ["node", cli] + args
        # fallback
        return ["cmd.exe", "/c", "claude"] + args
    return ["claude"] + args

AGENT_PROMPTS = {
    "actions_effects": ACTIONS_EFFECTS_SYSTEM_PROMPT,
    "mitre": MITRE_SYSTEM_PROMPT,
    "raw": RAW_SYSTEM_PROMPT,
}


def _null_actions_effects(entry_id):
    return {"entry_id": entry_id, "action_name": "unknown", "action_description": "",
            "phase": "noise", "produces_effects": [], "requires_effects": [], "is_noise": True}


def _null_mitre(entry_id):
    return {"entry_id": entry_id, "technique_id": "T0000", "technique_name": "Unknown",
            "tactic": "none", "confidence": 0.0}


def _null_raw(entry_id, command=""):
    return {"entry_id": entry_id, "tool": "", "action": "", "target": "",
            "phase": "noise", "is_noise": True, "cleaned_command": command}


NULL_FACTORIES = {
    "actions_effects": _null_actions_effects,
    "mitre": _null_mitre,
    "raw": _null_raw,
}


def _extract_json(text):
    """Extract a JSON array from Claude output, stripping any markdown fences."""
    text = text.strip()
    text = re.sub(r'^```(?:json)?\s*', '', text, flags=re.MULTILINE)
    text = re.sub(r'\s*```\s*$', '', text, flags=re.MULTILINE)
    text = text.strip()

    start = text.find('[')
    end = text.rfind(']')
    if start == -1 or end == -1 or end < start:
        return None
    return text[start:end + 1]


def run_agent(agent_name, batch, timeout=180):
    """
    Run a Claude agent on a batch of entries.

    Args:
        agent_name: "actions_effects", "mitre", or "raw"
        batch: list of entry dicts (already have entry_id assigned)
        timeout: seconds before giving up

    Returns:
        list of classification dicts, one per entry in batch
    """
    system_prompt = AGENT_PROMPTS[agent_name]
    null_factory = NULL_FACTORIES[agent_name]
    entry_ids = [e["entry_id"] for e in batch]

    prompt_text = (
        f"Classify the following {len(batch)} attack session entries.\n\n"
        + json.dumps(batch, indent=2)
    )

    try:
        result = subprocess.run(
            _claude_cmd(["-p", prompt_text, "--system-prompt", system_prompt]),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )

        raw_output = result.stdout.strip()

        if not raw_output:
            print(f"  [WARN] {agent_name} agent: empty output for batch {entry_ids[:3]}...")
            return [null_factory(eid) for eid in entry_ids]

        json_str = _extract_json(raw_output)
        if json_str is None:
            print(f"  [WARN] {agent_name} agent: no JSON array found in output")
            return [null_factory(eid) for eid in entry_ids]

        parsed = json.loads(json_str)

        if len(parsed) != len(batch):
            print(f"  [WARN] {agent_name} agent: expected {len(batch)} results, got {len(parsed)}")
            while len(parsed) < len(batch):
                parsed.append(null_factory(entry_ids[len(parsed)]))
            parsed = parsed[:len(batch)]

        for i, item in enumerate(parsed):
            item["entry_id"] = entry_ids[i]

        return parsed

    except subprocess.TimeoutExpired:
        print(f"  [ERROR] {agent_name} agent timed out for batch {entry_ids[:3]}...")
        return [null_factory(eid) for eid in entry_ids]
    except json.JSONDecodeError as e:
        print(f"  [ERROR] {agent_name} agent JSON parse error: {e}")
        return [null_factory(eid) for eid in entry_ids]
    except Exception as e:
        print(f"  [ERROR] {agent_name} agent unexpected error: {e}")
        return [null_factory(eid) for eid in entry_ids]
