"""
Builds graph_data.json and a self-contained index.html from enriched entries.
"""

import json
import os

# ── Color maps ──────────────────────────────────────────────────────────────

PHASE_COLORS = {
    "reconnaissance":   "#4e9af1",
    "exploitation":     "#e84a4a",
    "post-exploitation":"#f1c94e",
    "lateral-movement": "#20b2aa",
    "persistence":      "#a0d468",
    "exfiltration":     "#ff4757",
    "noise":            "#555555",
}

EFFECT_COLOR = "#6e48aa"  # purple — visually distinct from action phase colors

MITRE_TACTIC_COLORS = {
    "reconnaissance":       "#4e9af1",
    "resource-development": "#7ec8e3",
    "initial-access":       "#c97fc9",
    "execution":            "#f1c94e",
    "persistence":          "#a0d468",
    "privilege-escalation": "#e84a4a",
    "defense-evasion":      "#fd9644",
    "credential-access":    "#da77f2",
    "discovery":            "#e8884a",
    "lateral-movement":     "#20b2aa",
    "collection":           "#a0522d",
    "command-and-control":  "#ff6b6b",
    "exfiltration":         "#ff4757",
    "impact":               "#ff0000",
    "none":                 "#888888",
}


def build_graph(enriched_entries):
    """
    Build the full graph_data structure from enriched entries.
    enriched_entries: list of dicts, each with entry_id + raw/mitre/actions_effects sub-dicts.
    """
    nodes = []
    action_map = {}   # action_name → action node
    effect_map = {}   # effect_name → effect node
    mitre_map  = {}   # technique_id → mitre node
    edges = []

    source_files_seen = set()

    # ── Build command nodes ──────────────────────────────────────────────────
    for e in enriched_entries:
        eid = e["entry_id"]
        raw  = e.get("raw", {})
        mitre = e.get("mitre", {})
        ae   = e.get("actions_effects", {})

        phase       = raw.get("phase", "noise")
        is_noise    = raw.get("is_noise", False)
        tactic      = mitre.get("tactic", "none")
        technique_id = mitre.get("technique_id", "T0000")
        action_name = ae.get("action_name", "unknown")
        ae_is_noise = ae.get("is_noise", False)

        source_file = e.get("source_file", "")
        source_files_seen.add(source_file)

        node = {
            "id": f"cmd::{eid}",
            "layer": "command",
            "label": (raw.get("cleaned_command") or e.get("command", ""))[:60],
            "entry_id": eid,
            "source_file": source_file,
            "command": e.get("command", ""),
            "reasoning": e.get("reasoning", ""),
            "output": e.get("output", ""),
            "exit_code": e.get("exit_code"),
            "agent_name": e.get("agent", ""),
            "raw": raw,
            "mitre": mitre,
            "actions_effects": ae,
            "color_command": PHASE_COLORS.get(phase, "#888888"),
            "color_mitre": MITRE_TACTIC_COLORS.get(tactic, "#888888"),
            "color_action": PHASE_COLORS.get(ae.get("phase", "noise"), "#888888"),
        }
        nodes.append(node)

        # ── Aggregate action/effect nodes ────────────────────────────────────
        if not ae_is_noise and action_name not in ("unknown", "noise", ""):
            ae_phase = ae.get("phase", "noise")
            produces = ae.get("produces_effects", [])
            requires = ae.get("requires_effects", [])

            if action_name not in action_map:
                action_map[action_name] = {
                    "id": f"action::{action_name}",
                    "node_type": "action",
                    "layer": "actions",
                    "label": action_name,
                    "name": action_name,
                    "description": ae.get("action_description", ""),
                    "phase": ae_phase,
                    "color": PHASE_COLORS.get(ae_phase, "#888888"),
                    "entry_ids": [],
                    "produces_effects": [],
                    "requires_effects": [],
                }
            anode = action_map[action_name]
            anode["entry_ids"].append(eid)
            for eff in produces:
                if eff not in anode["produces_effects"]:
                    anode["produces_effects"].append(eff)
            for eff in requires:
                if eff not in anode["requires_effects"]:
                    anode["requires_effects"].append(eff)

            # Collect all effect names
            for eff in produces + requires:
                if eff not in effect_map:
                    effect_map[eff] = {
                        "id": f"effect::{eff}",
                        "node_type": "effect",
                        "layer": "actions",
                        "label": eff,
                        "name": eff,
                        "color": EFFECT_COLOR,
                        "produced_by": [],
                        "enables_actions": [],
                    }
            for eff in produces:
                if action_name not in effect_map[eff]["produced_by"]:
                    effect_map[eff]["produced_by"].append(action_name)
            for eff in requires:
                if action_name not in effect_map[eff]["enables_actions"]:
                    effect_map[eff]["enables_actions"].append(action_name)

        # ── Aggregate MITRE nodes ─────────────────────────────────────────────
        if not is_noise and technique_id and technique_id != "T0000":
            if technique_id not in mitre_map:
                mitre_map[technique_id] = {
                    "id": f"mitre::{technique_id}",
                    "layer": "mitre",
                    "label": technique_id,
                    "technique_name": mitre.get("technique_name", ""),
                    "tactic": tactic,
                    "color": MITRE_TACTIC_COLORS.get(tactic, "#888888"),
                    "entry_ids": [],
                }
            mitre_map[technique_id]["entry_ids"].append(eid)

    # ── Command sequence edges ────────────────────────────────────────────────
    by_source = {}
    for node in nodes:
        by_source.setdefault(node["source_file"], []).append(node)

    for sf_nodes in by_source.values():
        sf_nodes.sort(key=lambda n: n["entry_id"])
        for i in range(len(sf_nodes) - 1):
            a, b = sf_nodes[i], sf_nodes[i + 1]
            if not a["raw"].get("is_noise") and not b["raw"].get("is_noise"):
                edges.append({"source": a["id"], "target": b["id"],
                               "type": "sequence", "layer": "command"})

    # ── Actions/effects edges ─────────────────────────────────────────────────
    for aname, anode in action_map.items():
        for eff in anode["produces_effects"]:
            if eff in effect_map:
                edges.append({"source": anode["id"], "target": effect_map[eff]["id"],
                               "type": "produces", "layer": "actions"})
        for eff in anode["requires_effects"]:
            if eff in effect_map:
                edges.append({"source": effect_map[eff]["id"], "target": anode["id"],
                               "type": "enables", "layer": "actions"})

    # ── MITRE sequence edges ──────────────────────────────────────────────────
    mitre_nodes = list(mitre_map.values())
    mitre_nodes.sort(key=lambda n: min(n["entry_ids"]))
    for i in range(len(mitre_nodes) - 1):
        edges.append({"source": mitre_nodes[i]["id"], "target": mitre_nodes[i + 1]["id"],
                       "type": "sequence", "layer": "mitre"})

    # ── Cross-layer edges (cmd → action, cmd → mitre) ─────────────────────────
    for node in nodes:
        eid = node["entry_id"]
        ae  = node["actions_effects"]
        aname = ae.get("action_name", "")
        if not ae.get("is_noise") and aname and aname not in ("unknown", "noise", "") and aname in action_map:
            edges.append({"source": node["id"], "target": f"action::{aname}",
                           "type": "maps_to", "layer": "cross"})

        mitre = node["mitre"]
        tid = mitre.get("technique_id", "T0000")
        if not node["raw"].get("is_noise") and tid and tid != "T0000":
            edges.append({"source": node["id"], "target": f"mitre::{tid}",
                           "type": "maps_to", "layer": "cross"})

    actions_effects_nodes = list(action_map.values()) + list(effect_map.values())

    graph = {
        "meta": {
            "total_entries": len(enriched_entries),
            "source_files": sorted(source_files_seen),
        },
        "nodes": nodes,
        "actions_effects_nodes": actions_effects_nodes,
        "mitre_nodes": mitre_nodes,
        "edges": edges,
        "color_maps": {
            "phase": PHASE_COLORS,
            "mitre_tactic": MITRE_TACTIC_COLORS,
            "effect": {"effect": EFFECT_COLOR},
        },
    }
    return graph


def build_html(graph):
    """Return a self-contained HTML string with inlined graph data and D3 visualization."""

    graph_json = json.dumps(graph, indent=2)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Attack Graph Visualizer</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', system-ui, sans-serif; height: 100vh; display: flex; flex-direction: column; overflow: hidden; }}

  #header {{ padding: 12px 20px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; align-items: center; gap: 16px; flex-shrink: 0; }}
  #header h1 {{ font-size: 16px; font-weight: 600; color: #f0f6fc; }}
  #header .meta {{ font-size: 12px; color: #8b949e; }}

  #controls {{ display: flex; gap: 8px; margin-left: auto; }}
  .layer-btn {{ padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; background: #21262d; color: #8b949e; cursor: pointer; font-size: 13px; transition: all 0.15s; }}
  .layer-btn:hover {{ border-color: #58a6ff; color: #58a6ff; }}
  .layer-btn.active {{ background: #1f6feb; border-color: #1f6feb; color: #fff; }}

  #flag-bar {{ padding: 6px 20px; background: #161b22; border-bottom: 1px solid #30363d; display: flex; gap: 6px; overflow-x: auto; flex-shrink: 0; }}
  #flag-bar::-webkit-scrollbar {{ height: 4px; }} #flag-bar::-webkit-scrollbar-thumb {{ background: #30363d; border-radius: 2px; }}
  .flag-btn {{ padding: 3px 10px; border: 1px solid #30363d; border-radius: 12px; background: transparent; color: #8b949e; cursor: pointer; font-size: 12px; white-space: nowrap; transition: all 0.15s; flex-shrink: 0; }}
  .flag-btn:hover {{ border-color: #f1c94e; color: #f1c94e; }}
  .flag-btn.active {{ background: #f1c94e22; border-color: #f1c94e; color: #f1c94e; }}

  #main {{ display: flex; flex: 1; overflow: hidden; }}
  #graph-container {{ flex: 1; position: relative; overflow: hidden; }}
  svg {{ width: 100%; height: 100%; }}

  #detail-panel {{ width: 320px; background: #161b22; border-left: 1px solid #30363d; overflow-y: auto; flex-shrink: 0; display: none; }}
  #detail-panel.visible {{ display: block; }}
  #detail-panel .panel-header {{ padding: 14px 16px; border-bottom: 1px solid #30363d; display: flex; justify-content: space-between; align-items: center; }}
  #detail-panel .panel-header h3 {{ font-size: 14px; font-weight: 600; color: #f0f6fc; }}
  #detail-panel .close-btn {{ cursor: pointer; color: #8b949e; font-size: 18px; line-height: 1; }}
  #detail-panel .close-btn:hover {{ color: #f0f6fc; }}
  .detail-body {{ padding: 16px; }}
  .detail-field {{ margin-bottom: 12px; }}
  .detail-field label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; display: block; margin-bottom: 4px; }}
  .detail-field .value {{ font-size: 13px; color: #c9d1d9; word-break: break-all; }}
  .detail-field .value.mono {{ font-family: 'Consolas', 'Courier New', monospace; background: #0d1117; padding: 6px 8px; border-radius: 4px; font-size: 12px; white-space: pre-wrap; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; margin: 2px; }}

  #legend {{ position: absolute; bottom: 16px; left: 16px; background: rgba(22,27,34,0.92); border: 1px solid #30363d; border-radius: 8px; padding: 12px; min-width: 160px; max-height: 60vh; overflow-y: auto; }}
  #legend h4 {{ font-size: 11px; text-transform: uppercase; color: #8b949e; margin-bottom: 8px; letter-spacing: 0.5px; }}
  #legend .legend-section {{ margin-top: 10px; }}
  #legend .legend-section:first-child {{ margin-top: 0; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 5px; font-size: 12px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
  .legend-diamond {{ width: 10px; height: 10px; transform: rotate(45deg); flex-shrink: 0; }}

  .node .node-shape {{ stroke-width: 1.5; cursor: pointer; transition: stroke 0.15s; }}
  .node .node-shape:hover {{ stroke: #f0f6fc !important; stroke-width: 2.5; }}
  .node.selected .node-shape {{ stroke: #f0f6fc !important; stroke-width: 3; }}
  .node.noise .node-shape {{ opacity: 0.35; }}
  .node text {{ font-size: 10px; fill: #c9d1d9; pointer-events: none; }}

  .link {{ stroke-opacity: 0.6; fill: none; }}
  .link-sequence {{ stroke: #30363d; }}
  .link-produces {{ stroke: #3fb950; stroke-dasharray: 5,3; }}
  .link-enables  {{ stroke: #58a6ff; }}

  .tooltip {{ position: absolute; background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; font-size: 12px; pointer-events: none; max-width: 260px; word-break: break-all; z-index: 10; }}

  #stats {{ position: absolute; top: 12px; left: 16px; font-size: 11px; color: #8b949e; }}
</style>
</head>
<body>

<div id="header">
  <h1>Attack Graph Visualizer</h1>
  <span class="meta" id="meta-text"></span>
  <div id="controls">
    <button class="layer-btn active" data-layer="command">Commands</button>
    <button class="layer-btn" data-layer="mitre">MITRE ATT&CK</button>
    <button class="layer-btn" data-layer="actions">Actions &amp; Effects</button>
  </div>
</div>

<div id="flag-bar"></div>

<div id="main">
  <div id="graph-container">
    <div id="stats"></div>
    <svg id="svg"></svg>
    <div id="legend">
      <div id="legend-items"></div>
    </div>
    <div class="tooltip" id="tooltip" style="display:none"></div>
  </div>
  <div id="detail-panel">
    <div class="panel-header">
      <h3>Details</h3>
      <span class="close-btn" id="close-panel">&times;</span>
    </div>
    <div class="detail-body" id="detail-body"></div>
  </div>
</div>

<script>
const GRAPH = {graph_json};
const COLOR_MAPS = GRAPH.color_maps;

let activeLayer = 'command';
let selectedFlag = null;
let simulation = null;

// ── SVG setup ──────────────────────────────────────────────────────────────
const svg = d3.select('#svg');
const container = svg.append('g').attr('class', 'container');

svg.call(d3.zoom().scaleExtent([0.08, 4]).on('zoom', (e) => container.attr('transform', e.transform)));

const defs = svg.append('defs');
function addMarker(id, color) {{
  defs.append('marker')
    .attr('id', id)
    .attr('viewBox', '0 -4 8 8').attr('refX', 16).attr('refY', 0)
    .attr('markerWidth', 5).attr('markerHeight', 5).attr('orient', 'auto')
    .append('path').attr('d', 'M0,-4L8,0L0,4').attr('fill', color);
}}
addMarker('arrow-gray',  '#30363d');
addMarker('arrow-green', '#3fb950');
addMarker('arrow-blue',  '#58a6ff');

const linkGroup = container.append('g').attr('class', 'links');
const nodeGroup = container.append('g').attr('class', 'nodes');

document.getElementById('meta-text').textContent =
  `${{GRAPH.meta.total_entries}} entries · ${{GRAPH.meta.source_files.length}} file(s)`;

// ── Flag filter ────────────────────────────────────────────────────────────
function renderFlagButtons() {{
  const bar = document.getElementById('flag-bar');
  const files = GRAPH.meta.source_files;
  if (files.length <= 1) {{ bar.style.display = 'none'; return; }}

  const flagName = f => f.replace(/[.]txt$/i, '');
  let html = `<button class="flag-btn active" data-flag="">All</button>`;
  html += files.map(f => `<button class="flag-btn" data-flag="${{f}}">${{flagName(f)}}</button>`).join('');
  bar.innerHTML = html;

  bar.querySelectorAll('.flag-btn').forEach(btn => {{
    btn.addEventListener('click', () => {{
      bar.querySelectorAll('.flag-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      selectedFlag = btn.dataset.flag || null;
      closePanel();
      renderGraph();
    }});
  }});
}}

// ── Layer toggle ───────────────────────────────────────────────────────────
document.querySelectorAll('.layer-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.layer-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    closePanel();
    activeLayer = btn.dataset.layer;
    renderGraph();
    renderLegend();
  }});
}});

// ── Graph rendering ────────────────────────────────────────────────────────
function getVisibleNodes() {{
  let nodes;
  if (activeLayer === 'command')      nodes = GRAPH.nodes;
  else if (activeLayer === 'mitre')   nodes = GRAPH.mitre_nodes;
  else                                nodes = GRAPH.actions_effects_nodes;

  if (!selectedFlag) return nodes;

  const flagEids = new Set(
    GRAPH.nodes.filter(n => n.source_file === selectedFlag).map(n => n.entry_id)
  );

  if (activeLayer === 'command') return nodes.filter(n => n.source_file === selectedFlag);

  if (activeLayer === 'mitre') return nodes.filter(n => (n.entry_ids || []).some(eid => flagEids.has(eid)));

  if (activeLayer === 'actions') {{
    const visibleActions = new Set(
      nodes.filter(n => n.node_type === 'action' && (n.entry_ids || []).some(eid => flagEids.has(eid))).map(n => n.name)
    );
    return nodes.filter(n =>
      n.node_type === 'action'
        ? visibleActions.has(n.name)
        : (n.produced_by || []).some(a => visibleActions.has(a)) || (n.enables_actions || []).some(a => visibleActions.has(a))
    );
  }}
  return nodes;
}}

function getVisibleEdges(nodeIds) {{
  return GRAPH.edges.filter(e => e.layer === activeLayer && nodeIds.has(e.source) && nodeIds.has(e.target));
}}

function getNodeColor(node) {{
  if (activeLayer === 'command') return node.color_command;
  return node.color;
}}

function getNodeRadius(node) {{
  if (activeLayer === 'command') return node.raw && node.raw.is_noise ? 5 : 9;
  if (activeLayer === 'actions') {{
    if (node.node_type === 'effect') return 9;
    const c = node.entry_ids ? node.entry_ids.length : 1;
    return Math.max(10, Math.min(22, 10 + c * 2));
  }}
  const c = node.entry_ids ? node.entry_ids.length : 1;
  return Math.max(10, Math.min(28, 10 + c * 2));
}}

// Circle and diamond path generators (centered at origin)
function circlePath(r) {{ return `M ${{r}},0 A ${{r}},${{r}} 0 1,0 ${{-r}},0 A ${{r}},${{r}} 0 1,0 ${{r}},0 Z`; }}
function diamondPath(r) {{ return `M 0,${{-r}} L ${{r}},0 L 0,${{r}} L ${{-r}},0 Z`; }}

function getNodePath(node) {{
  const r = getNodeRadius(node);
  if (activeLayer === 'actions' && node.node_type === 'effect') return diamondPath(r);
  return circlePath(r);
}}

function getNodeLabel(node) {{
  if (activeLayer === 'command') {{
    const cmd = node.raw && node.raw.cleaned_command ? node.raw.cleaned_command : node.command;
    return cmd ? cmd.substring(0, 28) : '';
  }}
  if (activeLayer === 'actions') {{
    // Split camelCase to words, truncate
    return (node.label || '').replace(/([A-Z])/g, ' $1').trim().substring(0, 20);
  }}
  return (node.label || '').substring(0, 20);
}}

function edgeMarker(e) {{
  if (e.type === 'produces') return 'url(#arrow-green)';
  if (e.type === 'enables')  return 'url(#arrow-blue)';
  return 'url(#arrow-gray)';
}}

function renderGraph() {{
  const rawNodes = getVisibleNodes();
  const nodes = rawNodes.map(n => ({{ ...n }}));
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
  const nodeIds = new Set(nodes.map(n => n.id));

  const rawEdges = getVisibleEdges(nodeIds);
  const edges = rawEdges.map(e => ({{ ...e,
    source: nodeById[e.source] || e.source,
    target: nodeById[e.target] || e.target,
  }}));

  document.getElementById('stats').textContent = `${{nodes.length}} nodes · ${{edges.length}} edges`;

  if (simulation) simulation.stop();

  const svgEl = document.getElementById('svg');
  const W = svgEl.clientWidth || 900;
  const H = svgEl.clientHeight || 600;

  simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(n => n.id).distance(90).strength(0.4))
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide().radius(n => getNodeRadius(n) + 8));

  // Links
  const link = linkGroup.selectAll('.link').data(edges, e => `${{e.source.id || e.source}}→${{e.target.id || e.target}}`);
  link.exit().remove();
  const linkEnter = link.enter().append('line')
    .attr('class', e => `link link-${{e.type}}`)
    .attr('marker-end', e => edgeMarker(e));
  const linkMerge = linkEnter.merge(link);

  // Nodes
  const node = nodeGroup.selectAll('.node').data(nodes, n => n.id);
  node.exit().remove();

  const nodeEnter = node.enter().append('g')
    .attr('class', n => 'node' + (n.raw && n.raw.is_noise ? ' noise' : ''))
    .call(d3.drag()
      .on('start', (e, n) => {{ if (!e.active) simulation.alphaTarget(0.3).restart(); n.fx = n.x; n.fy = n.y; }})
      .on('drag',  (e, n) => {{ n.fx = e.x; n.fy = e.y; }})
      .on('end',   (e, n) => {{ if (!e.active) simulation.alphaTarget(0); n.fx = null; n.fy = null; }})
    )
    .on('click', (e, n) => {{ e.stopPropagation(); selectNode(n); }})
    .on('mouseover', showTooltip)
    .on('mouseout', hideTooltip);

  nodeEnter.append('path')
    .attr('class', 'node-shape')
    .attr('d', n => getNodePath(n))
    .attr('fill', n => getNodeColor(n))
    .attr('stroke', '#0d1117');

  nodeEnter.append('text')
    .attr('dy', n => getNodeRadius(n) + 13)
    .attr('text-anchor', 'middle')
    .text(n => getNodeLabel(n));

  const nodeMerge = nodeEnter.merge(node);
  nodeMerge.select('.node-shape')
    .attr('d', n => getNodePath(n))
    .attr('fill', n => getNodeColor(n));
  nodeMerge.select('text').text(n => getNodeLabel(n));

  simulation.on('tick', () => {{
    linkMerge.attr('x1', e => e.source.x).attr('y1', e => e.source.y)
             .attr('x2', e => e.target.x).attr('y2', e => e.target.y);
    nodeMerge.attr('transform', n => `translate(${{n.x}},${{n.y}})`);
  }});

  svg.on('click', () => {{ closePanel(); nodeGroup.selectAll('.node').classed('selected', false); }});
}}

// ── Detail panel ───────────────────────────────────────────────────────────
function selectNode(node) {{
  nodeGroup.selectAll('.node').classed('selected', n => n.id === node.id);
  showDetail(node);
}}

function field(label, value, mono=false) {{
  if (!value && value !== 0) return '';
  return `<div class="detail-field">
    <label>${{label}}</label>
    <div class="value${{mono ? ' mono' : ''}}">${{esc(String(value))}}</div>
  </div>`;
}}

function badge(text, color) {{
  return `<span class="badge" style="background:${{color}}22;color:${{color}};border:1px solid ${{color}}44">${{esc(text)}}</span>`;
}}

function esc(s) {{ return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }}

function cmdList(entry_ids, onclick) {{
  return (entry_ids || []).map(eid => {{
    const cn = GRAPH.nodes.find(n => n.entry_id === eid);
    if (!cn) return '';
    const cmd = cn.raw && cn.raw.cleaned_command ? cn.raw.cleaned_command : cn.command;
    return `<div class="badge" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;display:block;margin:3px 0;cursor:pointer;font-size:11px" onclick="${{onclick}}(${{eid}})">${{esc(cmd.substring(0,50))}}</div>`;
  }}).join('');
}}

function showDetail(node) {{
  const panel = document.getElementById('detail-panel');
  const body  = document.getElementById('detail-body');
  panel.classList.add('visible');

  if (activeLayer === 'command') {{
    const r = node.raw || {{}};
    const m = node.mitre || {{}};
    const ae = node.actions_effects || {{}};
    body.innerHTML = `
      ${{field('Command', r.cleaned_command || node.command, true)}}
      ${{field('Reasoning', node.reasoning)}}
      <div class="detail-field"><label>Phase</label><div>${{badge(r.phase || 'unknown', node.color_command)}}</div></div>
      ${{field('Tool', r.tool)}}
      ${{field('Target', r.target)}}
      <div class="detail-field"><label>Action</label><div>${{badge(ae.action_name || '?', node.color_action)}}</div>
        ${{ae.action_description ? `<div style="margin-top:4px;font-size:12px;color:#8b949e">${{esc(ae.action_description)}}</div>` : ''}}
      </div>
      ${{ae.produces_effects && ae.produces_effects.length ? `<div class="detail-field"><label>Produces Effects</label><div>${{ae.produces_effects.map(e => badge(e, '#3fb950')).join(' ')}}</div></div>` : ''}}
      ${{ae.requires_effects && ae.requires_effects.length ? `<div class="detail-field"><label>Requires Effects</label><div>${{ae.requires_effects.map(e => badge(e, '#58a6ff')).join(' ')}}</div></div>` : ''}}
      <div class="detail-field"><label>MITRE</label>
        <div>${{badge(m.technique_id || '?', node.color_mitre)}} ${{esc(m.technique_name || '')}}</div>
        <div style="margin-top:4px;font-size:11px;color:#8b949e">${{m.tactic || ''}}</div>
      </div>
      ${{field('Source File', node.source_file)}}
      ${{node.output ? field('Output', node.output.substring(0, 300), true) : ''}}
    `;
  }} else if (activeLayer === 'actions') {{
    if (node.node_type === 'action') {{
      body.innerHTML = `
        <div class="detail-field"><label>Action</label><div style="font-size:15px;font-weight:600;color:#f0f6fc">${{esc(node.name)}}</div></div>
        ${{field('Description', node.description)}}
        <div class="detail-field"><label>Phase</label><div>${{badge(node.phase, node.color)}}</div></div>
        ${{node.produces_effects && node.produces_effects.length ? `<div class="detail-field"><label>Produces</label><div>${{node.produces_effects.map(e => badge(e, '#3fb950')).join(' ')}}</div></div>` : ''}}
        ${{node.requires_effects && node.requires_effects.length ? `<div class="detail-field"><label>Requires</label><div>${{node.requires_effects.map(e => badge(e, '#58a6ff')).join(' ')}}</div></div>` : ''}}
        <div class="detail-field"><label>Commands (${{(node.entry_ids||[]).length}})</label>${{cmdList(node.entry_ids, 'switchToCommand')}}</div>
      `;
    }} else {{
      body.innerHTML = `
        <div class="detail-field"><label>Effect</label><div style="font-size:15px;font-weight:600;color:#f0f6fc">${{esc(node.name)}}</div></div>
        ${{node.produced_by && node.produced_by.length ? `<div class="detail-field"><label>Produced By</label><div>${{node.produced_by.map(a => badge(a, '#3fb950')).join(' ')}}</div></div>` : ''}}
        ${{node.enables_actions && node.enables_actions.length ? `<div class="detail-field"><label>Enables</label><div>${{node.enables_actions.map(a => badge(a, '#58a6ff')).join(' ')}}</div></div>` : ''}}
      `;
    }}
  }} else if (activeLayer === 'mitre') {{
    body.innerHTML = `
      ${{field('Technique ID', node.label)}}
      ${{field('Technique Name', node.technique_name)}}
      <div class="detail-field"><label>Tactic</label><div>${{badge(node.tactic, node.color)}}</div></div>
      <div class="detail-field"><label>Commands (${{(node.entry_ids||[]).length}})</label>${{cmdList(node.entry_ids, 'switchToCommand')}}</div>
    `;
  }}
}}

function switchToCommand(eid) {{
  document.querySelectorAll('.layer-btn').forEach(b => b.classList.toggle('active', b.dataset.layer === 'command'));
  closePanel();
  activeLayer = 'command';
  renderGraph();
  renderLegend();
  setTimeout(() => {{
    const target = GRAPH.nodes.find(n => n.entry_id === eid);
    if (target) {{
      const g = nodeGroup.selectAll('.node').filter(n => n.entry_id === eid);
      if (!g.empty()) selectNode(g.datum());
    }}
  }}, 600);
}}

function closePanel() {{ document.getElementById('detail-panel').classList.remove('visible'); }}
document.getElementById('close-panel').addEventListener('click', closePanel);

// ── Tooltip ────────────────────────────────────────────────────────────────
const tooltip = document.getElementById('tooltip');
function showTooltip(event, node) {{
  let text = '';
  if (activeLayer === 'command') {{
    const cmd = node.raw && node.raw.cleaned_command ? node.raw.cleaned_command : node.command;
    text = cmd || node.label;
  }} else if (activeLayer === 'actions') {{
    text = node.node_type === 'effect' ? `Effect: ${{node.name}}` : `Action: ${{node.name}} (${{node.phase}})`;
  }} else {{
    text = `${{node.label}}: ${{node.technique_name || ''}} (${{node.tactic || ''}})`;
  }}
  tooltip.textContent = text;
  tooltip.style.display = 'block';
  tooltip.style.left = (event.offsetX + 14) + 'px';
  tooltip.style.top  = (event.offsetY - 10) + 'px';
}}
function hideTooltip() {{ tooltip.style.display = 'none'; }}

// ── Legend ─────────────────────────────────────────────────────────────────
function renderLegend() {{
  const items = document.getElementById('legend-items');

  if (activeLayer === 'command' || activeLayer === 'actions') {{
    const phaseMap = COLOR_MAPS.phase;
    const effectColor = COLOR_MAPS.effect.effect;
    let html = `<div class="legend-section"><h4>${{activeLayer === 'actions' ? 'Actions (by phase)' : 'Phase'}}</h4>`;
    html += Object.entries(phaseMap).map(([k, c]) =>
      `<div class="legend-item"><div class="legend-dot" style="background:${{c}}"></div><span>${{k}}</span></div>`
    ).join('');
    if (activeLayer === 'actions') {{
      html += `</div><div class="legend-section"><h4>Effects</h4>`;
      html += `<div class="legend-item"><div class="legend-diamond" style="background:${{effectColor}}"></div><span>effect (diamond)</span></div>`;
      html += `</div><div class="legend-section"><h4>Edges</h4>`;
      html += `<div class="legend-item"><svg width="28" height="12"><line x1="0" y1="6" x2="28" y2="6" stroke="#3fb950" stroke-dasharray="4,2" stroke-width="1.5"/></svg><span>produces</span></div>`;
      html += `<div class="legend-item"><svg width="28" height="12"><line x1="0" y1="6" x2="28" y2="6" stroke="#58a6ff" stroke-width="1.5"/></svg><span>enables</span></div>`;
    }}
    html += `</div>`;
    items.innerHTML = html;
  }} else {{
    const map = COLOR_MAPS.mitre_tactic;
    items.innerHTML = `<div class="legend-section"><h4>Tactic</h4>` +
      Object.entries(map).map(([k, c]) =>
        `<div class="legend-item"><div class="legend-dot" style="background:${{c}}"></div><span>${{k}}</span></div>`
      ).join('') + `</div>`;
  }}
}}

// ── Init ───────────────────────────────────────────────────────────────────
renderFlagButtons();
renderGraph();
renderLegend();
</script>
</body>
</html>"""

    return html


def write_outputs(graph, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    json_path = os.path.join(output_dir, "graph_data.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(graph, f, indent=2)
    print(f"  Saved: {json_path}")

    html_path = os.path.join(output_dir, "index.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(build_html(graph))
    print(f"  Saved: {html_path}")

    return json_path, html_path
