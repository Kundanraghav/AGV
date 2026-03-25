"""
Builds graph_data.json and a self-contained index.html from enriched entries.
"""

import json
import os

# ── Color maps ──────────────────────────────────────────────────────────────

CORELANG_ASSET_COLORS = {
    "Network":        "#4e9af1",
    "NetworkService": "#20b2aa",
    "Host":           "#f1c94e",
    "Credentials":    "#c97fc9",
    "Application":    "#e8884a",
    "Data":           "#e84a4a",
    "Identity":       "#a0d468",
    "Unknown":        "#888888",
}

MITRE_TACTIC_COLORS = {
    "reconnaissance":      "#4e9af1",
    "resource-development":"#7ec8e3",
    "initial-access":      "#c97fc9",
    "execution":           "#f1c94e",
    "persistence":         "#a0d468",
    "privilege-escalation":"#e84a4a",
    "defense-evasion":     "#fd9644",
    "credential-access":   "#da77f2",
    "discovery":           "#e8884a",
    "lateral-movement":    "#20b2aa",
    "collection":          "#a0522d",
    "command-and-control": "#ff6b6b",
    "exfiltration":        "#ff4757",
    "impact":              "#ff0000",
    "none":                "#888888",
}

COMMAND_PHASE_COLORS = {
    "reconnaissance":   "#4e9af1",
    "exploitation":     "#e84a4a",
    "post-exploitation":"#f1c94e",
    "lateral-movement": "#20b2aa",
    "persistence":      "#a0d468",
    "exfiltration":     "#ff4757",
    "noise":            "#555555",
}


def build_graph(enriched_entries):
    """
    Build the full graph_data structure from enriched entries.
    enriched_entries: list of dicts, each with entry_id + raw/mitre/corelang sub-dicts.
    """
    nodes = []
    corelang_map = {}   # full_key → corelang node dict
    mitre_map = {}      # technique_id → mitre node dict
    edges = []

    source_files_seen = set()

    # ── Build command nodes ──────────────────────────────────────────────────
    for e in enriched_entries:
        eid = e["entry_id"]
        raw = e.get("raw", {})
        mitre = e.get("mitre", {})
        cl = e.get("corelang", {})

        phase = raw.get("phase", "noise")
        is_noise = raw.get("is_noise", False)
        tactic = mitre.get("tactic", "none")
        asset = cl.get("asset", "Unknown")
        cl_full = cl.get("full", "Unknown.unknown")
        technique_id = mitre.get("technique_id", "T0000")

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
            "corelang": cl,
            "color_command": COMMAND_PHASE_COLORS.get(phase, "#888888"),
            "color_mitre": MITRE_TACTIC_COLORS.get(tactic, "#888888"),
            "color_corelang": CORELANG_ASSET_COLORS.get(asset, "#888888"),
        }
        nodes.append(node)

        # ── Aggregate coreLang nodes ─────────────────────────────────────────
        if not is_noise:
            if cl_full not in corelang_map:
                corelang_map[cl_full] = {
                    "id": f"corelang::{cl_full}",
                    "layer": "corelang",
                    "label": cl_full,
                    "asset": asset,
                    "step": cl.get("step", "unknown"),
                    "full": cl_full,
                    "color": CORELANG_ASSET_COLORS.get(asset, "#888888"),
                    "entry_ids": [],
                }
            corelang_map[cl_full]["entry_ids"].append(eid)

            # ── Aggregate MITRE nodes ────────────────────────────────────────
            if technique_id and technique_id != "T0000":
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

    # ── Build sequence edges within command layer (per source_file, in order) ──
    by_source = {}
    for node in nodes:
        sf = node["source_file"]
        by_source.setdefault(sf, []).append(node)

    for sf, sf_nodes in by_source.items():
        sf_nodes.sort(key=lambda n: n["entry_id"])
        for i in range(len(sf_nodes) - 1):
            a = sf_nodes[i]
            b = sf_nodes[i + 1]
            if not a["raw"].get("is_noise") and not b["raw"].get("is_noise"):
                edges.append({
                    "source": a["id"],
                    "target": b["id"],
                    "type": "sequence",
                    "layer": "command",
                })

    # ── Build coreLang sequence edges ───────────────────────────────────────
    corelang_nodes = list(corelang_map.values())
    # Connect coreLang nodes that appear consecutively (by min entry_id)
    corelang_nodes.sort(key=lambda n: min(n["entry_ids"]))
    for i in range(len(corelang_nodes) - 1):
        edges.append({
            "source": corelang_nodes[i]["id"],
            "target": corelang_nodes[i + 1]["id"],
            "type": "sequence",
            "layer": "corelang",
        })

    # ── Build MITRE sequence edges ───────────────────────────────────────────
    mitre_nodes = list(mitre_map.values())
    mitre_nodes.sort(key=lambda n: min(n["entry_ids"]))
    for i in range(len(mitre_nodes) - 1):
        edges.append({
            "source": mitre_nodes[i]["id"],
            "target": mitre_nodes[i + 1]["id"],
            "type": "sequence",
            "layer": "mitre",
        })

    # ── Cross-layer edges (cmd → mitre, cmd → corelang) ──────────────────────
    for node in nodes:
        eid = node["entry_id"]
        cl = node["corelang"]
        mitre = node["mitre"]
        raw = node["raw"]
        if raw.get("is_noise"):
            continue

        cl_full = cl.get("full", "Unknown.unknown")
        if cl_full in corelang_map:
            edges.append({
                "source": node["id"],
                "target": f"corelang::{cl_full}",
                "type": "maps_to",
                "layer": "cross",
            })

        technique_id = mitre.get("technique_id", "T0000")
        if technique_id and technique_id != "T0000":
            edges.append({
                "source": node["id"],
                "target": f"mitre::{technique_id}",
                "type": "maps_to",
                "layer": "cross",
            })

    graph = {
        "meta": {
            "total_entries": len(enriched_entries),
            "source_files": sorted(source_files_seen),
        },
        "nodes": nodes,
        "corelang_nodes": corelang_nodes,
        "mitre_nodes": mitre_nodes,
        "edges": edges,
        "color_maps": {
            "corelang_asset": CORELANG_ASSET_COLORS,
            "mitre_tactic": MITRE_TACTIC_COLORS,
            "command_phase": COMMAND_PHASE_COLORS,
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
<title>MAL Attack Graph Visualizer</title>
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
  .tag-list {{ display: flex; flex-wrap: wrap; gap: 4px; margin-top: 4px; }}

  #legend {{ position: absolute; bottom: 16px; left: 16px; background: rgba(22,27,34,0.9); border: 1px solid #30363d; border-radius: 8px; padding: 12px; min-width: 160px; }}
  #legend h4 {{ font-size: 11px; text-transform: uppercase; color: #8b949e; margin-bottom: 8px; letter-spacing: 0.5px; }}
  .legend-item {{ display: flex; align-items: center; gap: 8px; margin-bottom: 5px; font-size: 12px; }}
  .legend-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}

  .node circle {{ stroke-width: 1.5; cursor: pointer; transition: stroke 0.15s; }}
  .node circle:hover {{ stroke: #f0f6fc !important; stroke-width: 2.5; }}
  .node.selected circle {{ stroke: #f0f6fc !important; stroke-width: 3; }}
  .node.noise circle {{ opacity: 0.35; }}
  .node text {{ font-size: 10px; fill: #c9d1d9; pointer-events: none; }}

  .link {{ stroke: #30363d; stroke-opacity: 0.6; }}

  .tooltip {{ position: absolute; background: #21262d; border: 1px solid #30363d; border-radius: 6px; padding: 8px 10px; font-size: 12px; pointer-events: none; max-width: 240px; word-break: break-all; z-index: 10; }}

  #stats {{ position: absolute; top: 12px; left: 16px; font-size: 11px; color: #8b949e; }}
</style>
</head>
<body>

<div id="header">
  <h1>MAL Attack Graph</h1>
  <span class="meta" id="meta-text"></span>
  <div id="controls">
    <button class="layer-btn active" data-layer="command">Commands</button>
    <button class="layer-btn" data-layer="mitre">MITRE ATT&CK</button>
    <button class="layer-btn" data-layer="corelang">coreLang</button>
  </div>
</div>

<div id="main">
  <div id="graph-container">
    <div id="stats"></div>
    <svg id="svg"></svg>
    <div id="legend">
      <h4 id="legend-title">Phase</h4>
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
let simulation = null;
let selectedNode = null;

// ── SVG setup ──────────────────────────────────────────────────────────────
const svg = d3.select('#svg');
const container = svg.append('g').attr('class', 'container');

svg.call(d3.zoom()
  .scaleExtent([0.1, 4])
  .on('zoom', (e) => container.attr('transform', e.transform))
);

// Arrow markers
const defs = svg.append('defs');
defs.append('marker')
  .attr('id', 'arrow')
  .attr('viewBox', '0 -4 8 8')
  .attr('refX', 20)
  .attr('refY', 0)
  .attr('markerWidth', 5)
  .attr('markerHeight', 5)
  .attr('orient', 'auto')
  .append('path')
  .attr('d', 'M0,-4L8,0L0,4')
  .attr('fill', '#30363d');

const linkGroup = container.append('g').attr('class', 'links');
const nodeGroup = container.append('g').attr('class', 'nodes');

// ── Meta ───────────────────────────────────────────────────────────────────
document.getElementById('meta-text').textContent =
  `${{GRAPH.meta.total_entries}} entries · ${{GRAPH.meta.source_files.length}} file(s)`;

// ── Layer toggle ───────────────────────────────────────────────────────────
document.querySelectorAll('.layer-btn').forEach(btn => {{
  btn.addEventListener('click', () => {{
    document.querySelectorAll('.layer-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    setLayer(btn.dataset.layer);
  }});
}});

function setLayer(layer) {{
  activeLayer = layer;
  closePanel();
  selectedNode = null;
  renderGraph();
  renderLegend();
}}

// ── Graph rendering ────────────────────────────────────────────────────────
function getVisibleNodes() {{
  if (activeLayer === 'command') return GRAPH.nodes;
  if (activeLayer === 'mitre')   return GRAPH.mitre_nodes;
  if (activeLayer === 'corelang') return GRAPH.corelang_nodes;
  return [];
}}

function getVisibleEdges(nodes) {{
  const ids = new Set(nodes.map(n => n.id));
  return GRAPH.edges.filter(e =>
    e.layer === activeLayer && ids.has(e.source) && ids.has(e.target)
  );
}}

function getNodeColor(node) {{
  if (activeLayer === 'command')  return node.color_command;
  if (activeLayer === 'mitre')    return node.color;
  if (activeLayer === 'corelang') return node.color;
  return '#888';
}}

function getNodeRadius(node) {{
  if (activeLayer === 'command') {{
    return node.raw && node.raw.is_noise ? 5 : 9;
  }}
  const count = node.entry_ids ? node.entry_ids.length : 1;
  return Math.max(10, Math.min(30, 10 + count * 2));
}}

function getNodeLabel(node) {{
  if (activeLayer === 'command') {{
    const cmd = node.raw && node.raw.cleaned_command ? node.raw.cleaned_command : node.command;
    return cmd ? cmd.substring(0, 25) : '';
  }}
  return node.label || '';
}}

function renderGraph() {{
  const nodes = getVisibleNodes().map(n => ({{ ...n }})); // clone for simulation
  const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));

  const rawEdges = getVisibleEdges(nodes);
  const edges = rawEdges.map(e => ({{
    ...e,
    source: nodeById[e.source] || e.source,
    target: nodeById[e.target] || e.target,
  }}));

  document.getElementById('stats').textContent =
    `${{nodes.length}} nodes · ${{edges.length}} edges`;

  // Stop previous simulation
  if (simulation) simulation.stop();

  const svgEl = document.getElementById('svg');
  const W = svgEl.clientWidth || 900;
  const H = svgEl.clientHeight || 600;

  simulation = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(edges).id(n => n.id).distance(80).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide().radius(n => getNodeRadius(n) + 6));

  // Links
  const link = linkGroup.selectAll('.link').data(edges, e => `${{e.source.id}}→${{e.target.id}}`);
  link.exit().remove();
  const linkEnter = link.enter().append('line')
    .attr('class', 'link')
    .attr('marker-end', activeLayer === 'command' ? 'url(#arrow)' : null);
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
    .on('mouseover', (e, n) => showTooltip(e, n))
    .on('mouseout', hideTooltip);

  nodeEnter.append('circle')
    .attr('r', n => getNodeRadius(n))
    .attr('fill', n => getNodeColor(n))
    .attr('stroke', '#0d1117');

  nodeEnter.append('text')
    .attr('dy', n => getNodeRadius(n) + 12)
    .attr('text-anchor', 'middle')
    .text(n => getNodeLabel(n));

  const nodeMerge = nodeEnter.merge(node);
  nodeMerge.select('circle')
    .attr('r', n => getNodeRadius(n))
    .attr('fill', n => getNodeColor(n));
  nodeMerge.select('text').text(n => getNodeLabel(n));

  simulation.on('tick', () => {{
    linkMerge
      .attr('x1', e => e.source.x)
      .attr('y1', e => e.source.y)
      .attr('x2', e => e.target.x)
      .attr('y2', e => e.target.y);
    nodeMerge.attr('transform', n => `translate(${{n.x}},${{n.y}})`);
  }});

  svg.on('click', () => {{ closePanel(); selectedNode = null; nodeGroup.selectAll('.node').classed('selected', false); }});
}}

// ── Detail panel ───────────────────────────────────────────────────────────
function selectNode(node) {{
  selectedNode = node;
  nodeGroup.selectAll('.node').classed('selected', n => n.id === node.id);
  showDetail(node);
}}

function field(label, value, mono=false) {{
  if (!value && value !== 0) return '';
  return `<div class="detail-field">
    <label>${{label}}</label>
    <div class="value${{mono ? ' mono' : ''}}">${{escHtml(String(value))}}</div>
  </div>`;
}}

function badge(text, color) {{
  return `<span class="badge" style="background:${{color}}22;color:${{color}};border:1px solid ${{color}}44">${{escHtml(text)}}</span>`;
}}

function escHtml(s) {{
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}}

function showDetail(node) {{
  const panel = document.getElementById('detail-panel');
  const body  = document.getElementById('detail-body');
  panel.classList.add('visible');

  if (activeLayer === 'command') {{
    const r = node.raw || {{}};
    const m = node.mitre || {{}};
    const c = node.corelang || {{}};
    body.innerHTML = `
      ${{field('Command', r.cleaned_command || node.command, true)}}
      ${{field('Reasoning', node.reasoning)}}
      <div class="detail-field">
        <label>Phase</label>
        <div>${{badge(r.phase || 'unknown', node.color_command)}}</div>
      </div>
      ${{field('Tool', r.tool)}}
      ${{field('Action', r.action)}}
      ${{field('Target', r.target)}}
      <div class="detail-field">
        <label>MITRE</label>
        <div>${{badge(m.technique_id || '?', node.color_mitre)}} ${{escHtml(m.technique_name || '')}}</div>
        <div style="margin-top:4px;font-size:11px;color:#8b949e">${{m.tactic || ''}}</div>
      </div>
      <div class="detail-field">
        <label>coreLang</label>
        <div>${{badge(c.full || '?', node.color_corelang)}}</div>
      </div>
      ${{field('Source File', node.source_file)}}
      ${{field('Agent', node.agent_name)}}
      ${{field('Exit Code', node.exit_code !== null && node.exit_code !== undefined ? node.exit_code : '')}}
      ${{node.output ? field('Output (truncated)', node.output.substring(0, 300), true) : ''}}
    `;
  }} else if (activeLayer === 'mitre') {{
    const cmds = (node.entry_ids || []).map(eid => {{
      const cn = GRAPH.nodes.find(n => n.entry_id === eid);
      if (!cn) return '';
      const cmd = cn.raw && cn.raw.cleaned_command ? cn.raw.cleaned_command : cn.command;
      return `<div class="badge" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;display:block;margin:3px 0;cursor:pointer;font-size:11px" onclick="switchToCommand(${{eid}})">${{escHtml(cmd.substring(0,50))}}</div>`;
    }}).join('');
    body.innerHTML = `
      ${{field('Technique ID', node.technique_id || node.label)}}
      ${{field('Technique Name', node.technique_name)}}
      <div class="detail-field">
        <label>Tactic</label>
        <div>${{badge(node.tactic, node.color)}}</div>
      </div>
      <div class="detail-field">
        <label>Mapped Commands (${{(node.entry_ids||[]).length}})</label>
        ${{cmds}}
      </div>
    `;
  }} else if (activeLayer === 'corelang') {{
    const cmds = (node.entry_ids || []).map(eid => {{
      const cn = GRAPH.nodes.find(n => n.entry_id === eid);
      if (!cn) return '';
      const cmd = cn.raw && cn.raw.cleaned_command ? cn.raw.cleaned_command : cn.command;
      return `<div class="badge" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;display:block;margin:3px 0;cursor:pointer;font-size:11px" onclick="switchToCommand(${{eid}})">${{escHtml(cmd.substring(0,50))}}</div>`;
    }}).join('');
    body.innerHTML = `
      ${{field('Asset', node.asset)}}
      ${{field('Attack Step', node.step)}}
      ${{field('Full', node.full || node.label)}}
      <div class="detail-field">
        <label>Mapped Commands (${{(node.entry_ids||[]).length}})</label>
        ${{cmds}}
      </div>
    `;
  }}
}}

function switchToCommand(eid) {{
  document.querySelectorAll('.layer-btn').forEach(b => {{
    b.classList.toggle('active', b.dataset.layer === 'command');
  }});
  setLayer('command');
  // Highlight the node after render
  setTimeout(() => {{
    const target = GRAPH.nodes.find(n => n.entry_id === eid);
    if (target) {{
      const gNode = nodeGroup.selectAll('.node').filter(n => n.entry_id === eid);
      if (!gNode.empty()) {{
        const d = gNode.datum();
        selectNode(d);
      }}
    }}
  }}, 600);
}}

function closePanel() {{
  document.getElementById('detail-panel').classList.remove('visible');
}}
document.getElementById('close-panel').addEventListener('click', closePanel);

// ── Tooltip ────────────────────────────────────────────────────────────────
const tooltip = document.getElementById('tooltip');
function showTooltip(event, node) {{
  let text = '';
  if (activeLayer === 'command') {{
    const cmd = node.raw && node.raw.cleaned_command ? node.raw.cleaned_command : node.command;
    text = cmd || node.label;
  }} else if (activeLayer === 'mitre') {{
    text = `${{node.label}}: ${{node.technique_name}} (${{node.tactic}})`;
  }} else {{
    text = node.label;
  }}
  tooltip.textContent = text;
  tooltip.style.display = 'block';
  tooltip.style.left = (event.offsetX + 12) + 'px';
  tooltip.style.top  = (event.offsetY - 10) + 'px';
}}
function hideTooltip() {{ tooltip.style.display = 'none'; }}

// ── Legend ─────────────────────────────────────────────────────────────────
function renderLegend() {{
  const title = document.getElementById('legend-title');
  const items = document.getElementById('legend-items');
  let map;

  if (activeLayer === 'command')  {{ title.textContent = 'Phase'; map = COLOR_MAPS.command_phase; }}
  if (activeLayer === 'mitre')    {{ title.textContent = 'Tactic'; map = COLOR_MAPS.mitre_tactic; }}
  if (activeLayer === 'corelang') {{ title.textContent = 'Asset'; map = COLOR_MAPS.corelang_asset; }}

  items.innerHTML = Object.entries(map).map(([k, c]) =>
    `<div class="legend-item">
      <div class="legend-dot" style="background:${{c}}"></div>
      <span>${{k}}</span>
    </div>`
  ).join('');
}}

// ── Init ───────────────────────────────────────────────────────────────────
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
