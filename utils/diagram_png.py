import os
import sys
import shutil
from typing import Optional, Dict, Any, List
from utils.threat_dragon_builder import ThreatDragonModel


def _find_and_add_graphviz_to_path() -> bool:
    """Check if dot/graphviz exists in PATH, or search common installation paths on Windows."""
    if shutil.which("dot"):
        return True

    candidate_paths = [
        r"C:\Program Files\Graphviz\bin",
        r"C:\Program Files (x86)\Graphviz\bin",
        r"C:\ProgramData\chocolatey\bin",
        r"C:\ProgramData\chocolatey\lib\Graphviz\tools\Graphviz\bin",
        os.path.expandvars(r"%LOCALAPPDATA%\Programs\Graphviz\bin"),
        os.path.expandvars(r"%USERPROFILE%\scoop\apps\graphviz\current\bin"),
    ]

    for p in candidate_paths:
        if os.path.exists(p) and os.path.exists(os.path.join(p, "dot.exe")):
            os.environ["PATH"] = p + os.pathsep + os.environ.get("PATH", "")
            if shutil.which("dot"):
                return True
    return False


def render_svg_fallback(model: ThreatDragonModel, output_filename: str) -> str:
    """Generate a clean, standalone SVG architecture diagram without requiring Graphviz."""
    base_name = output_filename
    if base_name.endswith(".png") or base_name.endswith(".svg"):
        base_name = os.path.splitext(base_name)[0]

    svg_path = f"{base_name}.svg"
    out_dir = os.path.dirname(svg_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    model.auto_layout()

    # Calculate canvas bounds
    all_x = [elem["position"]["x"] + elem["size"]["width"] for elem in model.actors + model.processes + model.stores]
    all_y = [elem["position"]["y"] + elem["size"]["height"] for elem in model.actors + model.processes + model.stores]
    width = max(max(all_x, default=800) + 150, 950)
    height = max(max(all_y, default=600) + 150, 650)

    svg_lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" style="background-color: #0f172a; font-family: -apple-system, BlinkMacSystemFont, \'Segoe UI\', Roboto, sans-serif;">',
        '  <defs>',
        '    <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">',
        '      <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />',
        '    </marker>',
        '    <filter id="shadow" x="-5%" y="-5%" width="110%" height="110%">',
        '      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#000000" flood-opacity="0.3" />',
        '    </filter>',
        '  </defs>',
        f'  <text x="30" y="45" fill="#f8fafc" font-size="22" font-weight="bold">{model.title}</text>',
        f'  <text x="30" y="70" fill="#94a3b8" font-size="13">{model.description}</text>',
    ]

    # 1. Trust Boundaries
    for b in model.boundaries:
        bx = b["position"]["x"]
        by = b["position"]["y"]
        bw = b["size"]["width"]
        bh = b["size"]["height"]
        svg_lines.append(
            f'  <rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="12" fill="#1e293b" fill-opacity="0.6" stroke="#ef4444" stroke-width="2" stroke-dasharray="6 4" />'
        )
        svg_lines.append(
            f'  <text x="{bx + 15}" y="{by + 25}" fill="#ef4444" font-size="12" font-weight="bold">🔒 Trust Boundary: {b["name"]}</text>'
        )

    # 2. Flows (Lines)
    for f in model.flows:
        src = model._element_by_id.get(f["source"])
        tgt = model._element_by_id.get(f["target"])
        if src and tgt:
            x1 = src["position"]["x"] + src["size"]["width"]
            y1 = src["position"]["y"] + src["size"]["height"] / 2
            x2 = tgt["position"]["x"]
            y2 = tgt["position"]["y"] + tgt["size"]["height"] / 2

            stroke_color = "#38bdf8" if f.get("isEncrypted", True) else "#f87171"
            dash = 'stroke-dasharray="4 2"' if not f.get("isEncrypted", True) else ""

            # Curve path
            cx1 = x1 + (x2 - x1) / 2
            cy1 = y1
            cx2 = x1 + (x2 - x1) / 2
            cy2 = y2
            svg_lines.append(
                f'  <path d="M {x1} {y1} C {cx1} {cy1}, {cx2} {cy2}, {x2} {y2}" fill="none" stroke="{stroke_color}" stroke-width="2" marker-end="url(#arrow)" {dash} />'
            )
            mid_x = (x1 + x2) / 2
            mid_y = (y1 + y2) / 2 - 8
            proto = f" ({f['protocol']})" if f.get("protocol") else ""
            svg_lines.append(
                f'  <text x="{mid_x}" y="{mid_y}" fill="#cbd5e1" font-size="10" text-anchor="middle" background="#0f172a">{f["name"]}{proto}</text>'
            )

    # 3. Actors (External Users)
    for a in model.actors:
        x, y = a["position"]["x"], a["position"]["y"]
        w, h = a["size"]["width"], a["size"]["height"]
        svg_lines.append(
            f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#334155" stroke="#38bdf8" stroke-width="2" filter="url(#shadow)" />'
        )
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 24}" fill="#f8fafc" font-size="12" font-weight="bold" text-anchor="middle">👤 {a["name"]}</text>')
        auth_txt = "Auth" if a.get("providesAuthentication") else "Unauthenticated"
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 44}" fill="#94a3b8" font-size="10" text-anchor="middle">{auth_txt}</text>')

    # 4. Processes
    for p in model.processes:
        x, y = p["position"]["x"], p["position"]["y"]
        w, h = p["size"]["width"], p["size"]["height"]
        svg_lines.append(
            f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#1e293b" stroke="#10b981" stroke-width="2" filter="url(#shadow)" />'
        )
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 24}" fill="#f8fafc" font-size="12" font-weight="bold" text-anchor="middle">⚙️ {p["name"]}</text>')
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 44}" fill="#94a3b8" font-size="10" text-anchor="middle">Process</text>')

    # 5. Data Stores
    for s in model.stores:
        x, y = s["position"]["x"], s["position"]["y"]
        w, h = s["size"]["width"], s["size"]["height"]
        svg_lines.append(
            f'  <rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" fill="#1e293b" stroke="#a855f7" stroke-width="2" filter="url(#shadow)" />'
        )
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 24}" fill="#f8fafc" font-size="12" font-weight="bold" text-anchor="middle">🗄️ {s["name"]}</text>')
        enc_txt = "Encrypted" if s.get("isEncrypted") else "Plaintext"
        svg_lines.append(f'  <text x="{x + w/2}" y="{y + 44}" fill="#94a3b8" font-size="10" text-anchor="middle">{enc_txt}</text>')

    svg_lines.append("</svg>")

    with open(svg_path, "w", encoding="utf-8") as f:
        f.write("\n".join(svg_lines))

    print(f"[INFO] Standalone SVG architecture diagram generated: {svg_path}")
    return svg_path


def render_png_diagram(
    model: ThreatDragonModel,
    output_filename: str = "architecture_diagram",
    show: bool = False,
    direction: str = "LR",
) -> Optional[str]:
    """
    Render a PNG architecture diagram for a ThreatDragonModel using the `diagrams` python package.
    Automatically checks and adds Graphviz to PATH if present on system, with graceful SVG fallback.
    """
    # 1. Attempt to find and configure Graphviz
    has_graphviz = _find_and_add_graphviz_to_path()

    base_name = output_filename
    if base_name.endswith(".png"):
        base_name = base_name[:-4]

    out_dir = os.path.dirname(base_name)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    if not has_graphviz:
        print(
            "\n[NOTICE] Graphviz executable 'dot' is not in system PATH.\n"
            "To enable native PNG rendering via 'diagrams', install Graphviz:\n"
            "  - Windows: winget install Graphviz.Graphviz\n"
            "  - macOS:   brew install graphviz\n"
            "  - Linux:   sudo apt-get install graphviz\n"
        )
        # Generate standalone SVG diagram as zero-dependency fallback
        svg_path = render_svg_fallback(model, output_filename=base_name)
        return svg_path

    try:
        from diagrams import Diagram, Cluster, Edge
        from diagrams.onprem.client import User
        from diagrams.onprem.compute import Server
        from diagrams.onprem.database import PostgreSQL
    except ImportError:
        print("[WARNING] 'diagrams' package not installed. Generating SVG fallback.")
        return render_svg_fallback(model, output_filename=base_name)

    try:
        with Diagram(
            name=model.title,
            filename=base_name,
            show=show,
            direction=direction,
            outformat="png",
        ):
            node_map = {}

            # 1. Actors (External Users)
            for actor in model.actors:
                label = f"{actor['name']}\n(Actor)"
                if actor.get("providesAuthentication"):
                    label += "\n[Auth]"
                node_map[actor["id"]] = User(label)
                node_map[actor["name"]] = node_map[actor["id"]]

            # 2. Internal / Trust Boundary Clusters
            if model.boundaries:
                for tb in model.boundaries:
                    with Cluster(f"Trust Boundary: {tb['name']}"):
                        for proc in model.processes:
                            label = f"{proc['name']}\n(Process)"
                            node_map[proc["id"]] = Server(label)
                            node_map[proc["name"]] = node_map[proc["id"]]

                        for store in model.stores:
                            label = f"{store['name']}\n(Data Store)"
                            if store.get("isEncrypted"):
                                label += "\n[Encrypted]"
                            node_map[store["id"]] = PostgreSQL(label)
                            node_map[store["name"]] = node_map[store["id"]]
            else:
                for proc in model.processes:
                    label = f"{proc['name']}\n(Process)"
                    node_map[proc["id"]] = Server(label)
                    node_map[proc["name"]] = node_map[proc["id"]]

                for store in model.stores:
                    label = f"{store['name']}\n(Data Store)"
                    if store.get("isEncrypted"):
                        label += "\n[Encrypted]"
                    node_map[store["id"]] = PostgreSQL(label)
                    node_map[store["name"]] = node_map[store["id"]]

            # 3. Flows / Edges
            for flow in model.flows:
                src_node = node_map.get(flow["source"])
                tgt_node = node_map.get(flow["target"])

                if src_node and tgt_node:
                    edge_label = flow["name"]
                    proto = flow.get("protocol")
                    if proto:
                        edge_label += f" ({proto})"

                    color = "blue" if flow.get("isEncrypted", True) else "red"
                    style = "solid" if not flow.get("isBidirectional") else "bold"

                    edge = Edge(label=edge_label, color=color, style=style)
                    if flow.get("isBidirectional"):
                        src_node - edge - tgt_node
                    else:
                        src_node >> edge >> tgt_node

        png_path = f"{base_name}.png"
        print(f"[INFO] PNG diagram successfully generated: {png_path}")
        return png_path

    except Exception as e:
        err_msg = str(e)
        if "dot" in err_msg or "executable" in err_msg.lower():
            print(
                "\n[NOTICE] Graphviz 'dot' executable was not found by the diagrams package.\n"
                "Generating standalone SVG architecture diagram as fallback..."
            )
            return render_svg_fallback(model, output_filename=base_name)
        else:
            print(f"[ERROR] Failed to generate PNG diagram: {e}")
            return render_svg_fallback(model, output_filename=base_name)
