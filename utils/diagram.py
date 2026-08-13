import json
import os
from typing import Any, Dict, List, Optional, Tuple


class DiagramHandler:
    flow_type = "flow"
    actor_type = "actor"
    process_type = "process"
    store_type = "store"
    trust_boundary_curve_type = "trust-boundary-curve"
    trust_boundary_box_type = "trust-boundary-box"

    # Known type aliases from different versions/formats of Threat Dragon
    TYPE_ALIASES = {
        "trust-broundary-curve": "trust-boundary-curve",
        "tm.Boundary": "trust-boundary-box",
        "tm.Flow": "flow",
        "tm.Actor": "actor",
        "tm.Process": "process",
        "tm.Store": "store",
    }

    def __init__(self, filename: str, diagram_index: int = 0):
        self.filename = filename
        self.diagram_index = diagram_index
        self.diagram_title = ""
        self.diagram_type = "STRIDE"
        self.raw_data: Dict[str, Any] = {}
        self.components: List[Dict[str, Any]] = []
        self.flows: List[Dict[str, Any]] = []
        self.trust_boundaries: List[Dict[str, Any]] = []
        self.component_map: Dict[str, Dict[str, Any]] = {}

        self.component_sentence_handler_map = {
            self.flow_type: self.make_flow_sentence,
            self.actor_type: self.make_actor_sentence,
            self.process_type: self.make_process_sentence,
            self.store_type: self.make_store_sentence,
            self.trust_boundary_curve_type: self.make_trust_boundary_sentence,
            self.trust_boundary_box_type: self.make_trust_boundary_sentence,
        }

    def _normalize_shape(self, shape: str) -> str:
        """Normalize shape names across Threat Dragon versions."""
        return self.TYPE_ALIASES.get(shape, shape)

    def read_data(self) -> None:
        """Read and parse the Threat Dragon JSON file."""
        if not os.path.exists(self.filename):
            raise FileNotFoundError(f"Diagram file not found: {self.filename}")

        with open(self.filename, "r", encoding="utf-8") as f:
            self.raw_data = json.load(f)

        diagrams = self.raw_data.get("detail", {}).get("diagrams", [])
        if not diagrams:
            raise ValueError("No diagrams found in the provided JSON file.")

        if self.diagram_index >= len(diagrams):
            raise IndexError(
                f"Diagram index {self.diagram_index} out of range (found {len(diagrams)} diagram(s))."
            )

        diagram = diagrams[self.diagram_index]
        self.diagram_title = diagram.get("title", f"Diagram {self.diagram_index + 1}")
        self.diagram_type = diagram.get("diagramType", "STRIDE")

        self.components = []
        self.flows = []
        self.trust_boundaries = []
        self.component_map = {}

        cells = diagram.get("cells", [])
        for comp in cells:
            shape = self._normalize_shape(comp.get("shape", ""))
            data = comp.get("data", {})
            if not isinstance(data, dict):
                data = {}

            # Skip out-of-scope elements (unless they are trust boundaries)
            is_tb = shape in (self.trust_boundary_box_type, self.trust_boundary_curve_type)
            if not is_tb and data.get("outOfScope", False):
                continue

            comp_id = str(comp.get("id", ""))
            name = data.get("name") or comp.get("attrs", {}).get("text", {}).get("text", "") or "Unnamed Component"
            description = data.get("description", "")

            new_comp: Dict[str, Any] = {
                "id": comp_id,
                "type": shape,
                "name": name.strip(),
                "description": description.strip(),
                "data": data,
            }

            if shape == self.trust_boundary_curve_type:
                vertices = []
                if "source" in comp and isinstance(comp["source"], dict):
                    vertices.append(comp["source"])
                for point in comp.get("vertices", []):
                    if isinstance(point, dict):
                        vertices.append(point)
                if "target" in comp and isinstance(comp["target"], dict):
                    vertices.append(comp["target"])
                new_comp["vertices"] = vertices
                self.trust_boundaries.append(new_comp)

            elif shape == self.trust_boundary_box_type:
                new_comp["position"] = comp.get("position", {"x": 0, "y": 0})
                new_comp["size"] = comp.get("size", {"width": 0, "height": 0})
                self.trust_boundaries.append(new_comp)

            elif shape == self.flow_type:
                source_cell = comp.get("source", {}).get("cell") if isinstance(comp.get("source"), dict) else None
                target_cell = comp.get("target", {}).get("cell") if isinstance(comp.get("target"), dict) else None
                new_comp["source"] = str(source_cell) if source_cell is not None else ""
                new_comp["target"] = str(target_cell) if target_cell is not None else ""
                new_comp["isBidirectional"] = data.get("isBidirectional", False)
                new_comp["isEncrypted"] = data.get("isEncrypted", False)
                new_comp["protocol"] = data.get("protocol", "")
                new_comp["isPublicNetwork"] = data.get("isPublicNetwork", False)
                new_comp["preventive_measures"] = data.get("preventive_measures", "")
                self.flows.append(new_comp)

            else:
                new_comp["position"] = comp.get("position", {"x": 0, "y": 0})
                new_comp["size"] = comp.get("size", {"width": 0, "height": 0})
                new_comp["flow"] = []

                if shape == self.actor_type:
                    new_comp["providesAuthentication"] = data.get("providesAuthentication", False)
                elif shape == self.store_type:
                    new_comp["isALog"] = data.get("isALog", False)
                    new_comp["storesCredentials"] = data.get("storesCredentials", False)
                    new_comp["isEncrypted"] = data.get("isEncrypted", False)
                    new_comp["isSigned"] = data.get("isSigned", False)

                self.components.append(new_comp)
                self.component_map[comp_id] = new_comp

    def link_flows(self) -> None:
        """Attach flows to their corresponding source components and populate target names."""
        for flow in self.flows:
            source_id = flow.get("source", "")
            target_id = flow.get("target", "")

            target_comp = self.component_map.get(target_id)
            target_name = target_comp["name"] if target_comp else f"External Entity ({target_id})"
            flow["target_name"] = target_name

            source_comp = self.component_map.get(source_id)
            if source_comp and "flow" in source_comp:
                source_comp["flow"].append(flow)

    def sort_components(self) -> None:
        """Sort components logically: Actors -> Processes -> Stores -> Trust Boundaries."""
        type_order = {
            self.actor_type: 0,
            self.process_type: 1,
            self.store_type: 2,
            self.trust_boundary_box_type: 3,
            self.trust_boundary_curve_type: 3,
        }
        self.components.sort(key=lambda c: type_order.get(c.get("type", ""), 99))

    def make_flow_sentence(self, flow_arr: List[Dict[str, Any]]) -> str:
        """Generate descriptive text for data flows originating from a component."""
        if not flow_arr:
            return ""

        parts = []
        for idx, flow in enumerate(flow_arr):
            prefix = "It also" if idx > 0 else "It"
            way = "bidirectional" if flow.get("isBidirectional") else "directional"
            flow_name = flow.get("name") or "data flow"
            desc = flow.get("description", "")
            protocol = flow.get("protocol", "")

            details = []
            if desc:
                details.append(f"described as {desc}")
            if protocol:
                details.append(f"{protocol} protocol")

            details_str = f" ({', '.join(details)})" if details else ""
            encrypted_text = "encrypted" if flow.get("isEncrypted") else "unencrypted"
            network_text = "public" if flow.get("isPublicNetwork") else "private"

            flow_sentence = (
                f"{prefix} interacts in a {way} manner with \"{flow.get('target_name', 'Unknown')}\" "
                f"via {flow_name}{details_str}, which is {encrypted_text} over a {network_text} network"
            )
            parts.append(flow_sentence)

        return ". " + ". ".join(parts)

    def intro_sentence(self, comp: Dict[str, Any]) -> str:
        """Generate base introductory sentence for a component."""
        sentence = f"The \"{comp['name']}\""
        if comp.get("description"):
            sentence += f", described as {comp['description']}"
        return sentence

    def format_sentence(self, sentence: str) -> str:
        """Clean sentence formatting."""
        cleaned = sentence.strip().replace("\n", " ")
        if not cleaned.endswith((".", ";")):
            cleaned += "."
        return cleaned + "\n"

    def make_actor_sentence(self, comp: Dict[str, Any]) -> str:
        """Describe an external actor / user."""
        sentence = self.intro_sentence(comp)
        if comp.get("providesAuthentication"):
            sentence += ", which provides authentication credentials"
        else:
            sentence += ", which does not provide authentication credentials"

        flow_sentence = self.make_flow_sentence(comp.get("flow", []))
        sentence += flow_sentence
        return self.format_sentence(sentence)

    def make_process_sentence(self, comp: Dict[str, Any]) -> str:
        """Describe a software process or service."""
        sentence = self.intro_sentence(comp)
        flow_sentence = self.make_flow_sentence(comp.get("flow", []))
        sentence += flow_sentence
        return self.format_sentence(sentence)

    def make_store_sentence(self, comp: Dict[str, Any]) -> str:
        """Describe a data store or database."""
        sentence = self.intro_sentence(comp)
        used_for: List[str] = []
        states: List[str] = []

        if comp.get("isALog"):
            used_for.append("log data storage")
        if comp.get("storesCredentials"):
            used_for.append("storing credentials")
        if comp.get("isEncrypted"):
            states.append("encrypted at rest")
        if comp.get("isSigned"):
            states.append("cryptographically signed")

        attrs = []
        if used_for:
            attrs.append("used for " + " and ".join(used_for))
        if states:
            attrs.append("is " + " and ".join(states))

        if attrs:
            sentence += ", which " + " and ".join(attrs)

        flow_sentence = self.make_flow_sentence(comp.get("flow", []))
        sentence += flow_sentence
        return self.format_sentence(sentence)

    def is_outside_of_tb_box(
        self, comp_pos: Dict[str, float], box_pos: Dict[str, float], box_size: Dict[str, float]
    ) -> bool:
        """Check if component position lies outside a rectangular trust boundary."""
        cx, cy = comp_pos.get("x", 0), comp_pos.get("y", 0)
        bx, by = box_pos.get("x", 0), box_pos.get("y", 0)
        bw, bh = box_size.get("width", 0), box_size.get("height", 0)

        is_inside = (bx <= cx <= bx + bw) and (by <= cy <= by + bh)
        return not is_inside

    def is_outside_of_tb_curve(
        self, comp_pos: Dict[str, float], vertices: List[Dict[str, float]]
    ) -> bool:
        """Use cross-product / winding logic to determine if a point is outside the trust boundary curve."""
        if len(vertices) < 2:
            return True

        def cross_product(v1: Tuple[float, float], v2: Tuple[float, float]) -> float:
            return v1[0] * v2[1] - v1[1] * v2[0]

        cx, cy = comp_pos.get("x", 0), comp_pos.get("y", 0)
        is_right = 0

        for i in range(len(vertices) - 1):
            v1 = (vertices[i].get("x", 0) - cx, vertices[i].get("y", 0) - cy)
            v2 = (vertices[i + 1].get("x", 0) - cx, vertices[i + 1].get("y", 0) - cy)
            cross = cross_product(v1, v2)
            if cross >= 0:
                is_right += 1
            else:
                is_right -= 1

        # Check closing segment
        v1 = (vertices[-1].get("x", 0) - cx, vertices[-1].get("y", 0) - cy)
        v2 = (vertices[0].get("x", 0) - cx, vertices[0].get("y", 0) - cy)
        cross = cross_product(v1, v2)
        if cross >= 0:
            is_right += 1
        else:
            is_right -= 1

        if is_right == len(vertices) or is_right == -len(vertices):
            return False  # Point lies on or inside boundary
        return is_right > 0

    def make_trust_boundary_sentence(self, tb: Dict[str, Any]) -> str:
        """Describe trust boundary separating inside and outside components."""
        sentence = self.intro_sentence(tb)
        outside: List[str] = []
        inside: List[str] = []

        for comp in self.components:
            pos = comp.get("position", {"x": 0, "y": 0})
            if tb.get("type") == self.trust_boundary_curve_type:
                is_outside = self.is_outside_of_tb_curve(pos, tb.get("vertices", []))
            else:
                is_outside = self.is_outside_of_tb_box(
                    pos, tb.get("position", {"x": 0, "y": 0}), tb.get("size", {"width": 0, "height": 0})
                )

            if is_outside:
                outside.append(comp["name"])
            else:
                inside.append(comp["name"])

        format_comps = lambda lst: " and ".join(f'"{x}"' for x in lst) if lst else "none"
        outside_str = format_comps(outside)
        inside_str = format_comps(inside)

        sentence += f" is a trust boundary that separates {outside_str} (outside trust zone) from {inside_str} (inside trust zone)"
        return self.format_sentence(sentence)

    def make_sentence(self) -> str:
        """Parse diagram and construct the complete threat modeling prompt for LLM."""
        self.read_data()
        self.link_flows()
        self.sort_components()

        # Combine components and trust boundaries for sentence generation
        all_elements = self.components + self.trust_boundaries

        introduction = (
            f"I will describe the architecture components of '{self.diagram_title}' "
            f"and I need your help to perform a comprehensive threat modeling analysis on this scenario.\n\n"
            f"Components & Architecture Overview:\n"
        )

        comp_sentences = []
        for idx, elem in enumerate(all_elements, start=1):
            handler = self.component_sentence_handler_map.get(elem.get("type", ""))
            if handler:
                c_sentence = handler(elem)
                comp_sentences.append(f"{idx}. {c_sentence}")

        last_sentence = (
            f"\nBased on the given scenario, perform a structured threat model using the {self.diagram_type} methodology. "
            f"For each threat, identify:\n"
            f"- Threat Category ({self.diagram_type})\n"
            f"- Affected Component / Flow\n"
            f"- Threat Description & Impact\n"
            f"- Severity / Risk Level\n"
            f"- Recommended Mitigation & Preventive Measures"
        )

        return introduction + "".join(comp_sentences) + last_sentence