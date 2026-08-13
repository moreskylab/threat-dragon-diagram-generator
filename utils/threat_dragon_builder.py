import json
import uuid
from typing import Any, Dict, List, Optional, Union


def _make_ports() -> Dict[str, Any]:
    """Generate standard Threat Dragon anchor ports for cells."""
    port_names = ["top", "right", "bottom", "left"]
    groups = {}
    for p in port_names:
        groups[p] = {
            "position": p,
            "attrs": {
                "circle": {
                    "r": 4,
                    "magnet": True,
                    "stroke": "#5F95FF",
                    "strokeWidth": 1,
                    "fill": "#fff",
                    "style": {"visibility": "hidden"},
                }
            },
        }
    return {"groups": groups}


class ThreatDragonModel:
    """Builder and exporter for OWASP Threat Dragon v2 JSON diagram files."""

    def __init__(
        self,
        title: str = "Threat Model",
        owner: str = "Security Team",
        description: str = "Automated Threat Dragon Model",
        diagram_type: str = "STRIDE",
    ):
        self.title = title
        self.owner = owner
        self.description = description
        self.diagram_type = diagram_type

        self.actors: List[Dict[str, Any]] = []
        self.processes: List[Dict[str, Any]] = []
        self.stores: List[Dict[str, Any]] = []
        self.boundaries: List[Dict[str, Any]] = []
        self.flows: List[Dict[str, Any]] = []

        self._element_by_name: Dict[str, Dict[str, Any]] = {}
        self._element_by_id: Dict[str, Dict[str, Any]] = {}

    def _gen_id(self) -> str:
        return str(uuid.uuid4())

    def add_actor(
        self,
        name: str,
        description: str = "",
        provides_authentication: bool = False,
        out_of_scope: bool = False,
        x: Optional[float] = None,
        y: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Add an external Actor/User to the threat model."""
        elem_id = self._gen_id()
        elem = {
            "id": elem_id,
            "shape": "actor",
            "name": name,
            "description": description,
            "providesAuthentication": provides_authentication,
            "outOfScope": out_of_scope,
            "position": {"x": x, "y": y},
            "size": {"width": 112.5, "height": 60},
        }
        self.actors.append(elem)
        self._element_by_name[name] = elem
        self._element_by_id[elem_id] = elem
        return elem

    def add_process(
        self,
        name: str,
        description: str = "",
        out_of_scope: bool = False,
        x: Optional[float] = None,
        y: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Add a Process/Service to the threat model."""
        elem_id = self._gen_id()
        elem = {
            "id": elem_id,
            "shape": "process",
            "name": name,
            "description": description,
            "outOfScope": out_of_scope,
            "position": {"x": x, "y": y},
            "size": {"width": 100, "height": 60},
        }
        self.processes.append(elem)
        self._element_by_name[name] = elem
        self._element_by_id[elem_id] = elem
        return elem

    def add_store(
        self,
        name: str,
        description: str = "",
        is_log: bool = False,
        stores_credentials: bool = False,
        is_encrypted: bool = False,
        is_signed: bool = False,
        out_of_scope: bool = False,
        x: Optional[float] = None,
        y: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Add a Data Store / Database to the threat model."""
        elem_id = self._gen_id()
        elem = {
            "id": elem_id,
            "shape": "store",
            "name": name,
            "description": description,
            "isALog": is_log,
            "storesCredentials": stores_credentials,
            "isEncrypted": is_encrypted,
            "isSigned": is_signed,
            "outOfScope": out_of_scope,
            "position": {"x": x, "y": y},
            "size": {"width": 120, "height": 60},
        }
        self.stores.append(elem)
        self._element_by_name[name] = elem
        self._element_by_id[elem_id] = elem
        return elem

    def add_trust_boundary(
        self,
        name: str,
        description: str = "",
        x: Optional[float] = None,
        y: Optional[float] = None,
        width: Optional[float] = None,
        height: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Add a Trust Boundary box surrounding components."""
        elem_id = self._gen_id()
        elem = {
            "id": elem_id,
            "shape": "trust-boundary-box",
            "name": name,
            "description": description,
            "position": {"x": x, "y": y},
            "size": {"width": width or 300, "height": height or 200},
        }
        self.boundaries.append(elem)
        self._element_by_name[name] = elem
        self._element_by_id[elem_id] = elem
        return elem

    def add_flow(
        self,
        source: Union[str, Dict[str, Any]],
        target: Union[str, Dict[str, Any]],
        name: str,
        description: str = "",
        protocol: str = "HTTPS",
        is_encrypted: bool = True,
        is_bidirectional: bool = False,
        is_public_network: bool = False,
    ) -> Dict[str, Any]:
        """Add a Data Flow between two components."""
        src_id = source["id"] if isinstance(source, dict) else self._resolve_id(source)
        tgt_id = target["id"] if isinstance(target, dict) else self._resolve_id(target)

        flow_id = self._gen_id()
        flow = {
            "id": flow_id,
            "shape": "flow",
            "name": name,
            "description": description,
            "source": src_id,
            "target": tgt_id,
            "protocol": protocol,
            "isEncrypted": is_encrypted,
            "isBidirectional": is_bidirectional,
            "isPublicNetwork": is_public_network,
        }
        self.flows.append(flow)
        return flow

    def _resolve_id(self, identifier: str) -> str:
        """Resolve component ID by name or ID string."""
        if identifier in self._element_by_name:
            return self._element_by_name[identifier]["id"]
        if identifier in self._element_by_id:
            return identifier
        return identifier

    def auto_layout(self) -> None:
        """Compute automatic grid coordinates for nodes without explicit positions."""
        col_actor_x = 100.0
        col_process_x = 350.0
        col_store_x = 600.0
        row_height = 120.0
        start_y = 100.0

        for idx, elem in enumerate(self.actors):
            if elem["position"]["x"] is None or elem["position"]["y"] is None:
                elem["position"] = {"x": col_actor_x, "y": start_y + idx * row_height}

        for idx, elem in enumerate(self.processes):
            if elem["position"]["x"] is None or elem["position"]["y"] is None:
                elem["position"] = {"x": col_process_x, "y": start_y + idx * row_height}

        for idx, elem in enumerate(self.stores):
            if elem["position"]["x"] is None or elem["position"]["y"] is None:
                elem["position"] = {"x": col_store_x, "y": start_y + idx * row_height}

        # Auto position boundaries to encompass processes & stores if unassigned
        for idx, elem in enumerate(self.boundaries):
            if elem["position"]["x"] is None or elem["position"]["y"] is None:
                max_rows = max(len(self.processes), len(self.stores), 1)
                elem["position"] = {"x": col_process_x - 40, "y": start_y - 40}
                elem["size"] = {
                    "width": (col_store_x + 180) - (col_process_x - 40),
                    "height": max_rows * row_height + 60,
                }

    def to_dict(self) -> Dict[str, Any]:
        """Generate OWASP Threat Dragon v2 schema dictionary."""
        self.auto_layout()

        cells: List[Dict[str, Any]] = []

        # 1. Trust Boundaries
        for b in self.boundaries:
            cells.append({
                "id": b["id"],
                "shape": "trust-boundary-box",
                "position": b["position"],
                "size": b["size"],
                "attrs": {
                    "text": {"text": b["name"]},
                    "body": {"stroke": "#ff3333", "strokeDasharray": "5 5", "fill": "transparent"},
                },
                "visible": True,
                "data": {
                    "name": b["name"],
                    "description": b.get("description", ""),
                    "threats": [],
                },
            })

        # 2. Actors
        for a in self.actors:
            cells.append({
                "id": a["id"],
                "shape": "actor",
                "position": a["position"],
                "size": a["size"],
                "attrs": {
                    "text": {"text": a["name"]},
                    "body": {"stroke": "#333333", "strokeWidth": 1.5},
                },
                "visible": True,
                "ports": _make_ports(),
                "data": {
                    "name": a["name"],
                    "description": a.get("description", ""),
                    "providesAuthentication": a.get("providesAuthentication", False),
                    "outOfScope": a.get("outOfScope", False),
                    "hasOpenThreats": False,
                    "threats": [],
                },
            })

        # 3. Processes
        for p in self.processes:
            cells.append({
                "id": p["id"],
                "shape": "process",
                "position": p["position"],
                "size": p["size"],
                "attrs": {
                    "text": {"text": p["name"]},
                    "body": {"stroke": "#333333", "strokeWidth": 1.5},
                },
                "visible": True,
                "ports": _make_ports(),
                "data": {
                    "name": p["name"],
                    "description": p.get("description", ""),
                    "outOfScope": p.get("outOfScope", False),
                    "hasOpenThreats": False,
                    "threats": [],
                },
            })

        # 4. Stores
        for s in self.stores:
            cells.append({
                "id": s["id"],
                "shape": "store",
                "position": s["position"],
                "size": s["size"],
                "attrs": {
                    "text": {"text": s["name"]},
                    "body": {"stroke": "#333333", "strokeWidth": 1.5},
                },
                "visible": True,
                "ports": _make_ports(),
                "data": {
                    "name": s["name"],
                    "description": s.get("description", ""),
                    "isALog": s.get("isALog", False),
                    "storesCredentials": s.get("storesCredentials", False),
                    "isEncrypted": s.get("isEncrypted", False),
                    "isSigned": s.get("isSigned", False),
                    "outOfScope": s.get("outOfScope", False),
                    "hasOpenThreats": False,
                    "threats": [],
                },
            })

        # 5. Flows
        for f in self.flows:
            cells.append({
                "id": f["id"],
                "shape": "flow",
                "source": {"cell": f["source"], "port": "right"},
                "target": {"cell": f["target"], "port": "left"},
                "labels": [{"attrs": {"text": {"text": f["name"]}}}],
                "visible": True,
                "data": {
                    "name": f["name"],
                    "description": f.get("description", ""),
                    "isBidirectional": f.get("isBidirectional", False),
                    "isEncrypted": f.get("isEncrypted", True),
                    "protocol": f.get("protocol", "HTTPS"),
                    "isPublicNetwork": f.get("isPublicNetwork", False),
                    "threats": [],
                },
            })

        schema = {
            "version": "2.6.2",
            "summary": {
                "title": self.title,
                "owner": self.owner,
                "description": self.description,
                "id": 0,
            },
            "detail": {
                "contributors": [],
                "diagrams": [
                    {
                        "id": 0,
                        "title": f"{self.title} ({self.diagram_type})",
                        "diagramType": self.diagram_type,
                        "placeholder": f"{self.title} Architecture Diagram",
                        "thumbnail": "./public/content/images/thumbnail.stride.jpg",
                        "version": "2.6.2",
                        "cells": cells,
                    }
                ],
            },
        }
        return schema

    def to_json(self, filepath: str, indent: int = 2) -> str:
        """Write the model to a JSON file."""
        data = self.to_dict()
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent)
        return filepath


def pytm_to_threat_dragon(tm_instance: Any, title: Optional[str] = None) -> ThreatDragonModel:
    """
    Convert a pytm Threat Model (TM) instance into an OWASP Threat Dragon model.
    Inspects tm_instance elements (Actors, Datastores, Processes/Servers, Boundaries, Dataflows).
    """
    tm_name = getattr(tm_instance, "name", title or "pytm Threat Model")
    tm_desc = getattr(tm_instance, "description", "Converted from pytm model")

    model = ThreatDragonModel(title=tm_name, description=tm_desc)

    # In pytm, elements are registered in Element._elements or tm_instance.elements
    elements = []
    if hasattr(tm_instance, "elements"):
        elements = tm_instance.elements
    elif hasattr(tm_instance, "_elements"):
        elements = tm_instance._elements
    else:
        # Check global Element registry if available
        try:
            from pytm.pytm import Element
            elements = Element._elements
        except Exception:
            elements = []

    # Map pytm elements to ThreatDragon elements
    for elem in elements:
        cls_name = elem.__class__.__name__.lower()
        name = getattr(elem, "name", str(elem))
        desc = getattr(elem, "description", "")
        out_of_scope = getattr(elem, "outOfScope", False)

        if "actor" in cls_name or "externalentity" in cls_name:
            provides_auth = getattr(elem, "providesAuthentication", False)
            model.add_actor(
                name=name,
                description=desc,
                provides_authentication=provides_auth,
                out_of_scope=out_of_scope,
            )
        elif "datastore" in cls_name or "store" in cls_name or "database" in cls_name:
            is_log = getattr(elem, "isALog", False) or getattr(elem, "isLog", False)
            stores_creds = getattr(elem, "storesCredentials", False)
            is_enc = getattr(elem, "isEncrypted", False)
            is_signed = getattr(elem, "isSigned", False)
            model.add_store(
                name=name,
                description=desc,
                is_log=is_log,
                stores_credentials=stores_creds,
                is_encrypted=is_enc,
                is_signed=is_signed,
                out_of_scope=out_of_scope,
            )
        elif "boundary" in cls_name:
            model.add_trust_boundary(name=name, description=desc)
        elif "dataflow" in cls_name or "flow" in cls_name:
            # Flows will be handled in second pass to ensure source/target exist
            pass
        else:
            # Treat other entities (Server, Process, Lambda, SetOfProcesses, etc.) as Process
            model.add_process(name=name, description=desc, out_of_scope=out_of_scope)

    # Second pass for flows
    for elem in elements:
        cls_name = elem.__class__.__name__.lower()
        if "dataflow" in cls_name or "flow" in cls_name:
            name = getattr(elem, "name", "Dataflow")
            desc = getattr(elem, "description", "")
            protocol = getattr(elem, "protocol", "HTTPS")
            is_enc = getattr(elem, "isEncrypted", True)
            is_bi = getattr(elem, "isBidirectional", False)
            is_public = getattr(elem, "isPublicNetwork", False)

            src = getattr(elem, "source", None)
            tgt = getattr(elem, "target", None)
            src_name = getattr(src, "name", str(src)) if src else ""
            tgt_name = getattr(tgt, "name", str(tgt)) if tgt else ""

            if src_name and tgt_name:
                model.add_flow(
                    source=src_name,
                    target=tgt_name,
                    name=name,
                    description=desc,
                    protocol=protocol,
                    is_encrypted=is_enc,
                    is_bidirectional=is_bi,
                    is_public_network=is_public,
                )

    return model
