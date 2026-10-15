"""Append newly requested panels without overwriting an operator's dashboard."""
from copy import deepcopy


def merge_panels(existing, proposed):
    if existing is None:
        return deepcopy(proposed)
    current = deepcopy(existing.get("spec", existing))
    # Resource metadata is not part of native Grafana's dashboard definition.
    for key in ("id", "uid", "version"):
        current.pop(key, None)
    panels = current.get("panels")
    if not isinstance(panels, list):
        raise ValueError("Existing dashboard has no valid panel collection")
    ids = [panel.get("id") for panel in panels]
    if any(type(value) is not int for value in ids) or len(set(ids)) != len(ids):
        raise ValueError("Existing dashboard panel IDs are invalid")
    def queries(panel):
        return tuple(sorted(target.get("expr", "") for target in panel.get("targets", []) if isinstance(target, dict)))
    known = {queries(panel) for panel in panels if queries(panel)}
    next_id = max(ids, default=0) + 1
    bottom = max((panel.get("gridPos", {}).get("y", 0) + panel.get("gridPos", {}).get("h", 8) for panel in panels), default=0)
    for panel in proposed.get("panels", []):
        expressions = queries(panel)
        if expressions and expressions in known:
            continue
        if len(panels) >= 20:
            raise ValueError("Dashboard already has 20 panels; choose a separate dashboard instead of discarding existing panels")
        added = deepcopy(panel)
        added["id"] = next_id; next_id += 1
        added["gridPos"] = {"x": 0, "y": bottom, "w": 24, "h": 8}; bottom += 8
        panels.append(added); known.add(expressions)
    current["panels"] = panels
    return current
