from copy import deepcopy
import pytest
from icheck.services.monitoring_dashboard_merge import merge_panels


def panel(identifier, query, title="Panel"):
    return {"id": identifier, "title": title, "type": "timeseries", "targets": [{"expr": query}],
            "gridPos": {"x": 0, "y": 0, "w": 12, "h": 8}}


def test_new_metrics_preserve_operator_panels_display_and_variables():
    old = {"metadata": {"resourceVersion": "7"}, "spec": {"title": "My dashboard", "panels": [panel(5, "old_metric", "Hand tuned")],
        "refresh": "1m", "time": {"from": "now-1h", "to": "now"}, "templating": {"list": []}}}
    before = deepcopy(old)
    result = merge_panels(old, {"title": "Generated", "panels": [panel(1, "old_metric"), panel(2, "new_metric")]})
    assert result["title"] == "My dashboard" and result["refresh"] == "1m"
    assert result["time"] == old["spec"]["time"] and result["templating"] == old["spec"]["templating"]
    assert result["panels"][0] == old["spec"]["panels"][0]
    assert result["panels"][1]["id"] == 6 and result["panels"][1]["gridPos"]["y"] == 8
    assert old == before
    assert merge_panels({"spec": result}, {"panels": [panel(2, "new_metric")]}) == result


def test_panel_limit_fails_instead_of_silently_removing_existing_content():
    with pytest.raises(ValueError, match="separate dashboard"):
        merge_panels({"spec": {"title": "Full", "panels": [panel(i, f"metric_{i}") for i in range(20)]}},
                     {"panels": [panel(99, "new_metric")]})
