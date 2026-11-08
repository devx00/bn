from __future__ import annotations

from copy import deepcopy
from types import SimpleNamespace

import pytest

from _bridge_fakes import _load_bridge


class ProjectContext:
    def __init__(self, metadata=None):
        self._metadata = metadata or {"complete": True, "truncated": False, "boundaries": []}

    def metadata(self):
        return self._metadata

    def identity(self, bv, function=None, address=None):
        return {"project_file_id": "consumer", "project_path": "bin/consumer"}

    def annotate(self, result):
        result["project_analysis"] = self.metadata()
        return result


def _analysis(direction="backward"):
    result = {
        "direction": direction, "leaves": [], "assumptions": [],
        "stats": {"truncated": False, "truncation_cause": [], "leaves": 0,
                  "functions_visited": 3},
    }
    if direction == "backward":
        result.update(
            slices=[{
                "sink": {"address": "0x1010", "project_file_id": "consumer"},
                "origin": {"kind": "parameter", "index": 0,
                           "project_file_id": "provider", "project_path": "lib/provider.so"},
                "slice": [
                    {"address": "0x1000", "op": "MLIL_CALL_SSA", "text": "provider()",
                     "project_file_id": "consumer", "project_path": "bin/consumer",
                     "target": {"address": "0x1000", "project_file_id": "provider"}},
                    {"address": "0x1000", "op": "MLIL_RET", "text": "return arg1",
                     "project_file_id": "provider", "project_path": "lib/provider.so"},
                ],
            }],
            sink_status=[{"seeded": True}],
            diagnostics={"sinks_seeded": 1, "safe_to_report_complete_slice": True},
        )
    else:
        result.update(reached_sinks=[], diagnostics={
            "source_callsites": 2, "tainted_values": 4,
            "safe_to_report_all_clear": True, "all_clear_caveats": ["old caveat"],
            "frontier": {"by_kind": {}},
        })
    return result


@pytest.mark.parametrize("direction", ["forward", "backward"])
@pytest.mark.parametrize("truncated", [False, True])
def test_project_boundaries_preserve_counters_and_block_claims(monkeypatch, direction, truncated):
    rts = _load_bridge(monkeypatch).read_taint_slice
    result = _analysis(direction)
    result["stats"]["truncation_cause"] = ["max_depth"]
    metadata = {"complete": False, "truncated": truncated, "boundaries": [
        {"reason": "provider_missing", "project_file_id": "provider", "address": "0x1000"}]}
    assert rts.apply_project_boundaries(result, metadata) is result
    first = deepcopy(result)
    rts.apply_project_boundaries(result, metadata)
    assert result == first
    assert result["stats"]["functions_visited"] == 3
    assert result["stats"]["analysis_incomplete"] is True
    assert result["stats"]["truncated"] is truncated
    assert result["stats"]["truncation_cause"] == (["max_depth", "project"] if truncated else ["max_depth"])
    assert result["stats"]["leaves"] == 1
    assert result["leaves"][0]["project_file_id"] == "provider"
    claim = "safe_to_report_all_clear" if direction == "forward" else "safe_to_report_complete_slice"
    assert result["diagnostics"][claim] is False
    if direction == "forward":
        assert result["diagnostics"]["source_callsites"] == 2
        assert result["diagnostics"]["tainted_values"] == 4
        assert result["diagnostics"]["all_clear_caveats"] == []


def test_complete_project_metadata_does_not_change_result(monkeypatch):
    rts = _load_bridge(monkeypatch).read_taint_slice
    result = _analysis()
    before = deepcopy(result)
    rts.apply_project_boundaries(result, ProjectContext().metadata())
    assert result == before


def test_incomplete_project_without_boundary_still_blocks_claim(monkeypatch):
    rts = _load_bridge(monkeypatch).read_taint_slice
    result = _analysis()
    rts.apply_project_boundaries(result, {"complete": False, "truncated": False, "boundaries": []})
    assert result["leaves"][0]["reason"] == "project_analysis_incomplete"
    assert result["diagnostics"]["safe_to_report_complete_slice"] is False


@pytest.mark.parametrize("project", [False, True])
def test_taint_reader_passes_context_only_for_project(monkeypatch, project):
    rts = _load_bridge(monkeypatch).read_taint_slice
    bv = object()
    context = ProjectContext() if project else None
    seen = {}

    class Engine:
        def __init__(self, view, models, **kwargs):
            assert view is bv
            seen.update(kwargs)

        def forward(self, func, locators, **kwargs):
            return _analysis("forward")

    monkeypatch.setattr(rts, "current", lambda view: context)
    monkeypatch.setattr(rts, "require_analysis", lambda *args: None)
    monkeypatch.setattr(rts, "_analysis_state_fields", lambda view: {})
    monkeypatch.setattr(rts._taint, "TaintEngine", Engine)
    ctx = SimpleNamespace(_resolve_view=lambda selector: bv,
                          _find_function=lambda view, name: SimpleNamespace(name=name, start=0x1000))
    rts._taint_op(ctx, None, {"function": "consumer", "sources": ["param:0"]})
    if project:
        assert seen["project_context"] is context
    else:
        assert "project_context" not in seen


@pytest.mark.parametrize("step_limit, truncated", [(3, False), (2, True)])
def test_project_trace_uses_exact_engine_sink_and_keeps_file_provenance(monkeypatch, step_limit, truncated):
    rts = _load_bridge(monkeypatch).read_taint_slice
    project = ProjectContext()
    bv = object()
    func = SimpleNamespace(name="consumer", start=0x1000)
    calls = []

    class Engine:
        def __init__(self, view, models, **kwargs):
            assert view is bv
            assert kwargs["project_context"] is project

        def backward(self, function, sinks, **kwargs):
            calls.append((function, sinks, kwargs))
            return _analysis()

    monkeypatch.setattr(rts._taint, "TaintEngine", Engine)
    result = rts._project_backward_slice(
        None, bv, func, project, target_addr=0x1010, arg_index=1,
        arg_label={"callee": "consume", "index": 1}, view="mlil",
        max_depth=step_limit, ip_depth=4, mangled=False, hints=[])
    assert calls == [(func, [{"kind": "arg", "callee": "consume", "index": 1,
                              "address": "0x1010"}], {"max_depth": 4})]
    assert [step["project_file_id"] for step in result["trace"][:2]] == ["consumer", "provider"]
    assert result["trace"][0]["target"]["project_file_id"] == "provider"
    assert result["truncated"] is truncated
    assert result["step_count"] == step_limit
    if truncated:
        assert "trace_steps" in result["stats"]["truncation_cause"]
        assert result["diagnostics"]["safe_to_report_complete_slice"] is False
    else:
        assert result["frontiers"][0]["examples"][0]["project_file_id"] == "provider"


def test_noninterprocedural_trace_does_not_consult_project_context(monkeypatch):
    from _bridge_fakes import _FakeBV, _FakeFunction, _FakeMLILFunction, _FakeMLILInsn, _FakeSSAVariable

    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    var = _FakeSSAVariable("r0#1")
    call = _FakeMLILInsn(0x1010, operation="MLIL_CALL_SSA", params=[
        _FakeMLILInsn(0x1010, operation="MLIL_VAR_SSA", vars_read=[var])], vars_read=[var])
    func = _FakeFunction(0x1000, "consumer")
    func.medium_level_il = _FakeMLILFunction(instructions=[call], definitions={})
    bv = _FakeBV(functions=[func])
    monkeypatch.setattr(instance.ctx, "_resolve_view", lambda selector: bv)

    def unexpected_context(view):
        pytest.fail("default trace must not enter project analysis")

    monkeypatch.setattr(bridge.read_taint_slice, "current", unexpected_context)
    result = instance._backward_slice("active", "consumer", "0x1010")
    assert "project_analysis" not in result
    assert result["interprocedural"] is False
