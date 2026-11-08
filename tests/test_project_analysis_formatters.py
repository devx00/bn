from __future__ import annotations

import copy
import json

import pytest

from bn.formatters import (
    _render_callgraph_text,
    _render_callsites_text,
    _render_taint_text,
    _render_trace_text,
    _render_xrefs_any_text,
    _render_xrefs_text,
)


_FUNCTION = {"name": "parse", "address": "0x1000"}
_CALLSITE = {
    "call_addr": "0x1010", "caller_static": "0x1014",
    "containing_function": _FUNCTION,
    "callee": {"name": "copy", "address": "0x2000"},
    "call_instruction": {"address": "0x1010", "text": "call copy"},
}
_CASES = [
    pytest.param(
        _render_taint_text,
        {"direction": "backward", "function": _FUNCTION, "sinks": [], "slices": []},
        id="taint"),
    pytest.param(
        _render_trace_text,
        {"function": "parse", "function_address": "0x1000", "target_address": "0x1010",
         "arg_index": 0, "trace": [{"address": "0x1004", "il_text": "x0#1 = 7"}]},
        id="trace"),
    pytest.param(
        _render_callgraph_text,
        {"function": _FUNCTION, "callees": [
            {"kind": "direct", "call_addr": "0x1010",
             "target": {"name": "copy", "address": "0x2000"}}], "callers": []},
        id="callgraph"),
    pytest.param(
        _render_callsites_text, {"items": [_CALLSITE], "total": 1, "offset": 0},
        id="callsites"),
    pytest.param(
        _render_xrefs_text,
        {"address": "0x2000", "items": [
            {"kind": "code", "address": "0x1010", "caller_function": _FUNCTION}]},
        id="xrefs"),
    pytest.param(
        _render_xrefs_any_text,
        {"present": 1, "count": 2, "items": [
            {"symbol": "copy", "present": True, "address": "0x2000",
             "code_ref_count": 1, "caller_function_count": 1},
            {"symbol": "missing", "present": False}]},
        id="xrefs-any"),
]


def _endpoint(file_id, address="0x1000", name="parse"):
    return {"project_file_id": file_id, "project_path": f"/lib/{file_id}.so",
            "address": address, "name": name}


def _metadata():
    return {
        "project_id": "firmware", "root_file_id": "app", "complete": False,
        "truncated": True,
        "files": [
            {**_endpoint("app"), "target_id": "target-app", "loaded": False, "aliases": []},
            {**_endpoint("provider"), "target_id": "target-provider", "loaded": True,
             "aliases": [f"raw-provider-{n}" for n in range(16)]},
        ],
        "limits": {"max_files": 2, "max_depth": 3, "max_functions": 17},
        "boundaries": [
            {"reason": "file_limit", "detail": {"project_file_id": f"unloaded-{n}"}}
            for n in range(16)
        ],
    }


def _rendered_metadata(text):
    # Parse the public text section, not formatter implementation details.
    section = text.split("\nproject_analysis:\n", 1)[1]
    return json.JSONDecoder().raw_decode(section.lstrip())[0]


def _provenance_rows(text):
    rows = {}
    for line in text.splitlines():
        if line.startswith(("  result:", "  result.")):
            path, payload = line.strip().split(": ", 1)
            assert path not in rows, text
            rows[path] = json.loads(payload)
    return rows


def _assert_endpoint(rows, path, endpoint):
    assert path in rows, rows
    for key in ("project_file_id", "project_path", "address", "name"):
        assert rows[path][key] == endpoint[key], (path, rows[path])


@pytest.mark.parametrize("render,payload", _CASES)
def test_every_renderer_preserves_all_metadata_without_mutation(render, payload):
    value = copy.deepcopy(payload)
    value["project_analysis"] = _metadata()
    before = copy.deepcopy(value)
    text = render(value)
    assert "incomplete" in text.casefold()
    assert _rendered_metadata(text) == value["project_analysis"]
    assert value == before


@pytest.mark.parametrize("render,payload", _CASES)
@pytest.mark.parametrize("metadata", [None, {}, {"complete": True, "truncated": False,
                                              "files": [], "boundaries": [], "limits": {}}])
def test_empty_metadata_does_not_invent_incompleteness(render, payload, metadata):
    text = render({**payload, "project_analysis": metadata})
    assert "incomplete" not in text.casefold()
    assert "malformed" not in text.casefold()
    assert _rendered_metadata(text) == metadata


@pytest.mark.parametrize("render,payload", _CASES)
@pytest.mark.parametrize("metadata,partial", [
    ({"complete": False, "truncated": False}, False),
    ({"complete": True, "truncated": True}, False),
    ({"complete": True, "truncated": False}, True),
])
def test_each_incomplete_signal_warns_even_without_boundaries(
        render, payload, metadata, partial):
    text = render({**payload, "project_analysis": metadata, "partial": partial})
    assert "incomplete" in text.casefold()
    assert _rendered_metadata(text) == metadata
    assert _provenance_rows(text)["result"]["partial"] is partial


@pytest.mark.parametrize("render,payload", _CASES)
@pytest.mark.parametrize("bad", [False, 0, "", [], "broken", ["broken"]])
def test_malformed_metadata_is_disclosed_not_silently_absent(render, payload, bad):
    text = render({**payload, "project_analysis": bad})
    assert _rendered_metadata(text) == bad
    assert "malformed" in text.casefold()


@pytest.mark.parametrize("render,payload", _CASES)
@pytest.mark.parametrize("metadata", [
    {"complete": []},
    {"truncated": {}},
    {"limits": False},
    {"files": {}},
    {"boundaries": "unavailable"},
    {"files": [False]},
    {"boundaries": [False]},
    {"files": [{"aliases": "raw-provider"}]},
    {"files": [{"loaded": []}]},
])
def test_malformed_nested_metadata_preserves_payload_and_discloses(
        render, payload, metadata):
    text = render({**payload, "project_analysis": metadata})
    assert _rendered_metadata(text) == metadata
    assert "malformed" in text.casefold()


@pytest.mark.parametrize("render,payload", _CASES)
def test_coverage_flags_boundaries_and_lower_bounds_remain_explicit(render, payload):
    coverage = {
        "complete": False, "partial": False, "truncated": False,
        "boundaries": [], "total_lower_bound": 0, "caller_function_count_lower_bound": 2,
        "resolution": "project_external", "resolution_detail": "provider body unavailable",
        "status": "partial", "resolved_from": _endpoint("app", "0x1020", "copy@plt"),
    }
    text = render({**payload, **coverage, "project_analysis": {}})
    row = _provenance_rows(text)["result"]
    for key, value in coverage.items():
        assert row[key] == value
    _assert_endpoint(_provenance_rows(text), "result.resolved_from", coverage["resolved_from"])


@pytest.mark.parametrize("full", [False, True])
def test_taint_source_sink_and_path_target_are_file_qualified_even_when_compact(full):
    source = {**_endpoint("app", "0x1010", "recv"), "kind": "arg", "index": 0}
    sink = {**_endpoint("provider", "0x1010", "copy"), "callee": "copy",
            "class": "overflow_len", "tainted_arg_index": 2}
    target = _endpoint("provider", "0x1000", "copy")
    step = {**_endpoint("app", "0x1010"), "il_text": "copy(dst, src, n)",
            "target": target}
    value = {"direction": "forward", "function": _endpoint("app"),
             "sources": [source], "project_analysis": {},
             "reached_sinks": [{"source": source, "sink": sink, "path": [step]}]}
    rows = _provenance_rows(_render_taint_text(value, full=full))
    for path, endpoint in [
        ("result.function", value["function"]), ("result.sources[0]", source),
        ("result.reached_sinks[0].source", source), ("result.reached_sinks[0].sink", sink),
        ("result.reached_sinks[0].path[0]", step),
        ("result.reached_sinks[0].path[0].target", target),
    ]:
        _assert_endpoint(rows, path, endpoint)


@pytest.mark.parametrize("full", [False, True])
def test_backward_taint_retains_sink_origin_and_crossed_call_endpoints(full):
    caller, callee = _endpoint("app"), _endpoint("provider")
    step = {**caller, "source": caller, "target": callee, "cross_file": True}
    value = {"direction": "backward", "function": caller, "project_analysis": {},
             "sinks": [callee], "slices": [{"sink": callee,
                 "origin": {**caller, "kind": "parameter"}, "slice": [step]}]}
    rows = _provenance_rows(_render_taint_text(value, full=full))
    for path, endpoint in [
        ("result.sinks[0]", callee), ("result.slices[0].sink", callee),
        ("result.slices[0].origin", caller), ("result.slices[0].slice[0]", caller),
        ("result.slices[0].slice[0].source", caller),
        ("result.slices[0].slice[0].target", callee),
    ]:
        _assert_endpoint(rows, path, endpoint)


def test_trace_steps_and_crossed_caller_callee_preserve_separate_identities():
    caller, callee = _endpoint("app"), _endpoint("provider")
    step = {**caller, "source": caller, "target": callee, "cross_file": True,
            "il_text": "copy(dst, src, n)"}
    terminal = {**callee, "terminates": True, "reason": "function_parameter",
                "origin": {**callee, "kind": "parameter"}}
    value = {"function": "parse", "function_address": "0x1000", "target_address": "0x1010",
             "arg_index": 0, "trace": [step, terminal], "project_analysis": {}}
    rows = _provenance_rows(_render_trace_text(value))
    for path, endpoint in [
        ("result.trace[0]", caller), ("result.trace[0].source", caller),
        ("result.trace[0].target", callee), ("result.trace[1]", callee),
        ("result.trace[1].origin", callee),
    ]:
        _assert_endpoint(rows, path, endpoint)


def test_callsites_preserve_row_container_and_callee_qualification():
    caller, callee = _endpoint("app"), _endpoint("provider")
    row = {**_CALLSITE, **caller, "containing_function": caller, "callee": callee,
           "also_in": [_endpoint("app", "0x1100", "alternate")]}
    rows = _provenance_rows(_render_callsites_text({"items": [row], "project_analysis": {}}))
    for path, endpoint in [
        ("result.items[0]", caller), ("result.items[0].containing_function", caller),
        ("result.items[0].callee", callee), ("result.items[0].also_in[0]", row["also_in"][0]),
    ]:
        _assert_endpoint(rows, path, endpoint)


@pytest.mark.parametrize("render", [_render_xrefs_text, _render_xrefs_any_text])
def test_xrefs_rows_and_nested_ref_endpoints_remain_qualified(render):
    target, caller = _endpoint("provider"), _endpoint("app")
    ref = {**caller, "kind": "code", "caller_function": caller}
    row = {**target, "symbol": "parse", "present": True, "kind": "code",
           "caller_function": caller, "items": [ref], "code_ref_count_lower_bound": 1}
    rows = _provenance_rows(render({"address": "0x1000", "items": [row], "project_analysis": {}}))
    for path, endpoint in [
        ("result.items[0]", target), ("result.items[0].caller_function", caller),
        ("result.items[0].items[0]", caller),
        ("result.items[0].items[0].caller_function", caller),
    ]:
        _assert_endpoint(rows, path, endpoint)
    assert rows["result.items[0]"]["code_ref_count_lower_bound"] == 1


@pytest.mark.parametrize("per_site", [False, True])
def test_callgraph_same_name_and_address_in_different_files_never_coalesce(per_site):
    first, second = _endpoint("first"), _endpoint("second")
    value = {"function": _FUNCTION, "project_analysis": {},
             "callees": [{"kind": "direct", "call_addr": site, "target": endpoint}
                         for site, endpoint in [("0x1010", first), ("0x1020", second),
                                                ("0x1030", first)]],
             "callers": [{"call_addr": "0x2010", "caller": endpoint}
                         for endpoint in [first, second]],
             }
    text = _render_callgraph_text(value, per_site=per_site)
    body = text.split("\n\nproject provenance and coverage:", 1)[0]
    for endpoint, other, sites in [
        (first, second, ("0x1010", "0x1030", "0x2010")),
        (second, first, ("0x1020", "0x2010")),
    ]:
        lines = [line for line in body.splitlines() if endpoint["project_path"] in line]
        assert lines, body
        assert all(other["project_path"] not in line for line in lines)
        for site in sites:
            assert any(site in line for line in lines), (endpoint, site, lines)
    rows = _provenance_rows(text)
    _assert_endpoint(rows, "result.callees[0].target", first)
    _assert_endpoint(rows, "result.callees[1].target", second)
    _assert_endpoint(rows, "result.callees[2].target", first)
    _assert_endpoint(rows, "result.callers[0].caller", first)
    _assert_endpoint(rows, "result.callers[1].caller", second)


@pytest.mark.parametrize("kind", ["code", "data"])
@pytest.mark.parametrize("qualification", ["caller", "row"])
def test_xrefs_same_name_address_and_site_in_different_files_form_distinct_groups(kind, qualification):
    refs = []
    for endpoint in [_endpoint("first"), _endpoint("second"), _endpoint("first")]:
        caller = endpoint if qualification == "caller" else _FUNCTION
        row = {"kind": kind, "address": "0x1010", "caller_function": caller}
        if qualification == "row":
            row.update({key: endpoint[key] for key in ("project_file_id", "project_path")})
        refs.append(row)
    text = _render_xrefs_text({"address": "0x2000", "items": refs, "project_analysis": {}})
    body = text.split("\n\nproject provenance and coverage:", 1)[0]
    for endpoint, other in [
        (_endpoint("first"), _endpoint("second")),
        (_endpoint("second"), _endpoint("first")),
    ]:
        lines = [line for line in body.splitlines() if endpoint["project_path"] in line]
        assert lines, body
        assert all(other["project_path"] not in line for line in lines)
        assert any("0x1010" in line for line in lines)
    rows = _provenance_rows(text)
    for index, ref in enumerate(refs):
        if qualification == "caller":
            _assert_endpoint(rows, f"result.items[{index}].caller_function",
                             ref["caller_function"])
        else:
            for key in ("project_file_id", "project_path"):
                assert rows[f"result.items[{index}]"][key] == ref[key]


def test_indirect_graph_resolution_keeps_each_provider_endpoint():
    first, second = _endpoint("first"), _endpoint("second")
    text = _render_callgraph_text({"function": _FUNCTION, "project_analysis": {},
        "callees": [{"kind": "indirect", "call_addr": "0x1010", "dest_expr": "x0",
                     "resolved": [first, second], "resolution": "possible_values"}]})
    body = text.split("\n\nproject provenance and coverage:", 1)[0]
    for endpoint in (first, second):
        assert endpoint["project_path"] in body
    rows = _provenance_rows(text)
    _assert_endpoint(rows, "result.callees[0].resolved[0]", first)
    _assert_endpoint(rows, "result.callees[0].resolved[1]", second)
    assert rows["result.callees[0]"]["resolution"] == "possible_values"


@pytest.mark.parametrize("render,payload", [
    (_render_taint_text, {"direction": "backward", "sinks": [], "slices": []}),
    (_render_trace_text, {"trace": []}),
    (_render_callgraph_text, {"callees": [], "callers": []}),
    (_render_callsites_text, {"items": [], "total": 0}),
    (_render_xrefs_text, {"items": []}),
    (_render_xrefs_any_text, {"items": [], "present": 0, "count": 0}),
])
def test_incomplete_empty_results_warn(render, payload):
    text = render({**payload, "project_analysis": {
        "complete": False, "truncated": False, "files": [],
        "boundaries": [{"reason": "provider_unavailable", "symbol": "copy"}],
    }})
    assert "incomplete" in text.casefold()
    assert _rendered_metadata(text)["boundaries"] == [
        {"reason": "provider_unavailable", "symbol": "copy"}
    ]


@pytest.mark.parametrize("render,payload", _CASES)
@pytest.mark.parametrize("key,bad", [
    ("complete", []), ("partial", {}), ("truncated", []),
    ("boundaries", False), ("resolved_from", []),
])
def test_malformed_row_coverage_is_retained_and_disclosed(render, payload, key, bad):
    text = render({**payload, "project_analysis": {}, key: bad})
    assert _provenance_rows(text)["result"][key] == bad
    assert "malformed" in text.casefold()
