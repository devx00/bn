"""Project reader joins, with overlapping addresses and source-local references."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from _bridge_fakes import _FakeBV, _FakeCodeRef, _FakeFunction, _load_bridge


class ReaderProject:
    def __init__(self, views):
        self.views = views
        self.bindings = {}
        self.sites = {}
        self.boundaries = []

    def file_id(self, view):
        return next(key for key, value in self.views.items() if value is view)

    def identity(self, view, function=None, address=None):
        key = self.file_id(view)
        result = {"project_file_id": key, "project_path": key + ".so"}
        if function is not None:
            result["function"] = function.name
            if address is None:
                address = function.start
        if address is not None:
            result["address"] = hex(address)
        return result

    def function_key(self, view, function):
        return self.file_id(view), function.start

    def resolve(self, view, address, name=None):
        target_view, target = self.bindings.get(
            (self.file_id(view), address), (view, view.get_function_at(address)))
        resolved = target is not None
        if not resolved:
            self.boundary("unlinked_import", bv=view, address=address)
        return SimpleNamespace(
            view=target_view if resolved else None, function=target,
            address=target.start if resolved else None,
            status="resolved" if resolved else "unresolved",
            reason=None if resolved else "unlinked_import",
            source=self.identity(view, address=address),
            target=self.identity(target_view, target) if resolved else None,
            cross_file=resolved and target_view is not view)

    def resolve_call(self, view, instruction):
        return self.resolve(view, instruction.target)

    def indirect_targets(self, view, instruction):
        return []

    def callers(self, view, function):
        return self.sites.get(self.function_key(view, function), [])

    def boundary(self, reason, **kwargs):
        if {"reason": reason} not in self.boundaries:
            self.boundaries.append({"reason": reason})

    def metadata(self):
        return {"complete": not self.boundaries, "truncated": bool(self.boundaries),
                "boundaries": self.boundaries}


def setup_readers(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    caller = _FakeFunction(0x1000, "consumer")
    provider = _FakeFunction(0x1000, "provider")
    other = _FakeFunction(0x1000, "other_consumer")
    consumer_view = _FakeBV(functions=[caller])
    provider_view = _FakeBV(functions=[provider])
    other_view = _FakeBV(functions=[other])
    project = ReaderProject({"consumer": consumer_view, "provider": provider_view, "other": other_view})
    project.bindings[("consumer", 0x2000)] = (provider_view, provider)
    instruction = SimpleNamespace(operation=SimpleNamespace(name="MLIL_CALL_SSA"),
                                  address=0x1010, instr_index=0, target=0x2000)
    first = SimpleNamespace(view=consumer_view, function=caller, address=0x1010,
                            instruction=instruction, target_view=provider_view,
                            target_function=provider)
    second = SimpleNamespace(view=other_view, function=other, address=0x1010,
                             instruction=instruction, target_view=provider_view,
                             target_function=provider)
    project.sites[("provider", 0x1000)] = [first, first, second]
    for reader in (bridge.read_decompile, bridge.read_listing, bridge.read_xrefs):
        monkeypatch.setattr(reader, "_project_current", lambda bv=None: project)
    monkeypatch.setattr(instance.ctx, "_resolve_view", lambda selector: consumer_view)
    return bridge, instance, project, caller, provider, first, second


def test_project_callgraph_resolves_actual_provider_and_qualified_reverse_callers(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_decompile
    monkeypatch.setattr(reader.il_format, "_il_function_for",
                        lambda *args: SimpleNamespace(instructions=[first.instruction]))
    monkeypatch.setattr(reader._taint, "resolve_call_target",
                        lambda *args, **kwargs: SimpleNamespace(address=0x2000))
    outgoing = reader._project_resolved_calls(instance.ctx, project, first.view, caller,
                                             direction="callees", resolve_indirect=True)
    assert outgoing["callees"][0]["target"]["project_file_id"] == "provider"
    assert outgoing["callees"][0]["target"]["address"] == "0x1000"
    assert outgoing["callees"][0]["source"]["project_file_id"] == "consumer"
    assert outgoing["callees"][0]["source"]["address"] == "0x1010"
    incoming = reader._project_resolved_calls(instance.ctx, project, first.target_view, provider,
                                             direction="callers", resolve_indirect=True)
    assert len(incoming["callers"]) == 2
    assert {row["caller"]["project_file_id"] for row in incoming["callers"]} == {"consumer", "other"}
    assert incoming["complete"]


def test_project_callgraph_unresolved_import_is_explicit(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_decompile
    project.bindings.clear()
    monkeypatch.setattr(reader.il_format, "_il_function_for",
                        lambda *args: SimpleNamespace(instructions=[first.instruction]))
    monkeypatch.setattr(reader._taint, "resolve_call_target",
                        lambda *args, **kwargs: SimpleNamespace(address=0x2000))
    result = reader._project_resolved_calls(instance.ctx, project, first.view, caller,
                                           direction="callees", resolve_indirect=True)
    assert result["callees"][0]["target"]["resolution"] == "unresolved"
    assert result["partial"] and result["truncated"] and not result["complete"]
    assert result["boundaries"] == [{"reason": "unlinked_import"}]


def stub_callsite_rendering(monkeypatch, bridge):
    def render(ctx, bv, callee, function, *, project_sites, **kwargs):
        return [{"call_addr": hex(address), "_excerpt_fn": function}
                for address in sorted(project_sites)]
    monkeypatch.setattr(bridge.read_listing, "_callsites_within_function", render)
    monkeypatch.setattr(bridge.read_listing, "_callee_data_refs", lambda *args: {})
    monkeypatch.setattr(bridge.read_listing, "_callee_variadic_hint", lambda *args: None)
    monkeypatch.setattr(bridge.read_listing, "_other_containing_functions", lambda *args: [])
    def excerpts(view, rows):
        for row in rows:
            row.pop("_excerpt_fn")
            row["rendered_in"] = view
    monkeypatch.setattr(bridge.read_listing, "_attach_callsite_excerpts", excerpts)


def test_project_callsites_dedupe_and_paginate_by_file(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    stub_callsite_rendering(monkeypatch, bridge)
    result = bridge.read_listing._project_callsites(
        instance.ctx, project, first.target_view, provider, within_identifiers=[], context=0,
        offset=1, limit=1, callee_symbol_only=False)
    assert result["total"] == 2 and result["returned"] == 1
    row = result["items"][0]
    assert row["project_file_id"] == "other"
    assert row["callee"]["project_file_id"] == "provider"
    assert row["containing_function"]["project_file_id"] == "other"
    assert row["rendered_in"] is second.view
    assert "_excerpt_fn" not in row


def test_project_callsites_within_is_selected_view_only(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    stub_callsite_rendering(monkeypatch, bridge)
    monkeypatch.setattr(instance.ctx, "_resolve_scope_functions", lambda bv, ids: [("consumer", caller)])
    result = bridge.read_listing._project_callsites(
        instance.ctx, project, first.view, SimpleNamespace(start=0x2000, name="import"),
        within_identifiers=["consumer"], context=0, offset=0, limit=10, callee_symbol_only=True)
    assert result["total"] == 1
    assert result["items"][0]["project_file_id"] == "consumer"
    assert result["resolved_from"]["project_file_id"] == "consumer"
    assert result["callee"]["address"] == "0x1000"


def test_project_xrefs_counts_and_data_pointers_remain_source_local(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_xrefs
    native = reader._xrefs_to_address
    def local(ctx, bv, address, **kwargs):
        if not kwargs.get("_project_local"):
            return native(ctx, bv, address, **kwargs)
        data = [{"address": "0x1010", "kind": "data", "caller_function": None,
                 "context": {"address": "0x1010"}}]
        return reader._xref_envelope(address, {}, [], data)
    monkeypatch.setattr(reader, "_xrefs_to_address", local)
    monkeypatch.setattr(instance.ctx, "_address_context", lambda bv, address, **kw: {"address": hex(address)})
    result = native(instance.ctx, first.target_view, 0x1000, offset=1, limit=2,
                    fn_pointer_scan=True)
    assert result["code_ref_count"] == 2
    assert result["caller_function_count"] == 2
    assert result["data_ref_count"] == 1
    assert result["total"] == 3
    assert [(row["project_file_id"], row["kind"]) for row in result["items"]] == [
        ("other", "code"), ("provider", "data")]
    assert result["items"][1]["context"]["project_file_id"] == "provider"


def test_project_xrefs_import_query_targets_provider_not_consumer_address(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_xrefs
    monkeypatch.setattr(first.view, "get_symbol_at", lambda address: SimpleNamespace(
        type=SimpleNamespace(name="ImportedFunctionSymbol")) if address == 0x2000 else None)
    monkeypatch.setattr(instance.ctx, "_address_context", lambda bv, address, **kw: {"address": hex(address)})
    monkeypatch.setattr(reader, "_union_stub_code_refs", lambda ctx, bv, addr, refs: (refs, []))
    result = reader._xrefs_to_address(instance.ctx, first.view, 0x2000)
    assert result["address"] == "0x1000"
    assert result["target_context"]["project_file_id"] == "provider"
    assert result["resolved_from"] == {"project_file_id": "consumer", "project_path": "consumer.so", "address": "0x2000"}
    assert result["code_ref_count"] == 2
    assert result["target_context"]["function"]["project_file_id"] == "provider"
    assert result["target_context"]["function"]["name"] == "provider"


def test_project_incomplete_counts_are_lower_bounds(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    stub_callsite_rendering(monkeypatch, bridge)
    project.boundary("max_files")
    result = bridge.read_listing._project_callsites(
        instance.ctx, project, first.target_view, provider, within_identifiers=[], context=0,
        offset=0, limit=1, callee_symbol_only=False)
    assert result["total"] is None and result["total_lower_bound"] == 2
    assert result["caller_total"] is None and result["caller_total_lower_bound"] == 2
    assert result["caller_scan_truncated"] and result["has_more"]
    xrefs = bridge.read_xrefs._project_read_completeness(project, {
        "total": 2, "code_ref_count": 2, "data_ref_count": 0, "caller_function_count": 2})
    assert xrefs["code_ref_count"] is None and xrefs["code_ref_count_lower_bound"] == 2
    assert xrefs["data_ref_count"] is None and xrefs["data_ref_count_lower_bound"] == 0


def test_standalone_callgraph_and_xrefs_keep_original_schema(monkeypatch):
    bridge = _load_bridge(monkeypatch)
    instance = bridge.BinaryNinjaBridge()
    function = _FakeFunction(0x1000, "body")
    view = _FakeBV(functions=[function], code_refs={0x1000: [_FakeCodeRef(0x1010, function)]})
    monkeypatch.setattr(instance.ctx, "_resolve_view", lambda selector: view)
    monkeypatch.setattr(instance.ctx, "_find_function", lambda *args, **kwargs: function)
    for reader in (bridge.read_decompile, bridge.read_xrefs):
        monkeypatch.setattr(reader, "_project_current", lambda bv=None: None)
    result = bridge.read_decompile._resolved_calls(instance.ctx, None, "body", direction="callers")
    assert set(result) == {"kind", "function", "callers"}
    monkeypatch.setattr(instance.ctx, "_address_context", lambda *args, **kwargs: {})
    result = bridge.read_xrefs._xrefs_to_address(instance.ctx, view, 0x1000)
    assert "partial" not in result and "complete" not in result and "project_analysis" not in result
    assert "project_file_id" not in result["items"][0]


def test_project_callsite_preserves_mlil_evidence_without_llil_mapping(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_listing
    monkeypatch.setattr(reader.il_format, "_structured_disasm_entries", lambda *args: [])
    monkeypatch.setattr(reader.il_format, "_iter_llil_instructions", lambda function: iter(()))
    monkeypatch.setattr(reader.il_format, "_instruction_length", lambda *args, **kwargs: 4)
    monkeypatch.setattr(reader.il_format, "_hlil_statement_localization",
                        lambda instruction: (None, "no_hlil_mapping"))
    monkeypatch.setattr(reader.il_format, "_hlil_pre_branch_condition", lambda instruction: None)
    monkeypatch.setattr(reader, "_attach_callsite_arity", lambda *args: None)
    rows = reader._callsites_within_function(
        instance.ctx, first.view, provider, caller, context=0,
        project_sites={first.address: first})
    assert len(rows) == 1
    assert rows[0]["call_addr"] == "0x1010"
    assert rows[0]["disasm_context_reason"] == "no_structured_disasm_entry"
    assert rows[0]["hlil_statement_reason"] == "no_hlil_mapping"
    assert rows[0]["caller_static"] == "0x1014"


@pytest.mark.parametrize("slot", [None, 0x3000])
def test_project_callgraph_indirect_candidates_resolve_before_unknown_boundary(monkeypatch, slot):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_decompile
    if slot is not None:
        first.instruction.dest = SimpleNamespace(operation=SimpleNamespace(name="MLIL_LOAD_SSA"))
    monkeypatch.setattr(reader.il_format, "_il_function_for",
                        lambda *args: SimpleNamespace(instructions=[first.instruction]))
    monkeypatch.setattr(reader._taint, "resolve_call_target",
                        lambda *args, **kwargs: SimpleNamespace(address=slot))
    monkeypatch.setattr(project, "indirect_targets", lambda *args: [0x2000, 0x2000])
    monkeypatch.setattr(project, "resolve_call",
                        lambda *args: (_ for _ in ()).throw(AssertionError("already have concrete candidates")))
    result = reader._project_resolved_calls(instance.ctx, project, first.view, caller,
                                           direction="callees", resolve_indirect=True)
    row = result["callees"][0]
    assert row["kind"] == "indirect" and row["resolution"] == "possible_values"
    assert len(row["resolved"]) == 1
    assert row["resolved"][0]["project_file_id"] == "provider"
    assert result["complete"]


def test_project_unresolved_import_xrefs_keep_confirmed_local_calls(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_xrefs
    project.bindings.clear()
    project.sites[("consumer", 0x2000)] = [first]
    monkeypatch.setattr(first.view, "get_symbol_at", lambda address: SimpleNamespace(
        name="unlinked", type=SimpleNamespace(name="ImportedFunctionSymbol")) if address == 0x2000 else None)
    monkeypatch.setattr(instance.ctx, "_address_context", lambda bv, address, **kw: {"address": hex(address)})
    monkeypatch.setattr(reader, "_union_stub_code_refs", lambda ctx, bv, addr, refs: (refs, []))
    result = reader._xrefs_to_address(instance.ctx, first.view, 0x2000)
    assert result["resolution"] == "unresolved"
    assert result["code_ref_count"] is None and result["code_ref_count_lower_bound"] == 1
    assert result["items"][0]["project_file_id"] == "consumer"
    assert result["items"][0]["address"] == "0x1010"


def test_project_callgraph_honors_shared_bound_got_before_raw_possible_values(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_decompile
    first.instruction.dest = SimpleNamespace(
        operation=SimpleNamespace(name="MLIL_LOAD_SSA"),
        possible_values=SimpleNamespace(type=SimpleNamespace(name="ConstantPointerValue"), value=0xDEAD))
    monkeypatch.setattr(reader.il_format, "_il_function_for",
                        lambda *args: SimpleNamespace(instructions=[first.instruction]))
    monkeypatch.setattr(reader._taint, "resolve_call_target",
                        lambda *args, **kwargs: SimpleNamespace(address=0x3000))
    monkeypatch.setattr(reader, "_pvs_targets",
                        lambda *args: (_ for _ in ()).throw(AssertionError("project owns candidate precedence")))
    result = reader._project_resolved_calls(instance.ctx, project, first.view, caller,
                                           direction="callees", resolve_indirect=True)
    assert result["callees"][0]["target"]["project_file_id"] == "provider"
    assert result["callees"][0]["target"]["address"] == "0x1000"
    assert result["complete"]


def test_project_callgraph_respects_disabled_indirect_resolution(monkeypatch):
    bridge, instance, project, caller, provider, first, second = setup_readers(monkeypatch)
    reader = bridge.read_decompile
    monkeypatch.setattr(reader.il_format, "_il_function_for",
                        lambda *args: SimpleNamespace(instructions=[first.instruction]))
    monkeypatch.setattr(reader._taint, "resolve_call_target",
                        lambda *args, **kwargs: SimpleNamespace(address=None))
    monkeypatch.setattr(project, "indirect_targets", lambda *args: [0x2000])
    monkeypatch.setattr(project, "resolve_call",
                        lambda *args: (_ for _ in ()).throw(AssertionError("resolution disabled")))
    result = reader._project_resolved_calls(instance.ctx, project, first.view, caller,
                                           direction="callees", resolve_indirect=False)
    assert result["callees"][0]["resolution"] == "disabled"
    assert "target" not in result["callees"][0] and "resolved" not in result["callees"][0]
    assert result["partial"]
