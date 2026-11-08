"""Project backward body traversal using the existing synthetic SSA fixtures."""
from types import SimpleNamespace

import pytest

from test_taint_engine import FBV, FExpr, FFunc, FInstr, FSSA, FSSAFunc, FVar, te


def value(var):
    return FExpr("MLIL_VAR_SSA", str(var), reads=[var])


def constant(number):
    return FExpr("MLIL_CONST", str(number), constant=number)


def call(index, target, params=(), output=None):
    ins = FInstr(index, 0x100 + index * 4, "MLIL_CALL_SSA", f"call {target:#x}",
                 dest=FExpr("MLIL_CONST_PTR", hex(target), constant=target),
                 params=list(params), reads=[r for p in params for r in te.expr_reads(p)],
                 writes=[] if output is None else [output])
    ins.src_memory, ins.dest_memory = index, index + 1
    return ins


def ret(index, expr=None):
    ins = FInstr(index, 0x100 + index * 4, "MLIL_RET", "return",
                 src=[] if expr is None else [expr],
                 reads=[] if expr is None else te.expr_reads(expr))
    ins.ssa_memory_version = index
    return ins


class Project:
    def __init__(self):
        self.views = {}
        self.links = {}
        self.reverse = {}
        self.boundaries = []
        self.caller_queries = []

    def add(self, name, instructions, params=(), names=None):
        view = FBV({0x900: "getenv", **(names or {})})
        view.file_id = name
        fn = FFunc(name, 0x100, FSSAFunc(instructions, {
            ins.dest_memory: ins for ins in instructions if hasattr(ins, "dest_memory")
        }), params=params)
        fn.view = view
        view._funcs[fn.start] = fn
        self.views[name] = view
        return fn

    def file_id(self, view):
        return view.file_id

    def function_key(self, view, function):
        return view.file_id, function.start

    def identity(self, view, function=None, address=None):
        row = {"project_file_id": view.file_id, "project_path": view.file_id}
        if function is not None:
            row.update(function=function.name, address=hex(function.start))
        if address is not None:
            row["address"] = hex(address)
        return row

    def resolve(self, view, address, name=None):
        fn = self.links.get((view.file_id, address))
        return SimpleNamespace(function=fn, view=fn.view if fn else None,
                               status="resolved" if fn else "unresolved",
                               reason=None if fn else "unlinked", address=fn.start if fn else None,
                               target=self.identity(fn.view, fn) if fn else None,
                               source=self.identity(view, address=address),
                               cross_file=bool(fn and fn.view is not view))

    def resolve_call(self, view, instruction):
        return self.resolve(view, te.const_target(instruction.dest))

    def indirect_targets(self, view, instruction):
        return te.targets_from_pvs(getattr(instruction.dest, "possible_values", None))

    def callers(self, view, function):
        self.caller_queries.append(view.file_id)
        return self.reverse.get(self.function_key(view, function), [])

    def boundary(self, reason, **kwargs):
        self.boundaries.append({"reason": reason, **kwargs})


def engine(project, root, overlay=None, **kwargs):
    result = te.TaintEngine(root.view, te.load_models(overlay), project_context=project, **kwargs)
    result._bw_leaves = []
    result._bw_assumptions = []
    result._bw_truncated = False
    result._bw_truncation_causes = set()
    return result


def origins(rows):
    return [row["origin"] for row in rows]


def test_return_descent_same_addresses_and_additive_benign_model():
    project = Project()
    bval, aval, rval = [FSSA(FVar(n), 1) for n in ("b", "a", "root")]
    b = project.add("B", [call(0, 0x900, output=bval), ret(1, value(bval))])
    a = project.add("A", [call(0, 0x800, output=aval), ret(1, value(aval))], names={0x800: "B"})
    root = project.add("root", [call(0, 0x800, output=rval), ret(1, value(rval))], names={0x800: "A"})
    project.links.update({("root", 0x800): a, ("A", 0x800): b})
    eng = engine(project, root, {"A": {}})
    rows = eng._backward_slice(root, rval, 0, 8, set(), seed_ins=root.mlil.ssa_form.instructions[-1])
    source = next(row for row in rows if row["origin"].get("callee") == "getenv")
    assert source["origin"]["project_file_id"] == "B"
    edges = [s for s in source["steps"] if s.get("cross_file")]
    assert {(e["source"]["project_file_id"], e["target"]["project_file_id"])
            for e in edges} == {("root", "A"), ("A", "B")}
    assert eng.bv is root.view


def test_descent_parameter_binds_invoking_operand_not_other_callers():
    project = Project()
    param = FSSA(FVar("param", ident=1), 0)
    provider = project.add("provider", [ret(0, value(param))], params=[param.var])
    out = FSSA(FVar("result"), 1)
    invoke = call(0, 0x800, [constant(17)], out)
    root = project.add("root", [invoke, ret(1, value(out))])
    unrelated = project.add("unrelated", [call(0, 0x800, [constant(99)])])
    project.links[("root", 0x800)] = provider
    project.reverse[("provider", provider.start)] = [SimpleNamespace(
        function=unrelated, instruction=unrelated.mlil.ssa_form.instructions[0])]
    rows = engine(project, root)._backward_slice(root, out, 0, 8, set(), seed_ins=invoke)
    assert any(o.get("value") == 17 for o in origins(rows))
    assert not any(o.get("value") == 99 for o in origins(rows))
    assert project.caller_queries == []


@pytest.mark.parametrize("conversion", ["ssa_property", "address_lookup"])
def test_provider_root_parameter_ascends_project_reverse_index(conversion):
    project = Project()
    param, source = FSSA(FVar("param", ident=1), 0), FSSA(FVar("input"), 1)
    provider = project.add("provider", [ret(0, value(param))], params=[param.var])
    invoke = call(1, 0x800, [value(source)])
    root = project.add("root", [call(0, 0x900, output=source), invoke])
    ordinary = FInstr(invoke.instr_index, invoke.address, "MLIL_CALL", "provider(input)",
                      dest=invoke.dest,
                      params=[FExpr("MLIL_VAR", "input", reads=[source.var])],
                      reads=[source.var])
    if conversion == "ssa_property":
        ordinary.ssa_form = invoke
    project.reverse[("provider", provider.start)] = [SimpleNamespace(function=root, instruction=ordinary)]
    rows = engine(project, provider)._backward_slice(provider, param, 0, 8, set())
    assert any(o.get("callee") == "getenv" and o["project_file_id"] == "root" for o in origins(rows))
    assert project.caller_queries == ["provider"]


@pytest.mark.parametrize("overlay", [None, {"provider": {}},
                                     {"provider": {"sources": [{"to": "*arg:0"}]}},
                                     {"provider": {"propagates": [
                                         {"from": "arg:1", "to": "ret"}]}}])
def test_output_writer_descends_body_with_opaque_benign_and_fill_models(overlay):
    project = Project()
    param = FSSA(FVar("out", ident=1, typ="char*"), 0)
    source = FSSA(FVar("input"), 1)
    store = FInstr(1, 0x104, "MLIL_STORE_SSA", "*out = input", dest=value(param),
                   src=value(source), reads=[param, source])
    store.src_memory, store.dest_memory, store.size = 1, 2, 8
    provider = project.add("provider", [call(0, 0x900, output=source), store, ret(2)], params=[param.var])
    local = FVar("buffer", ident=2, typ="char[8]")
    addr = FExpr("MLIL_ADDRESS_OF", "&buffer", src=local)
    writer = call(0, 0x800, [addr, constant(17)])
    sink = ret(1)
    root = project.add("root", [writer, sink], names={0x800: "provider"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, overlay)
    rows = eng._backward_slice(root, None, 0, 8, set(), seed_expr=addr,
                               seed_ins=sink, anchor=(addr, 0))
    assert any(o.get("callee") == "getenv" and o["project_file_id"] == "provider"
               for o in origins(rows))


def test_depth_and_recursion_boundaries_are_explicit():
    project = Project()
    result = FSSA(FVar("result"), 1)
    root = project.add("root", [call(0, 0x800, output=result), ret(1, value(result))])
    project.links[("root", 0x800)] = root
    eng = engine(project, root)
    eng._backward_slice(root, result, 0, 8, set())
    assert any(b["reason"] == "backward_recursion" for b in project.boundaries)
    project.boundaries.clear()
    eng._backward_slice(root, result, 0, 0, set())
    assert any(b["reason"] == "backward_depth_limit" for b in project.boundaries)


def test_exact_indirect_sink_site_is_project_only():
    project = Project()
    p = FSSA(FVar("arg"), 0)
    first, second = call(0, 0x800, [value(p)]), call(1, 0x800, [value(p)])
    second.dest = FExpr("MLIL_VAR_SSA", "indirect")
    root = project.add("root", [first, second])
    eng = engine(project, root)
    sink = {"kind": "arg", "callee": "not_named", "index": 0, "address": hex(second.address)}
    assert eng._seed_backward(root, root.mlil.ssa_form, [first, second], sink) == [(p, second)]
    assert eng._bw_unseeded_demand(root, root.mlil.ssa_form, [first, second], sink)
    assert {leaf["address"] for leaf in eng._bw_leaves} == {hex(second.address)}


def test_project_function_budget_stops_before_reading_provider_body():
    project = Project()
    project.limits = {"max_functions": 1}
    result = FSSA(FVar("result"), 1)
    root = project.add("root", [call(0, 0x800, output=result)])
    provider = project.add("provider", [ret(0, constant(17))])
    provider.mlil = None
    project.links[("root", 0x800)] = provider
    eng = engine(project, root)
    eng._backward_slice(root, result, 0, 8, set())
    assert any(b["reason"] == "function_limit" for b in project.boundaries)
    assert not any(b["reason"] == "backward_missing_body" for b in project.boundaries)
    assert eng.bv is root.view


@pytest.mark.parametrize("overlay", [None, {"provider": {"propagates": [
    {"from": "arg:0", "to": "ret"}]}}])
def test_literal_provider_return_excludes_unknown_argument_fallback_but_keeps_models(overlay):
    project = Project()
    ignored = FSSA(FVar("ignored", ident=1, typ="char*"), 0)
    literal = FExpr("MLIL_CONST_PTR", '"safe"', constant=0x5000)
    provider = project.add("provider", [ret(0, literal)], params=[ignored.var])
    param = FSSA(FVar("input", ident=2, typ="char*"), 0)
    result = FSSA(FVar("result", typ="char*"), 1)
    invoke = call(0, 0x800, [value(param)], result)
    sink = ret(1, value(result))
    root = project.add("root", [invoke, sink], params=[param.var], names={0x800: "provider"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, overlay)
    eng._const_ptr_storage = lambda address: "readonly"
    rows = eng._backward_slice(root, result, 0, 8, set(),
                               seed_ins=sink, anchor=(value(result), 0))
    assert any(o.get("kind") == "constant" and o.get("project_file_id") == "provider"
               for o in origins(rows))
    caller_inputs = [o for o in origins(rows)
                     if o.get("kind") == "parameter" and o.get("project_file_id") == "root"]
    assert bool(caller_inputs) == (overlay is not None)


@pytest.mark.parametrize("writer_kind", ["parameter_copy", "source_copy", "source_fill", "store"])
def test_returned_global_buffer_follows_provider_exit_memory(writer_kind):
    project = Project()
    storage = FExpr("MLIL_CONST_PTR", "static_output", constant=0x5000)
    param = FSSA(FVar("input", ident=1, typ="char*"), 0)
    source = FSSA(FVar("provider_input", typ="char*"), 1)
    instructions = []
    if writer_kind == "source_copy":
        instructions.append(call(0, 0x900, output=source))
    index = len(instructions)
    if writer_kind == "source_fill":
        writer = call(index, 0x901, [constant(0), storage, constant(8)])
    elif writer_kind == "store":
        writer = FInstr(index, 0x100 + index * 4, "MLIL_STORE_SSA",
                        "*static_output = input", dest=storage, src=value(param), reads=[param])
        writer.src_memory, writer.dest_memory, writer.size = index, index + 1, 8
    else:
        writer = call(index, 0x902, [storage, value(
            source if writer_kind == "source_copy" else param)])
    instructions.extend([writer, ret(index + 1, storage)])
    # Present in the function, but not on this RET's reaching memory chain.
    instructions.append(call(index + 2, 0x903, [storage]))
    provider = project.add("provider", instructions, params=[param.var],
                           names={0x901: "read", 0x902: "strcpy", 0x903: "late_source"})
    caller_input = FSSA(FVar("caller_input", ident=2, typ="char*"), 0)
    result = FSSA(FVar("result", typ="char*"), 1)
    invoke = call(0, 0x800, [value(caller_input)], result)
    sink = ret(1, value(result))
    root = project.add("root", [invoke, sink], params=[caller_input.var],
                       names={0x800: "provider"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, {"late_source": {"sources": [{"to": "*arg:0"}]}})
    eng._const_ptr_storage = lambda address: "writable" if address == 0x5000 else "readonly"
    rows = eng._backward_slice(root, result, 0, 8, set(),
                               seed_ins=sink, anchor=(value(result), 0))
    if writer_kind in ("parameter_copy", "store"):
        matching = [row for row in rows if row["origin"].get("kind") == "parameter"
                    and row["origin"].get("project_file_id") == "root"]
    else:
        matching = [row for row in rows
                    if row["origin"].get("callee") == (
                        "getenv" if writer_kind == "source_copy" else "read")
                    and row["origin"].get("project_file_id") == "provider"]
    assert matching
    assert any(step.get("project_file_id") == "provider"
               and step.get("address") == hex(writer.address)
               for row in matching for step in row["steps"])
    assert not any(o.get("callee") == "late_source" for o in origins(rows))
    assert any(leaf.get("global") == "0x5000" for leaf in eng._bw_leaves)


@pytest.mark.parametrize("resolution", ["map", "vsa", "project_binding"])
def test_indirect_provider_resolution_does_not_record_discarded_boundary(resolution):
    project = Project()
    provider = project.add("provider", [ret(0, constant(17))])
    result = FSSA(FVar("result"), 1)
    invoke = call(0, 0x800, output=result)
    invoke.dest = FExpr("MLIL_VAR_SSA", "callback")
    root = project.add("root", [invoke])
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, **(
        {"resolve_map": {hex(invoke.address): ["0x800"]}} if resolution == "map" else {}))
    lookups = []

    def resolve_call(view, instruction):
        lookups.append(instruction)
        if resolution == "project_binding":
            return project.resolve(view, 0x800)
        project.boundary("speculative_unresolved")
        return project.resolve(view, None)

    project.resolve_call = resolve_call
    if resolution == "vsa":
        invoke.dest.possible_values = SimpleNamespace(
            type=SimpleNamespace(name="InSetOfValues"), values=[0x800])
    rows = eng._backward_slice(root, result, 0, 8, set(), seed_ins=invoke)
    assert any(o.get("value") == 17 and o.get("project_file_id") == "provider"
               for o in origins(rows))
    assert len(lookups) == (1 if resolution == "project_binding" else 0)
    assert project.boundaries == []
    assert not any(leaf["kind"] == "indirect_call_unresolved" for leaf in eng._bw_leaves)


@pytest.mark.parametrize("return_kind", ["allocated", "static", "identity"])
def test_provider_pointer_return_keeps_later_caller_pointee_writes(return_kind):
    project = Project()
    param = FSSA(FVar("input", ident=1, typ="char*"), 0)
    allocated = FSSA(FVar("allocated", typ="char*"), 1)
    storage = FExpr("MLIL_CONST_PTR", "static_output", constant=0x5000)
    instructions = []
    if return_kind == "allocated":
        instructions.append(call(0, 0x901, [constant(8)], allocated))
        returned = value(allocated)
    elif return_kind == "static":
        returned = storage
    else:
        returned = value(param)
    if return_kind != "identity":
        index = len(instructions)
        store = FInstr(index, 0x100 + index * 4, "MLIL_STORE_SSA",
                       "*output = 0", dest=returned, src=constant(0),
                       reads=te.expr_reads(returned))
        store.src_memory, store.dest_memory, store.size = index, index + 1, 8
        instructions.append(store)
    instructions.append(ret(len(instructions), returned))
    provider = project.add("provider", instructions,
                           params=[param.var] if return_kind == "identity" else [],
                           names={0x901: "malloc"})
    local = FVar("buffer", ident=2, typ="char[8]")
    addr = FExpr("MLIL_ADDRESS_OF", "&buffer", src=local)
    result = FSSA(FVar("result", typ="char*"), 1)
    source = FSSA(FVar("caller_input", typ="char*"), 1)
    invoke = call(0, 0x800, [addr] if return_kind == "identity" else [], result)
    writer = call(2, 0x902, [value(result), value(source)])
    sink = call(3, 0x903, [value(result)])
    root = project.add("root", [invoke, call(1, 0x900, output=source), writer, sink],
                       names={0x800: "provider", 0x902: "strcpy", 0x903: "system"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root)
    eng._const_ptr_storage = lambda address: "writable" if address == 0x5000 else "readonly"
    rows = eng._backward_slice(root, result, 0, 8, set(),
                               seed_ins=sink, anchor=(value(result), 0))
    caller_sources = [row for row in rows
                      if row["origin"].get("callee") == "getenv"
                      and row["origin"].get("project_file_id") == "root"]
    assert caller_sources
    assert any(step.get("project_file_id") == "root"
               and step.get("address") == hex(writer.address)
               for row in caller_sources for step in row["steps"])
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               for row in rows for step in row["steps"])


def test_import_alias_keeps_canonical_return_source_alias_overlay_and_body():
    project = Project()
    provider = project.add("provider", [ret(0, constant(17))])
    provider.name = "getenv"
    result = FSSA(FVar("result"), 1)
    invoke = call(0, 0x800, output=result)
    sink = ret(1, value(result))
    root = project.add("root", [invoke, sink], names={0x800: "import_alias"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, {"import_alias": {"sources": [{"to": "ret"}]}})
    rows = eng._backward_slice(root, result, 0, 8, set(), seed_ins=sink)
    canonical = [row for row in rows if row["origin"].get("kind") == "source"
                 and row["origin"].get("callee") == "getenv"]
    assert canonical
    assert all(row["origin"].get("project_file_id") == "provider" for row in canonical)
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               for row in canonical for step in row["steps"])
    assert any(o.get("kind") == "source" and o.get("callee") == "import_alias"
               and o.get("project_file_id") == "root" for o in origins(rows))
    assert any(o.get("kind") == "constant" and o.get("value") == 17
               and o.get("project_file_id") == "provider" for o in origins(rows))


def test_import_alias_keeps_canonical_return_propagation_alias_overlay_and_body():
    project = Project()
    first = FSSA(FVar("first", ident=1, typ="char*"), 0)
    second = FSSA(FVar("second", ident=2, typ="char*"), 0)
    provider = project.add("provider", [ret(0, constant(17))],
                           params=[first.var, second.var])
    provider.name = "canonical_copy"
    canonical_input = FSSA(FVar("canonical_input", typ="char*"), 1)
    alias_input = FSSA(FVar("alias_input", typ="char*"), 1)
    result = FSSA(FVar("result", typ="char*"), 1)
    invoke = call(2, 0x800, [value(canonical_input), value(alias_input)], result)
    sink = ret(3, value(result))
    root = project.add("root", [call(0, 0x900, output=canonical_input),
                               call(1, 0x901, output=alias_input), invoke, sink],
                       names={0x800: "import_alias", 0x901: "alias_input"})
    project.links[("root", 0x800)] = provider
    eng = engine(project, root, {
        "canonical_copy": {"propagates": [{"from": "arg:0", "to": "ret"}]},
        "import_alias": {"propagates": [{"from": "arg:1", "to": "ret"}]},
        "alias_input": {"sources": [{"to": "ret"}]},
    })
    rows = eng._backward_slice(root, result, 0, 8, set(), seed_ins=sink)
    canonical = [row for row in rows if row["origin"].get("callee") == "getenv"
                 and row["origin"].get("project_file_id") == "root"]
    assert canonical
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               for row in canonical for step in row["steps"])
    assert any(o.get("callee") == "alias_input" and o.get("project_file_id") == "root"
               for o in origins(rows))
    assert any(o.get("kind") == "constant" and o.get("value") == 17
               and o.get("project_file_id") == "provider" for o in origins(rows))


@pytest.mark.parametrize("model_kind", ["source", "propagation"])
@pytest.mark.parametrize("body_kind", ["safe_store", "no_write"])
def test_import_alias_keeps_canonical_outparam_model_alias_overlay_and_body(model_kind, body_kind):
    project = Project()
    out = FSSA(FVar("out", ident=1, typ="char*"), 0)
    incoming = FSSA(FVar("input", ident=2, typ="char*"), 0)
    instructions = []
    if body_kind == "safe_store":
        store = FInstr(0, 0x100, "MLIL_STORE_SSA", "*out = 23",
                       dest=value(out), src=constant(23), reads=[out])
        store.src_memory, store.dest_memory, store.size = 0, 1, 8
        instructions.append(store)
    # A read of the formal also makes its SSA version available for a no-write body.
    instructions.append(ret(len(instructions), value(out)))
    provider = project.add("provider", instructions, params=[out.var, incoming.var])
    provider.name = "canonical_fill"
    local = FVar("buffer", ident=3, typ="char[8]")
    addr = FExpr("MLIL_ADDRESS_OF", "&buffer", src=local)
    source = FSSA(FVar("caller_input", typ="char*"), 1)
    invoke = call(1, 0x800, [addr, value(source)])
    sink = call(2, 0x902, [addr])
    root = project.add("root", [call(0, 0x900, output=source), invoke, sink],
                       names={0x800: "import_alias", 0x902: "system"})
    project.links[("root", 0x800)] = provider
    canonical_model = ({"sources": [{"to": "*arg:0"}]} if model_kind == "source"
                       else {"propagates": [{"from": "arg:1", "to": "*arg:0"}]})
    eng = engine(project, root, {
        "canonical_fill": canonical_model,
        "import_alias": {"sources": [{"to": "*arg:0"}]},
    })
    rows = eng._backward_slice(root, None, 0, 8, set(),
                               seed_expr=addr, seed_ins=sink, anchor=(addr, 0))
    canonical = [row for row in rows if row["origin"].get("kind") == "source"
                 and row["origin"].get("callee") == (
                     "canonical_fill" if model_kind == "source" else "getenv")
                 and row["origin"].get("project_file_id") == (
                     "provider" if model_kind == "source" else "root")]
    assert canonical
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               for row in canonical for step in row["steps"])
    assert any(o.get("kind") == "source" and o.get("callee") == "import_alias"
               and o.get("project_file_id") == "root" for o in origins(rows))
    if body_kind == "safe_store":
        body = [row for row in rows if row["origin"].get("kind") == "constant"
                and row["origin"].get("value") == 23
                and row["origin"].get("project_file_id") == "provider"]
        assert body
        assert any(step.get("project_file_id") == "provider"
                   and step.get("address") == hex(store.address)
                   for row in body for step in row["steps"])
    else:
        assert any(row["origin"].get("kind") != "source"
                   and any(step.get("cross_file")
                           and step["target"]["project_file_id"] == "provider"
                           for step in row["steps"])
                   for row in rows)


def test_import_alias_sprintf_keeps_caller_vararg_with_constant_format():
    project = Project()
    out = FSSA(FVar("out", ident=1, typ="char*"), 0)
    fmt = FSSA(FVar("format", ident=2, typ="char*"), 0)
    provider = project.add("provider", [ret(0, value(out))], params=[out.var, fmt.var])
    provider.name = "sprintf"
    local = FVar("buffer", ident=3, typ="char[64]")
    addr = FExpr("MLIL_ADDRESS_OF", "&buffer", src=local)
    format_string = FExpr("MLIL_CONST_PTR", '"%s"', constant=0x5000)
    source = FSSA(FVar("caller_input", typ="char*"), 1)
    invoke = call(1, 0x800, [addr, format_string, value(source)])
    sink = call(2, 0x902, [addr])
    root = project.add("root", [call(0, 0x900, output=source), invoke, sink],
                       names={0x800: "import_alias", 0x902: "system"})
    root.view.is_offset_writable = lambda address: False
    root.view.get_ascii_string_at = lambda address, minimum: (
        SimpleNamespace(value="%s") if address == 0x5000 else None)
    project.links[("root", 0x800)] = provider
    eng = engine(project, root)
    rows = eng._backward_slice(root, None, 0, 8, set(),
                               seed_expr=addr, seed_ins=sink, anchor=(addr, 0))
    caller_sources = [row for row in rows
                      if row["origin"].get("kind") == "source"
                      and row["origin"].get("callee") == "getenv"
                      and row["origin"].get("project_file_id") == "root"]
    assert caller_sources
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               and step.get("address") == hex(invoke.address)
               for row in caller_sources for step in row["steps"])


def test_name_resolved_import_keeps_canonical_source_without_caller_model():
    class ImportProject(Project):
        def resolve_call(self, view, instruction):
            target = te.resolve_call_target(view, instruction, follow_thunks=False)
            return self.resolve(view, target.address)

    project = ImportProject()
    provider = project.add("provider", [ret(0, constant(17))])
    provider.name = "getenv"
    result = FSSA(FVar("result", typ="char*"), 1)
    invoke = call(0, 0x800, output=result)
    invoke.dest = FExpr("MLIL_IMPORT", "getenv", constant=0x6000)
    invoke.dest.name = "getenv"
    sink = ret(1, value(result))
    root = project.add("root", [invoke, sink], names={0x800: "getenv"})
    root.view.get_symbols_by_name = lambda name: (
        [SimpleNamespace(address=0x800)] if name == "getenv" else [])
    project.links[("root", 0x800)] = provider
    eng = engine(project, root)
    # The shared resolver can name this import, but the ordinary backward call
    # walker uses const_target, which deliberately excludes GOT-slot constants.
    assert te.const_target(invoke.dest) is None
    assert eng._resolve_direct_target(invoke) == 0x800
    assert te.lookup_model(eng.models, eng._callee_name(te.const_target(invoke.dest)))[1] is None
    rows = eng._backward_slice(root, result, 0, 8, set(), seed_ins=sink)
    canonical = [row for row in rows
                 if row["origin"].get("kind") == "source"
                 and row["origin"].get("callee") == "getenv"
                 and row["origin"].get("project_file_id") == "provider"]
    assert canonical
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               for row in canonical for step in row["steps"])
    assert any(o.get("kind") == "constant" and o.get("value") == 17
               and o.get("project_file_id") == "provider" for o in origins(rows))


@pytest.mark.parametrize("sink_model", [
    None,
    {"class": "bounded_copy", "len_arg": 2, "tainted_args": []},
    {"class": "fortified_overflow", "tainted_args": [2]},
], ids=["builtin_overflow_len", "explicit_len_arg", "fortified_overflow"])
def test_import_alias_bounded_copy_keeps_length_with_constant_source(sink_model):
    project = Project()
    out = FSSA(FVar("out", ident=1, typ="char*"), 0)
    incoming = FSSA(FVar("input", ident=2, typ="char*"), 0)
    length = FSSA(FVar("length", ident=3), 0)
    provider = project.add("provider", [ret(0, value(out))],
                           params=[out.var, incoming.var, length.var])
    provider.name = "memcpy"
    local = FVar("buffer", ident=4, typ="char[64]")
    addr = FExpr("MLIL_ADDRESS_OF", "&buffer", src=local)
    literal = FExpr("MLIL_CONST_PTR", '"constant"', constant=0x5000)
    source = FSSA(FVar("caller_length"), 1)
    invoke = call(1, 0x800, [addr, literal, value(source)])
    sink = call(2, 0x902, [addr])
    root = project.add("root", [call(0, 0x900, output=source), invoke, sink],
                       names={0x800: "import_alias", 0x902: "system"})
    root.view.is_offset_writable = lambda address: False
    root.view.get_ascii_string_at = lambda address, minimum: (
        SimpleNamespace(value="constant") if address == 0x5000 else None)
    project.links[("root", 0x800)] = provider
    overlay = None if sink_model is None else {
        "memcpy": {"propagates": [{"from": "*arg:1", "to": "*arg:0"}],
                   "sink": sink_model},
    }
    eng = engine(project, root, overlay)
    rows = eng._backward_slice(root, None, 0, 8, set(),
                               seed_expr=addr, seed_ins=sink, anchor=(addr, 0))
    caller_sources = [row for row in rows
                      if row["origin"].get("kind") == "source"
                      and row["origin"].get("callee") == "getenv"
                      and row["origin"].get("project_file_id") == "root"]
    assert caller_sources
    assert any(step.get("cross_file")
               and step["target"]["project_file_id"] == "provider"
               and step.get("address") == hex(invoke.address)
               for row in caller_sources for step in row["steps"])
