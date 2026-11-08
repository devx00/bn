"""Synthetic forward taint across file-qualified project provider bodies."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from test_taint_engine import (
    FBV, FExpr, FFunc, FInstr, FSSA, FSSAFunc, FVar,
    _driver_calls_quote, _quote_callee, te,
)


class ProjectView(FBV):
    """Keep imports local and give every function its actual owning view."""

    def __init__(self, file_id, functions=(), imports=None):
        imported = [
            FFunc(name, address, FSSAFunc([]), symbol_type="ImportedFunctionSymbol")
            for address, name in (imports or {}).items()
        ]
        functions = [*functions, *imported]
        super().__init__({}, funcs={fn.start: fn for fn in functions})
        self.project_file_id = file_id
        self.functions = functions
        for fn in functions:
            fn.view = self


class FakeProjectContext:
    """Implement the shared contract without doing name-only provider lookup."""

    def __init__(self, root_view, *providers, bindings=()):
        self.root_view = root_view
        self.project_id = "synthetic-project"
        self.views = {
            view.project_file_id: view for view in (root_view, *providers)
        }
        self.bindings = {
            (self.file_id(source), address): (target, function)
            for source, address, target, function in bindings
        }
        self.resolutions = []
        self.boundaries = []

    def file_id(self, bv):
        return bv.project_file_id

    def function_key(self, bv, function):
        assert function.view is bv
        return self.file_id(bv), function.start

    def identity(self, bv, function=None, address=None):
        result = {
            "project_file_id": self.file_id(bv),
            "project_path": f"/project/{self.file_id(bv)}",
        }
        if function is not None:
            assert function.view is bv
            result["function"] = function.name
            if address is None:
                address = function.start
        if address is not None:
            result["address"] = hex(address)
        return result

    def resolve(self, bv, address, name=None):
        self.resolutions.append((self.file_id(bv), address))
        bound = self.bindings.get((self.file_id(bv), address))
        if bound is not None:
            target_view, function = bound
        else:
            target_view = bv
            function = bv.get_function_at(address) if address is not None else None
            if function is not None and function.symbol.type.name == "ImportedFunctionSymbol":
                function = None
        resolved = function is not None
        reason = None if resolved else "provider_not_prepared"
        if not resolved:
            self.boundary(reason, bv=bv, address=address, symbol=name)
        return SimpleNamespace(
            view=target_view if resolved else None,
            function=function,
            address=function.start if resolved else None,
            status="resolved" if resolved else "unresolved",
            reason=reason,
            source=self.identity(bv, address=address),
            target=self.identity(target_view, function) if resolved else None,
            cross_file=resolved and self.file_id(bv) != self.file_id(target_view),
        )

    def resolve_call(self, bv, instruction):
        address = te.extract_dest_address(bv, getattr(instruction, "dest", None))
        function = bv.get_function_at(address) if address is not None else None
        return self.resolve(bv, address, getattr(function, "name", None))

    def indirect_targets(self, bv, instruction):
        return te.targets_from_pvs(getattr(instruction.dest, "possible_values", None))

    def boundary(self, reason, *, bv=None, address=None, symbol=None, detail=None):
        row = {"reason": reason, **self.identity(bv or self.root_view, address=address)}
        if symbol is not None:
            row["symbol"] = symbol
        if detail is not None:
            row["detail"] = detail
        if row not in self.boundaries:
            self.boundaries.append(row)

    def metadata(self):
        return {
            "project_id": self.project_id,
            "root_file_id": self.file_id(self.root_view),
            "files": [
                {**self.identity(view), "target_id": file_id, "loaded": False}
                for file_id, view in self.views.items()
            ],
            "limits": {"max_files": 16, "max_depth": 8, "max_functions": 4096},
            "truncated": False,
            "complete": not self.boundaries,
            "boundaries": list(self.boundaries),
        }

    def annotate(self, result):
        result["project_analysis"] = self.metadata()
        return result


def _var(ssa):
    return FExpr("MLIL_VAR_SSA", f"{ssa.var.name}#{ssa.version}", reads=[ssa])


def _constant(value):
    return FExpr("MLIL_CONST", str(value), constant=value)


def _call(index, address, target, params, *, writes=()):
    dest = (FExpr("MLIL_CONST_PTR", hex(target), constant=target)
            if target is not None else FExpr("MLIL_VAR_SSA", "fp#0"))
    reads = [var for param in params for var in param.vars_read]
    return FInstr(index, address, "MLIL_CALL_SSA", f"{dest}({', '.join(map(str, params))})",
                  reads=reads, writes=writes, dest=dest, params=params)


def _return_provider(*, safe=False, start=0x500, name="transform"):
    arg = FVar("input", ident=1)
    arg0 = FSSA(arg, 0)
    value = _constant(4) if safe else _var(arg0)
    return FFunc(name, start, FSSAFunc([
        FInstr(0, start + 4, "MLIL_RET", f"return {value}",
               reads=value.vars_read, src=[value]),
    ]), params=[arg])


def _forward(root, function, context, *, overlay=None, **kwargs):
    engine = te.TaintEngine(root, te.load_models(overlay), project_context=context,
                            unknown_call_policy="stop", **kwargs)
    result = engine.forward(function, [te.parse_locator("param:0")])
    return engine, result


def _command_sinks(result):
    return [finding["sink"] for finding in result["reached_sinks"]
            if finding["sink"]["class"] == "command_injection"]


def _hidden_sink_project():
    arg = FVar("command", ident=1)
    arg0 = FSSA(arg, 0)
    # Matching function and instruction addresses in all three files must not
    # look like recursion, nor let a caller's symbols interpret provider IL.
    driver = FFunc("driver", 0x500, FSSAFunc([
        _call(0, 0x504, 0x800, [_var(arg0)]),
    ]), params=[arg])
    middle_arg = FVar("command", ident=1)
    middle0 = FSSA(middle_arg, 0)
    middle = FFunc("dispatch", 0x500, FSSAFunc([
        _call(0, 0x504, 0x800, [_var(middle0)]),
    ]), params=[middle_arg])
    leaf_arg = FVar("command", ident=1)
    leaf0 = FSSA(leaf_arg, 0)
    leaf = FFunc("execute", 0x500, FSSAFunc([
        _call(0, 0x504, 0x900, [_var(leaf0)]),
    ]), params=[leaf_arg])
    root = ProjectView("consumer", [driver], {0x800: "dispatch", 0x900: "puts"})
    first = ProjectView("libfirst.so", [middle], {0x800: "execute", 0x900: "puts"})
    second = ProjectView("libsecond.so", [leaf], {0x900: "system"})
    context = FakeProjectContext(root, first, second, bindings=[
        (root, 0x800, first, middle), (first, 0x800, second, leaf),
    ])
    return root, driver, context


def test_forward_resolver_descends_nested_provider_to_hidden_sink():
    root, driver, context = _hidden_sink_project()
    engine, result = _forward(root, driver, context)

    sink, = _command_sinks(result)
    assert sink["project_file_id"] == "libsecond.so"
    assert sink["address"] == "0x504"
    assert result["stats"]["functions_visited"] == 3
    assert {step["project_file_id"] for step in result["reached_sinks"][0]["path"]} == {
        "consumer", "libfirst.so", "libsecond.so",
    }
    assert ("consumer", 0x800) in context.resolutions
    assert ("libfirst.so", 0x800) in context.resolutions
    assert result["project_analysis"]["root_file_id"] == "consumer"
    assert engine.bv is root


@pytest.mark.parametrize("safe", [False, True], ids=["scalar-return", "constant-return"])
def test_forward_provider_scalar_return_reaches_caller_length_sink_only_when_tainted(safe):
    provider = _return_provider(safe=safe)
    arg = FVar("length", ident=1)
    arg0 = FSSA(arg, 0)
    returned = FSSA(FVar("returned", ident=2), 1)
    driver = FFunc("driver", 0x100, FSSAFunc([
        _call(0, 0x104, 0x800, [_var(arg0)], writes=[returned]),
        _call(1, 0x108, 0x900, [_constant(0x3000), _constant(0x4000), _var(returned)]),
    ]), params=[arg])
    root = ProjectView("consumer", [driver], {0x800: "transform", 0x900: "memcpy"})
    library = ProjectView("libtransform.so", [provider], {0x900: "puts"})
    context = FakeProjectContext(root, library, bindings=[(root, 0x800, library, provider)])

    engine, result = _forward(root, driver, context)

    sinks = [finding["sink"] for finding in result["reached_sinks"]
             if finding["sink"]["class"] == "overflow_len"]
    if safe:
        assert result["reached_sinks"] == []
    else:
        sink, = sinks
        assert sink["address"] == "0x108"
        assert sink["project_file_id"] == "consumer"
        assert sink["tainted_arg_index"] == 2
    assert result["stats"]["functions_visited"] == 2
    assert engine.bv is root


@pytest.mark.parametrize("writer", ["store", "strcpy"])
def test_forward_provider_outparam_writer_taints_caller_buffer(writer):
    source = FVar("source", ident=1)
    output = FVar("output", ident=2)
    source0, output0 = FSSA(source, 0), FSSA(output, 0)
    if writer == "store":
        write = FInstr(0, 0x504, "MLIL_STORE_SSA", "*output#0 = source#0",
                       reads=[source0], dest=_var(output0), src=_var(source0))
    else:
        write = _call(0, 0x504, 0x920, [_var(output0), _var(source0)])
    provider = FFunc("fill", 0x500, FSSAFunc([write]), params=[source, output])
    command = FVar("command", ident=1)
    command0 = FSSA(command, 0)
    buffer = FVar("buffer", ident=2, typ="char[0x40]")
    pointer = FSSA(FVar("pointer", ident=3), 1)
    buffer0 = FSSA(buffer, 0)
    driver = FFunc("driver", 0x100, FSSAFunc([
        FInstr(0, 0x100, "MLIL_SET_VAR_SSA", "pointer#1 = &buffer", writes=[pointer],
               src=FExpr("MLIL_ADDRESS_OF", "&buffer", src=buffer)),
        _call(1, 0x104, 0x800, [_var(command0), _var(pointer)]),
        _call(2, 0x108, 0x900, [_var(buffer0)]),
    ]), params=[command])
    root = ProjectView("consumer", [driver], {0x800: "fill", 0x900: "system", 0x920: "puts"})
    library = ProjectView("libfill.so", [provider], {0x920: "strcpy", 0x900: "puts"})
    context = FakeProjectContext(root, library, bindings=[(root, 0x800, library, provider)])

    _, result = _forward(root, driver, context)

    sink, = _command_sinks(result)
    assert sink["address"] == "0x108"
    assert sink["project_file_id"] == "consumer"
    assert result["stats"]["functions_visited"] == 2


def test_forward_provider_returned_heap_buffer_reaches_caller_sink():
    provider = _quote_callee()
    driver = _driver_calls_quote(callee_addr=0x800)
    root = ProjectView("consumer", [driver], {0x800: "quote", 0x910: "system", 0x900: "puts"})
    library = ProjectView("libquote.so", [provider], {0x900: "ecalloc", 0x910: "puts"})
    context = FakeProjectContext(root, library, bindings=[(root, 0x800, library, provider)])

    _, result = _forward(root, driver, context)

    sink, = _command_sinks(result)
    assert sink["address"] == "0x14"
    assert sink["project_file_id"] == "consumer"
    assert result["stats"]["functions_visited"] == 2


@pytest.mark.parametrize("safe_first", [True, False], ids=["clean-cache-first", "tainted-cache-first"])
def test_forward_same_address_and_name_in_distinct_providers_have_distinct_summaries(safe_first):
    providers = [_return_provider(safe=safe_first), _return_provider(safe=not safe_first)]
    arg = FVar("command", ident=1)
    arg0 = FSSA(arg, 0)
    first = FSSA(FVar("first", ident=2), 1)
    second = FSSA(FVar("second", ident=3), 1)
    driver = FFunc("driver", 0x100, FSSAFunc([
        _call(0, 0x100, 0x800, [_var(arg0)], writes=[first]),
        _call(1, 0x104, 0x808, [_var(arg0)], writes=[second]),
        _call(2, 0x108, 0x900, [_var(first)]),
        _call(3, 0x10c, 0x900, [_var(second)]),
    ]), params=[arg])
    root = ProjectView("consumer", [driver], {0x800: "transform", 0x808: "transform", 0x900: "system"})
    libraries = [ProjectView("libfirst.so", [providers[0]]), ProjectView("libsecond.so", [providers[1]])]
    context = FakeProjectContext(root, *libraries, bindings=[
        (root, 0x800, libraries[0], providers[0]),
        (root, 0x808, libraries[1], providers[1]),
    ])

    _, result = _forward(root, driver, context)

    sink, = _command_sinks(result)
    assert sink["address"] == ("0x10c" if safe_first else "0x108")
    assert result["stats"]["functions_visited"] == 3


def test_forward_model_overlay_adds_return_flow_without_replacing_provider_body():
    command = FVar("command", ident=1)
    command0 = FSSA(command, 0)
    provider = FFunc("wrapper", 0x500, FSSAFunc([
        _call(0, 0x504, 0x900, [_var(command0)]),
        FInstr(1, 0x508, "MLIL_RET", "return 0", src=[_constant(0)]),
    ]), params=[command])
    arg = FVar("input", ident=1)
    arg0 = FSSA(arg, 0)
    returned = FSSA(FVar("returned", ident=2), 1)
    driver = FFunc("driver", 0x100, FSSAFunc([
        _call(0, 0x104, 0x800, [_var(arg0)], writes=[returned]),
        _call(1, 0x108, 0x900, [_var(returned)]),
    ]), params=[arg])
    root = ProjectView("consumer", [driver], {0x800: "wrapper", 0x900: "system"})
    library = ProjectView("libwrapper.so", [provider], {0x900: "system"})
    bindings = [(root, 0x800, library, provider)]
    _, baseline = _forward(root, driver, FakeProjectContext(root, library, bindings=bindings))
    _, overlaid = _forward(root, driver, FakeProjectContext(root, library, bindings=bindings),
                           overlay={"wrapper": {"propagates": [{"from": "arg:0", "to": "ret"}]}})

    def locations(result):
        return {(sink["project_file_id"], sink["address"]) for sink in _command_sinks(result)}

    assert locations(baseline) == {("libwrapper.so", "0x504")}
    assert locations(overlaid) == {("libwrapper.so", "0x504"), ("consumer", "0x108")}


def test_forward_resolve_map_applies_only_to_root_callsites_and_is_restored():
    arg = FVar("command", ident=1)
    arg0 = FSSA(arg, 0)
    driver = FFunc("driver", 0x100, FSSAFunc([
        _call(0, 0x104, None, [_var(arg0)]),
        _call(1, 0x108, 0x900, [_var(arg0)]),
    ]), params=[arg])
    provider_arg = FVar("command", ident=1)
    provider0 = FSSA(provider_arg, 0)
    provider = FFunc("dispatch", 0x500, FSSAFunc([
        _call(0, 0x104, None, [_var(provider0)]),
    ]), params=[provider_arg])
    trap_arg = FVar("command", ident=1)
    trap0 = FSSA(trap_arg, 0)
    trap = FFunc("must_not_resolve", 0x800, FSSAFunc([
        _call(0, 0x804, 0x900, [_var(trap0)]),
    ]), params=[trap_arg])
    root = ProjectView("consumer", [driver], {0x800: "dispatch", 0x900: "system"})
    library = ProjectView("libdispatch.so", [provider, trap], {0x900: "system"})
    context = FakeProjectContext(root, library, bindings=[(root, 0x800, library, provider)])
    engine = te.TaintEngine(root, te.load_models(), project_context=context,
                            unknown_call_policy="stop", resolve_map={"0x104": ["0x800"]})
    root_map = engine.resolve_map

    result = engine.forward(driver, [te.parse_locator("param:0")])

    assert {(sink["project_file_id"], sink["address"]) for sink in _command_sinks(result)} == {
        ("consumer", "0x108"),
    }
    assert result["stats"]["functions_visited"] == 2
    assert any(leaf["kind"] == "indirect_call_unresolved"
               and leaf["project_file_id"] == "libdispatch.so" for leaf in result["leaves"])
    assert any("resolved via agent-map" in assumption for assumption in result["assumptions"])
    assert engine.bv is root
    assert engine.resolve_map is root_map


def test_forward_restores_root_view_and_resolve_map_when_provider_resolution_raises(monkeypatch):
    root, driver, context = _hidden_sink_project()
    engine = te.TaintEngine(root, te.load_models(), project_context=context,
                            resolve_map={"0x1234": ["0x800"]})
    root_map = engine.resolve_map
    resolve = context.resolve
    entered_provider = []

    def fail_inside_provider(bv, address, name=None):
        if bv is not root:
            entered_provider.append(bv)
            assert engine.bv is bv
            assert engine.resolve_map == {}
            raise RuntimeError("provider resolution failed")
        return resolve(bv, address, name)

    monkeypatch.setattr(context, "resolve", fail_inside_provider)

    with pytest.raises(RuntimeError, match="provider resolution failed"):
        engine.forward(driver, [te.parse_locator("param:0")])

    assert entered_provider
    assert engine.bv is root
    assert engine.resolve_map is root_map


@pytest.mark.parametrize("conflicting_vsa", [False, True])
def test_forward_bound_got_descends_before_indirect_frontier(monkeypatch, conflicting_vsa):
    root, driver, context = _hidden_sink_project()
    call = driver.mlil.ssa_form.instructions[0]
    call.dest = FExpr("MLIL_LOAD_SSA", "[got_dispatch]",
                      src=FExpr("MLIL_CONST_PTR", "0xa00", constant=0xa00))
    if conflicting_vsa:
        call.dest.possible_values = SimpleNamespace(
            type=SimpleNamespace(name="InSetOfValues"), values=[0x500])
    indirect_targets = context.indirect_targets

    def bound_targets(view, instruction):
        # A bound GOT slot outranks its stale/concrete value-set candidate.
        return [] if view is root and instruction is call else indirect_targets(view, instruction)

    monkeypatch.setattr(context, "indirect_targets", bound_targets)
    resolve_call = context.resolve_call

    def bound_got(view, instruction):
        if view is root and instruction is call:
            # The shared resolver has a bound ExternalLocation for this slot.
            # Its provider entry equals the unrelated consumer's entry.
            return context.resolve(view, 0x800)
        return resolve_call(view, instruction)

    monkeypatch.setattr(context, "resolve_call", bound_got)
    engine, result = _forward(root, driver, context)

    assert {sink["project_file_id"] for sink in _command_sinks(result)} == {"libsecond.so"}
    assert not any(leaf["kind"] == "indirect_call_unresolved"
                   and leaf["project_file_id"] == "consumer" for leaf in result["leaves"])
    assert ("consumer", 0x500) not in context.resolutions
    unchecked = []
    fill = _call(0, 0x400, 0xb00, [])
    engine._unchecked_indirect_calls([fill, call], [fill], "read", unchecked.append)
    assert unchecked == []


@pytest.mark.parametrize("resolution", ["map", "vsa"])
def test_forward_concrete_indirect_resolution_has_no_speculative_boundary(resolution):
    root, driver, context = _hidden_sink_project()
    call = driver.mlil.ssa_form.instructions[0]
    call.dest = FExpr("MLIL_VAR_SSA", "callback#0")
    kwargs = {}
    if resolution == "map":
        kwargs["resolve_map"] = {"0x504": ["0x800"]}
    else:
        call.dest.possible_values = SimpleNamespace(
            type=SimpleNamespace(name="InSetOfValues"), values=[0x800])

    _, result = _forward(root, driver, context, **kwargs)

    assert {sink["project_file_id"] for sink in _command_sinks(result)} == {"libsecond.so"}
    assert ("consumer", None) not in context.resolutions
    assert not any(boundary["project_file_id"] == "consumer"
                   for boundary in context.boundaries)
