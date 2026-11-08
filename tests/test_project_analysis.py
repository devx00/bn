"""Project resolution, ownership and request-local bounds without a native core."""
from __future__ import annotations

from contextlib import contextmanager
import importlib
from types import SimpleNamespace as NS

import pytest

from _bridge_fakes import _load_bridge, _register_views
from test_bridge_project import FakeView, world  # noqa: F401 - shared project fixture


@pytest.fixture
def module(monkeypatch):
    _load_bridge(monkeypatch)
    return importlib.import_module("bn_test_bridge.project_analysis")


def symbol(name, address, kind="FunctionSymbol", binding="GlobalBinding"):
    return NS(name=name, raw_name=name, address=address, type=NS(name=kind), binding=NS(name=binding))


def call(address, destination, operation="MLIL_CALL"):
    dest = destination if not isinstance(destination, int) else NS(operation=NS(name="MLIL_CONST_PTR"), constant=destination)
    return NS(address=address, dest=dest, operation=NS(name=operation))


class View:
    def __init__(self, pf):
        self.project_file = pf
        self.functions = []
        self.symbols = []
        self.libraries = []
        self.locations = []
        self.relocations = {}

    def function(self, name, address, instructions=(), *, thunk=False):
        sym = symbol(name, address)
        fn = NS(name=name, start=address, view=self, symbol=sym, is_thunk=thunk,
                mlil=NS(instructions=list(instructions)))
        self.functions.append(fn)
        self.symbols.append(sym)
        return fn

    def get_function_at(self, address):
        return next((fn for fn in self.functions if fn.start == address), None)

    def get_symbol_at(self, address):
        return next((sym for sym in self.symbols if sym.address == address), None)

    def get_symbols_by_raw_name(self, name):
        return [sym for sym in self.symbols if sym.raw_name == name]

    get_symbols_by_name = get_symbols_by_raw_name

    def get_external_locations(self):
        return self.locations

    def get_external_libraries(self):
        return self.libraries

    def relocations_at(self, address):
        return self.relocations.get(address, [])

    def bind(self, provider, name, address, *, target_name=None, target_address=None):
        lib = NS(name=provider.name, backing_file=provider)
        source = symbol(name, address, "ExternalSymbol")
        loc = NS(library=lib, source_symbol=source, target_symbol=target_name or name, target_address=target_address)
        self.libraries.append(lib)
        self.locations.append(loc)
        self.symbols.append(source)
        return loc


class Gate:
    def __init__(self):
        self.readers = 0

    @contextmanager
    def read(self):
        self.readers += 1
        try:
            yield
        finally:
            self.readers -= 1


class Projects:
    def __init__(self, files):
        self.current = NS(project_id="project-one", path="/test.bnpr", project=NS(id="project-one"))
        self.entries = files

    def files(self):
        return self.entries

    def path_in_project(self, pf):
        return pf.project_path

    def sibling_index(self, files):
        result = {}
        for pf in files:
            result.setdefault(pf.project_path, []).append(pf)
        return result


class Targets:
    def __init__(self, root):
        self.root = root
        self.loaded = [root]
        self.ids = {root: "target-root"}
        self.bindings = {}
        self.resolutions = 0

    def refresh(self):
        return [{"target_id": self.ids[bv], "view_id": self.ids[bv],
                 "project_file_id": self.bindings.get(bv, (bv.project_file.id,))[0],
                 "project_path": bv.project_file.project_path} for bv in self.loaded]

    def resolve_with_snapshot(self, selector):
        self.resolutions += 1
        return self.root, self.refresh()

    def view_for_project_file(self, file_id):
        return next((bv for bv in self.loaded if self.bindings.get(bv, (bv.project_file.id,))[0] == file_id), None)

    def project_binding(self, bv):
        return self.bindings.get(bv)


class Bridge:
    def __init__(self, views):
        self.projects = Projects([bv.project_file for bv in views])
        self.targets = Targets(views[0])
        self._target_lock = Gate()
        self.available = {bv.project_file.id: bv for bv in views}
        self.loads = []
        self.load_hook = None

    def _loaded_target_row(self, rows, bv):
        target_id = self.targets.ids.get(bv)
        return next((row for row in rows if row["target_id"] == target_id), None)

    def _project_load(self, file_id, **kwargs):
        assert self._target_lock.readers == 0, "provider load must not upgrade a read gate"
        assert kwargs == {"prefer_bndb": False, "quick": False, "link": True}
        self.loads.append(file_id)
        if self.load_hook:
            self.load_hook(file_id)
        bv = self.available[file_id]
        self.targets.loaded.append(bv)
        self.targets.ids[bv] = "target-" + file_id
        return {"loaded": True, "analysis_state": "full",
                "target": self._loaded_target_row(self.targets.refresh(), bv)}


@pytest.fixture
def graph(tmp_path):
    def make(file_id, name=None, magic=b"\x7fELF"):
        path = tmp_path / file_id
        path.write_bytes(magic + b"\0" * 32)
        pf = NS(id=file_id, name=name or file_id, project_path="/" + (name or file_id),
                path_on_disk=str(path), project=NS(id="project-one"))
        return View(pf)
    root, provider, other = make("root"), make("provider"), make("other")
    root.function("main", 0x1000, [call(0x1010, 0x5000)])
    provider.function("entry", 0x1000)
    other.function("entry", 0x1000)
    root.bind(provider.project_file, "entry", 0x5000)
    return Bridge([root, provider, other]), root, provider, other, make


def test_standalone_fast_path_does_not_resolve_or_validate_options(module, graph):
    bridge, *_ = graph
    bridge.projects.current = None
    assert module.prepare(bridge, "bad", {"project_max_files": False}, reverse=True) == (None, None)
    assert bridge.targets.resolutions == 0
    assert not bridge.loads


def test_disabled_does_not_resolve(module, graph):
    bridge, *_ = graph
    assert module.prepare(bridge, None, {"project": False}, reverse=True) == (None, None)
    assert bridge.targets.resolutions == 0


def test_standalone_selected_in_open_project_does_not_load(module, graph):
    bridge, root, *_ = graph
    root.project_file.project.id = "another-project"
    assert module.prepare(bridge, None, {}, reverse=True) == (None, None)
    assert not bridge.loads


@pytest.mark.parametrize("params", [{"project": 1}, {"project_max_files": True},
    {"project_max_files": 0}, {"project_max_files": 257}, {"project_max_depth": "2"},
    {"project_max_depth": 65}, {"project_max_functions": -1}, {"project_max_functions": 100001}])
def test_invalid_bounds(module, graph, params):
    bridge, *_ = graph
    with pytest.raises(ValueError):
        module.prepare(bridge, None, params, reverse=False)
    assert not bridge.loads


def test_exact_bound_provider_same_addresses_and_nonproject_context(module, graph):
    bridge, root, provider, other, _ = graph
    context, pinned = module.prepare(bridge, None, {}, reverse=False)
    assert pinned == "target-root"
    assert bridge.loads == ["provider"]
    target = context.resolve(root, 0x5000)
    assert target.status == "resolved" and target.view is provider
    assert target.function is provider.functions[0]
    assert target.source["address"] == "0x5000"
    assert target.target["project_file_id"] == "provider"
    assert target.cross_file
    assert context.function_key(root, root.functions[0]) != context.function_key(provider, provider.functions[0])
    assert context.resolve(root, 0x1000, "entry").view is root
    assert module.current() is None
    with pytest.raises(KeyboardInterrupt):
        with context.activate():
            assert module.current(root) is context
            assert module.current(other) is None
            assert context.view_for_function(provider.functions[0]) is provider
            raise KeyboardInterrupt
    assert module.current() is None
    assert context.metadata()["files"][1]["loaded"] is True


def test_nested_context_restores_outer(module, graph):
    bridge, root, *_ = graph
    first, _ = module.prepare(bridge, None, {}, reverse=False)
    second, _ = module.prepare(bridge, None, {}, reverse=False)
    with first.activate():
        with second.activate():
            assert module.current(root) is second
        assert module.current(root) is first
    assert module.current() is None
    assert bridge.loads == ["provider"]
    assert second.metadata()["files"][1]["loaded"] is False


def test_raw_database_aliases_are_exposed(module, graph):
    bridge, root, provider, _, make = graph
    db = make("database", "provider.bndb", b"SQLite format 3\0")
    db.function("entry", 0x2000)
    bridge.projects.entries.append(db.project_file)
    bridge.available["database"] = db
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert bridge.loads == ["database"]
    assert context.resolve(root, 0x5000).view is db
    assert context.file_id(db) == "database"
    assert context.metadata()["files"][1]["aliases"] == ["provider"]


def test_ambiguous_database_never_guesses(module, graph):
    bridge, root, _, _, make = graph
    for file_id in ("db-one", "db-two"):
        db = make(file_id, "provider.bndb", b"SQLite format 3\0")
        bridge.projects.entries.append(db.project_file)
        bridge.available[file_id] = db
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert not bridge.loads
    assert context.resolve(root, 0x5000).status == "ambiguous"
    assert "ambiguous_database" in {row["reason"] for row in context.metadata()["boundaries"]}


def test_bound_address_beats_same_name(module, graph):
    bridge, root, provider, *_ = graph
    selected = provider.function("different", 0x2000)
    root.locations[0].target_address = 0x2000
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x5000).function is selected


def test_missing_export_does_not_pick_unrelated_name(module, graph):
    bridge, root, provider, *_ = graph
    provider.symbols.clear()
    context, _ = module.prepare(bridge, None, {}, reverse=True)
    target = context.resolve(root, 0x5000)
    assert target.status == "unresolved" and target.reason == "missing_export"
    assert not context.metadata()["complete"]


def test_ambiguous_exports_are_not_first_match(module, graph):
    bridge, root, provider, *_ = graph
    provider.function("entry", 0x2000)
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x5000).status == "ambiguous"


def test_local_non_thunk_tailcall_remains_real_body(module, graph):
    bridge, root, *_ = graph
    wrapper = root.function("wrapper", 0x2000, [call(0x2000, 0x5000, "MLIL_TAILCALL")])
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x2000).function is wrapper


def test_plt_and_got_follow_explicit_external_location(module, graph):
    bridge, root, provider, *_ = graph
    got = symbol("entry", 0x6000, "ImportAddressSymbol")
    root.symbols.append(got)
    destination = NS(operation=NS(name="MLIL_IMPORT"), constant=0x6000, name="entry")
    root.function("entry@plt", 0x3000, [call(0x3000, destination, "MLIL_TAILCALL")], thunk=True)
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x3000).view is provider
    assert context.resolve_call(root, call(0x1020, destination)).view is provider
    load = NS(operation=NS(name="MLIL_LOAD"), src=NS(operation=NS(name="MLIL_CONST_PTR"), constant=0x6000))
    assert context.resolve_call(root, call(0x1020, load)).view is provider


def test_unused_unbound_import_not_reported_until_attempted(module, graph):
    bridge, root, *_ = graph
    root.locations[0].library.backing_file = None
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.metadata()["complete"]
    assert context.resolve(root, 0x5000).reason == "unbound_external"
    context.resolve(root, 0x5000)
    assert len(context.metadata()["boundaries"]) == 1


def test_file_cap_discloses_provider_boundary(module, graph):
    bridge, root, *_ = graph
    context, _ = module.prepare(bridge, None, {"project_max_files": 1}, reverse=False)
    assert not bridge.loads
    assert context.metadata()["truncated"]
    assert context.resolve(root, 0x5000).reason == "provider_unavailable"


def test_dependency_depth_and_bfs_before_reverse_consumers(module, graph):
    bridge, root, provider, other, _ = graph
    provider.bind(other.project_file, "entry", 0x5000)
    context, _ = module.prepare(bridge, None, {"project_max_depth": 1}, reverse=False)
    assert bridge.loads == ["provider"]
    assert context.metadata()["truncated"]
    assert "depth_limit" in {row["reason"] for row in context.metadata()["boundaries"]}
    assert context.resolve(provider, 0x5000).status == "unresolved"


def test_reverse_discovers_consumers_skips_json_and_deduplicates(module, graph):
    bridge, root, provider, other, make = graph
    other.functions[0].mlil.instructions.append(call(0x1010, 0x5000))
    other.bind(provider.project_file, "entry", 0x5000)
    artifact = make("artifact", ".bn-findings/data.json", b"\x7fELF")
    json_file = make("json", "settings.json", b"{\"value\":1}")
    bridge.projects.entries.extend([artifact.project_file, json_file.project_file])
    context, _ = module.prepare(bridge, None, {}, reverse=True)
    assert bridge.loads == ["provider", "other"]
    sites = context.callers(provider, provider.functions[0])
    assert {(context.file_id(site.view), site.address) for site in sites} == {("root", 0x1010), ("other", 0x1010)}
    assert len(context.callers(provider, provider.functions[0])) == 2


def test_reverse_scan_caps_and_missing_il(module, graph):
    bridge, root, provider, *_ = graph
    context, _ = module.prepare(bridge, None, {"project_max_functions": 1}, reverse=False)
    assert len(context.callers(provider, provider.functions[0])) == 1
    assert context.metadata()["truncated"]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    context.limits["max_instructions"] = 0
    assert context.callers(provider, provider.functions[0]) == []
    assert context.metadata()["boundaries"][0]["reason"] == "instruction_limit"
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    root.functions[0].mlil = None
    assert context.callers(provider, provider.functions[0]) == []
    assert context.metadata()["boundaries"][0]["reason"] == "missing_il"


def test_failed_provider_load_is_explicit_and_context_not_installed(module, graph):
    bridge, root, *_ = graph
    def fail(_):
        raise RuntimeError("analysis failed")
    bridge.load_hook = fail
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x5000).status == "unresolved"
    assert context.metadata()["boundaries"][0]["reason"] == "provider_load_failed"
    assert module.current() is None


@pytest.mark.parametrize("exception", [KeyboardInterrupt(), RuntimeError("busy: write gate")])
def test_cancel_and_no_wait_propagate_without_context_leaks(module, graph, exception):
    bridge, *_ = graph
    def fail(_):
        raise exception
    bridge.load_hook = fail
    with pytest.raises(type(exception)):
        module.prepare(bridge, None, {}, reverse=False)
    assert module.current() is None
    assert bridge._target_lock.readers == 0


def test_project_replaced_during_provider_load_refuses(module, graph):
    bridge, *_ = graph
    def replace(_):
        bridge.projects.current = NS(project_id="project-two")
    bridge.load_hook = replace
    with pytest.raises(RuntimeError, match="Project changed"):
        module.prepare(bridge, None, {}, reverse=False)


def test_validate_detects_root_and_provider_removal(module, graph):
    bridge, root, provider, *_ = graph
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    for victim in (root, provider):
        bridge.targets.loaded.remove(victim)
        with bridge._target_lock.read(), pytest.raises(RuntimeError, match="closed or replaced"):
            context.validate(bridge)
        bridge.targets.loaded.append(victim)


def test_validate_detects_replaced_target_id(module, graph):
    bridge, root, *_ = graph
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    bridge.targets.ids[root] = "new-target"
    with bridge._target_lock.read(), pytest.raises(RuntimeError, match="closed or replaced"):
        context.validate(bridge)


def test_annotation_only_adds_project_metadata(module, graph):
    bridge, *_ = graph
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    result = {"complete": False, "items": []}
    assert context.annotate(result) is result
    assert result["complete"] is False
    assert result["project_analysis"]["project_id"] == "project-one"


def test_got_relocation_without_slot_symbol(module, graph):
    bridge, root, provider, *_ = graph
    root.relocations[0x6000] = [NS(symbol=root.locations[0].source_symbol)]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x6000).view is provider


def test_unresolved_import_retains_native_callers(module, graph):
    bridge, root, *_ = graph
    root.locations[0].library.backing_file = None
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    sites = context.callers(root, NS(start=0x5000))
    assert len(sites) == 1
    assert sites[0].view is root and sites[0].address == 0x1010
    assert not context.metadata()["complete"]


def test_cooperative_cancel_keeps_loaded_provider_owned(module, graph):
    bridge, root, provider, *_ = graph
    bridge_module = importlib.import_module("bn_test_bridge.bridge")
    with bridge_module._request_cancel_context(lambda: bool(bridge.loads)):
        with pytest.raises(RuntimeError, match="request cancelled"):
            module.prepare(bridge, None, {}, reverse=False)
    assert provider in bridge.targets.loaded
    assert module.current() is None
    assert root in bridge.targets.loaded


def _dispatcher_graph(world):
    root = View(world.files.boot_app)
    provider = View(world.files.loader)
    for view in (root, provider):
        native_shape = FakeView(view.project_file.path_on_disk, view.project_file)
        view.file = native_shape.file
        view.view_type = native_shape.view_type
    root.function("main", 0x1000, [call(0x1010, 0x5000)])
    provider.function("entry", 0x1000)
    root.bind(provider.project_file, "entry", 0x5000)
    _register_views(world.module, root)
    return root, provider


def test_real_dispatch_load_phases_and_implicit_root_pin(world, monkeypatch):
    root, provider = _dispatcher_graph(world)
    bridge = world.instance
    phases = []

    def native_open(pf, update_analysis):
        assert pf is provider.project_file and not update_analysis
        assert bridge._target_lock._writer and bridge._target_lock._readers == 0
        phases.append("open-exclusive")
        return provider

    def analysis():
        assert not bridge._target_lock._writer and bridge._target_lock._readers == 0
        phases.append("analysis-unlocked")

    provider.update_analysis_and_wait = analysis
    world.bn.load = native_open

    def read_callgraph(target, identifier, **kwargs):
        assert bridge._target_lock._readers == 1
        selected = bridge.targets.resolve(target)
        assert selected is root  # A newly loaded second target must not steal it.
        context = world.module.project_analysis.current(selected)
        resolved = context.resolve_call(selected, selected.functions[0].mlil.instructions[0])
        return {"root": context.identity(selected, selected.functions[0]), "callee": resolved.target}

    monkeypatch.setattr(bridge, "_resolved_calls", read_callgraph)
    response = bridge.dispatch({"op": "resolved_calls", "params": {"identifier": "main", "direction": "callees"}})
    assert response["ok"], response
    assert phases == ["open-exclusive", "analysis-unlocked"]
    assert response["result"]["root"]["project_file_id"] == root.project_file.id
    assert response["result"]["callee"]["project_file_id"] == provider.project_file.id
    assert response["result"]["project_analysis"]["files"][1]["loaded"] is True
    assert world.module.project_analysis.current() is None


def test_real_dispatch_refuses_root_replacement_during_analysis(world, monkeypatch):
    root, provider = _dispatcher_graph(world)
    bridge = world.instance
    replacement = View(root.project_file)
    replacement.file = FakeView(root.project_file.path_on_disk, root.project_file).file
    replacement.view_type = root.view_type
    provider.update_analysis_and_wait = lambda: _register_views(world.module, replacement)
    world.bn.load = lambda pf, update_analysis: provider

    def must_not_traverse(*args, **kwargs):
        pytest.fail("dispatch traversed a replacement root")

    monkeypatch.setattr(bridge, "_resolved_calls", must_not_traverse)
    response = bridge.dispatch({"op": "resolved_calls", "params": {"identifier": "main", "direction": "callees"}})
    assert not response["ok"]
    assert "closed or replaced" in str(response["error"])
    assert world.module.project_analysis.current() is None


def test_real_dispatch_context_reset_after_reader_failure(world, monkeypatch):
    root, _ = _dispatcher_graph(world)
    bridge = world.instance
    root.libraries.clear()
    root.locations.clear()

    def failing_reader(*args, **kwargs):
        assert world.module.project_analysis.current(root) is not None
        raise RuntimeError("reader failure")

    monkeypatch.setattr(bridge, "_resolved_calls", failing_reader)
    request = {"op": "resolved_calls", "params": {"identifier": "main", "direction": "callees"}}
    assert not bridge.dispatch(request)["ok"]
    assert world.module.project_analysis.current() is None
    standalone = FakeView("/standalone")
    _register_views(world.module, standalone)

    def standalone_reader(target, identifier, **kwargs):
        assert bridge.targets.resolve(target) is standalone
        assert world.module.project_analysis.current() is None
        return {"complete": True}

    monkeypatch.setattr(bridge, "_resolved_calls", standalone_reader)
    response = bridge.dispatch(request)
    assert response["ok"]
    assert "project_analysis" not in response["result"]


@pytest.mark.parametrize("binding", ["LocalBinding", "NoBinding"])
def test_name_resolution_requires_actual_export(module, graph, binding):
    bridge, root, provider, *_ = graph
    provider.symbols[0].binding = NS(name=binding)
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.resolve(root, 0x5000).reason == "missing_export"


def test_import_veneer_not_reported_as_application_caller(module, graph):
    bridge, root, provider, *_ = graph
    veneer = root.function("entry@plt", 0x3000, [call(0x3000, 0x5000, "MLIL_TAILCALL")], thunk=True)
    veneer.symbol.type = NS(name="ImportedFunctionSymbol")
    root.functions[0].mlil.instructions = [call(0x1010, 0x3000)]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    sites = context.callers(provider, provider.functions[0])
    assert [(site.function.name, site.address) for site in sites] == [("main", 0x1010)]


def test_open_exact_raw_provider_wins_over_database_alias(module, graph):
    bridge, root, provider, _, make = graph
    db = make("database", "provider.bndb", b"SQLite format 3\0")
    bridge.projects.entries.append(db.project_file)
    bridge.available["database"] = db
    bridge.targets.loaded.append(provider)
    bridge.targets.ids[provider] = "already-open-provider"
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert not bridge.loads
    assert context.resolve(root, 0x5000).view is provider


def test_deleted_project_file_refuses_even_if_view_survives(module, graph):
    bridge, _, provider, *_ = graph
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    bridge.projects.entries.remove(provider.project_file)
    with bridge._target_lock.read(), pytest.raises(RuntimeError, match="closed or replaced"):
        context.validate(bridge)


def pointer_load(slot, *targets):
    return NS(
        operation=NS(name="MLIL_LOAD"),
        src=NS(operation=NS(name="MLIL_CONST_PTR"), constant=slot),
        possible_values=NS(type=NS(name="InSetOfValues"), values=list(targets)),
    )


def test_loaded_pointer_value_set_indexes_all_actual_callees(module, graph):
    bridge, root, provider, *_ = graph
    local = root.function("local_destination", 0x2000)
    slot_function = root.function("not_the_destination", 0x6000)
    instruction = call(0x1010, pointer_load(0x6000, 0x5000, 0x2000))
    root.functions[0].mlil.instructions = [instruction]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.indirect_targets(root, instruction) == [0x2000, 0x5000]
    assert [site.address for site in context.callers(provider, provider.functions[0])] == [0x1010]
    assert [site.address for site in context.callers(root, local)] == [0x1010]
    assert context.callers(root, slot_function) == []
    assert context.metadata()["complete"]


def test_loaded_pointer_singleton_resolves_without_slot_boundary(module, graph):
    bridge, root, provider, *_ = graph
    instruction = call(0x1010, pointer_load(0x6000, 0x5000))
    root.functions[0].mlil.instructions = [instruction]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    result = context.resolve_call(root, instruction)
    assert result.view is provider and result.function is provider.functions[0]
    assert len(context.callers(provider, provider.functions[0])) == 1
    assert context.metadata()["complete"]


def test_loaded_pointer_without_values_never_calls_storage_address(module, graph):
    bridge, root, *_ = graph
    root.function("storage_is_not_a_callee", 0x6000)
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    result = context.resolve_call(root, call(0x1010, pointer_load(0x6000)))
    assert result.status == "unresolved"
    assert result.reason == "unresolved_indirect_call"


def test_explicit_got_binding_beats_speculative_load_values(module, graph):
    bridge, root, provider, *_ = graph
    instruction = call(0x1010, pointer_load(0x5000, 0x1000))
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert context.indirect_targets(root, instruction) == []
    assert context.resolve_call(root, instruction).view is provider
    assert context.metadata()["complete"]


def test_nonreporting_probe_does_not_poison_successful_resolution(module, graph):
    bridge, root, provider, *_ = graph
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    probe = context.resolve(root, 0x7000, record_boundary=False)
    assert probe.status == "unresolved"
    probe = context.resolve_call(root, call(0x1010, pointer_load(0x6000, 0x5000, 0x1000)),
                                 record_boundary=False)
    assert probe.reason == "multiple_indirect_targets"
    assert context.resolve(root, 0x5000).view is provider
    assert context.metadata()["complete"]
    context.resolve(root, 0x7000)
    assert not context.metadata()["complete"]


def test_explicit_external_thumb_pointer_resolves_function_entry(module, graph):
    bridge, root, provider, *_ = graph
    root.locations[0].target_address = 0x1001
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    result = context.resolve(root, 0x5000)
    assert result.status == "resolved"
    assert result.function is provider.functions[0] and result.address == 0x1000
    assert context.metadata()["complete"]


def test_dependency_database_alias_preserves_selected_raw_root(module, graph):
    bridge, root, provider, _, make = graph
    root_db = make("root-database", "root.bndb", b"SQLite format 3\0")
    root_db.function("main", 0x1000)
    bridge.projects.entries.append(root_db.project_file)
    bridge.available[root_db.project_file.id] = root_db
    provider.bind(root_db.project_file, "main", 0x5000)
    provider.functions[0].mlil.instructions = [call(0x1010, 0x5000)]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert bridge.loads == ["provider"]
    assert set(context.views) == {"root", "provider"}
    assert context.resolve(provider, 0x5000).view is root
    assert context.metadata()["files"][0]["aliases"] == ["root-database"]
    sites = context.callers(root, root.functions[0])
    assert len(sites) == 1 and sites[0].view is provider


def test_dependency_database_alias_reuses_prepared_raw_provider(module, graph):
    bridge, root, provider, other, make = graph
    database = make("provider-database", "provider.bndb", b"SQLite format 3\0")
    bridge.projects.entries.append(database.project_file)
    bridge.available[database.project_file.id] = database
    bridge.targets.loaded.append(provider)
    bridge.targets.ids[provider] = "already-open-provider"
    provider.bind(other.project_file, "entry", 0x5000)
    other.bind(database.project_file, "entry", 0x5000)
    other.functions[0].mlil.instructions = [call(0x1010, 0x5000)]
    context, _ = module.prepare(bridge, None, {}, reverse=False)
    assert bridge.loads == ["other"]
    assert context.resolve(other, 0x5000).view is provider
    assert set(context.views) == {"root", "provider", "other"}
    assert {site.view for site in context.callers(provider, provider.functions[0])} == {root, other}
