"""Request-local, explicitly bound cross-project call resolution.

Preparation owns all loading; traversal only reads the pinned views. Providers
remain ordinary bridge-owned targets, never temporary views or implicit saves.
"""
from __future__ import annotations

from collections import deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import os
from typing import Any, Iterator


_active: ContextVar[ProjectAnalysis | None] = ContextVar("project_analysis", default=None)
_IMPORT_TYPES = {"ImportAddressSymbol", "ImportedFunctionSymbol", "ImportedDataSymbol", "ExternalSymbol"}
_EXPORT_TYPES = {"FunctionSymbol", "LibraryFunctionSymbol"}
_MAX_INSTRUCTIONS = 200000


def current(bv=None) -> ProjectAnalysis | None:
    context = _active.get()
    return context if context is not None and (bv is None or bv in context._file_ids) else None


def _enum_name(value: Any) -> str:
    return str(getattr(value, "name", value)).rsplit(".", 1)[-1]


def _names(symbol: Any) -> set[str]:
    return {str(value) for value in (getattr(symbol, "raw_name", None), getattr(symbol, "name", None)) if value}


def _import_name(name: str) -> str:
    # Only used to find an ExternalLocation in the *source* view. The bound
    # target_symbol itself is never stripped or searched in another library.
    if name.startswith("__imp_"):
        name = name[6:]
    return name.split("@", 1)[0]


def _locations(bv) -> list[Any]:
    getter = getattr(bv, "get_external_locations", None)
    return list(getter() or ()) if callable(getter) else []


def _instructions(function) -> Iterator[Any]:
    il = getattr(function, "mlil", None)
    if il is None:
        il = getattr(function, "medium_level_il", None)
    if il is None:
        return
    # Native MLIL functions iterate basic blocks; .instructions is a flat,
    # lazy iterable and also accommodates the existing bridge IL fakes.
    flat = getattr(il, "instructions", None)
    if flat is not None:
        yield from flat
    else:
        for block in il:
            if hasattr(block, "operation"):
                yield block
            else:
                yield from block


def _dest_facts(dest) -> tuple[int | None, str | None]:
    if isinstance(dest, int):
        return dest, None
    operation = _enum_name(getattr(dest, "operation", ""))
    if "LOAD" in operation:
        return _dest_facts(getattr(dest, "src", None))
    address = getattr(dest, "constant", None)
    if not isinstance(address, int):
        address = None
    return address, getattr(dest, "name", None)


@dataclass(frozen=True)
class ResolvedProjectCall:
    view: Any | None
    function: Any | None
    address: int | None
    status: str
    reason: str | None
    source: dict[str, Any]
    target: dict[str, Any] | None
    cross_file: bool


@dataclass(frozen=True)
class ProjectCallSite:
    view: Any
    function: Any
    address: int
    instruction: Any
    target_view: Any
    target_function: Any


@dataclass(frozen=True)
class _NativeEndpoint:
    """Confirmed source-local call destination without an analyzed body."""
    start: int
    name: str
    view: Any


class ProjectAnalysis:
    def __init__(self, bridge, root_view, root_row, state, files, *,
                 max_files=16, max_depth=8, max_functions=4096):
        from .bridge import _request_cancelled
        self._cancelled = _request_cancelled
        self.root_view = root_view
        self.project_id = str(state.project_id)
        self.views: dict[str, Any] = {}
        self.limits = {"max_files": max_files, "max_depth": max_depth,
                       "max_functions": max_functions, "max_instructions": _MAX_INSTRUCTIONS}
        self._state = state
        self._project_handle = state.project
        self._project_path = state.path
        self._bridge = bridge
        self._files = {str(pf.id): pf for pf in files}
        self._paths = {str(pf.id): bridge.projects.path_in_project(pf) for pf in files}
        self._file_ids: dict[Any, str] = {}
        self._rows: dict[str, dict[str, Any]] = {}
        self._aliases: dict[str, str] = {}
        self._ambiguous_files: set[str] = set()
        self._boundaries: list[dict[str, Any]] = []
        self._boundary_keys: set[str] = set()
        self._reverse: dict[tuple[str, int], list[ProjectCallSite]] | None = None
        self._location_cache: dict[str, tuple[dict[int, list[Any]], dict[str, list[Any]]]] = {}
        self._add(root_view, root_row, loaded=False)
        self.root_file_id = self.file_id(root_view)

    @contextmanager
    def activate(self):
        token = _active.set(self)
        try:
            yield self
        finally:
            _active.reset(token)

    def _add(self, bv, row, *, loaded):
        file_id = str(row["project_file_id"])
        self.views[file_id] = bv
        self._file_ids[bv] = file_id
        self._rows[file_id] = {
            "project_file_id": file_id,
            "project_path": self._paths[file_id],
            "target_id": str(row["target_id"]), "loaded": loaded,
        }
        native_pf = getattr(bv, "project_file", None)
        if native_pf is not None and str(native_pf.id) != file_id:
            self._aliases[str(native_pf.id)] = file_id
        from .bridge import _quick_loaded_views, _unanalyzed_views
        if bv in _quick_loaded_views or bv in _unanalyzed_views:
            self.boundary("provider_unanalyzed", bv=bv)

    def file_id(self, bv) -> str:
        return self._file_ids[bv]

    def view_for_function(self, function):
        view = getattr(function, "view", None)
        file_id = self._file_ids.get(view)
        return self.views.get(file_id) if file_id is not None else None

    def identity(self, bv, function=None, address=None) -> dict[str, Any]:
        file_id = self.file_id(bv)
        result = {"project_file_id": file_id, "project_path": self._paths[file_id]}
        if function is not None:
            result["function"] = str(function.name)
            if address is None:
                address = function.start
        if address is not None:
            result["address"] = hex(int(address))
        return result

    def function_key(self, bv, function) -> tuple[str, int]:
        return self.file_id(bv), int(function.start)

    def boundary(self, reason, *, bv=None, address=None, symbol=None, detail=None):
        row = {"reason": str(reason)}
        if bv is not None:
            row.update(self.identity(bv, address=address))
        elif address is not None:
            row["address"] = hex(int(address))
        if symbol is not None:
            row["symbol"] = str(symbol)
        if detail is not None:
            row["detail"] = detail
        key = repr(row)
        if key not in self._boundary_keys:
            self._boundary_keys.add(key)
            self._boundaries.append(row)

    def metadata(self) -> dict[str, Any]:
        files = []
        for file_id, row in self._rows.items():
            aliases = sorted(alias for alias, canonical in self._aliases.items() if canonical == file_id)
            files.append({**row, "aliases": aliases})
        truncated = any(row["reason"] in {"file_limit", "depth_limit", "function_limit", "instruction_limit"}
                        for row in self._boundaries)
        return {"project_id": self.project_id, "root_file_id": self.root_file_id,
                "files": files, "limits": dict(self.limits), "truncated": truncated,
                "complete": not self._boundaries, "boundaries": list(self._boundaries)}

    def annotate(self, result: dict) -> dict:
        result["project_analysis"] = self.metadata()
        return result

    def _check_cancelled(self):
        if self._cancelled():
            raise RuntimeError("request cancelled during project analysis")

    def validate(self, bridge):
        """Called under the dispatch read gate, including after every load gap."""
        self._check_cancelled()
        if (bridge is not self._bridge or bridge.projects.current is not self._state
                or self._state.project != self._project_handle
                or str(self._state.project_id) != self.project_id
                or self._state.path != self._project_path):
            raise RuntimeError("Project changed during analysis preparation; retry the request")
        rows = bridge.targets.refresh()
        live_files = {str(pf.id): pf for pf in bridge.projects.files()}
        for file_id, bv in self.views.items():
            row = bridge._loaded_target_row(rows, bv)
            if (file_id not in live_files or not _same_file(live_files[file_id], self._files[file_id])
                    or row is None or str(row.get("target_id")) != self._rows[file_id]["target_id"]
                    or str(row.get("project_file_id")) != file_id
                    or not _belongs(bridge, self._state, bv, live_files[file_id])):
                raise RuntimeError("Project analysis target closed or replaced during preparation; retry the request")

    def _location_index(self, bv):
        file_id = self.file_id(bv)
        if file_id not in self._location_cache:
            addresses: dict[int, list[Any]] = {}
            names: dict[str, list[Any]] = {}
            for location in _locations(bv):
                symbol = getattr(location, "source_symbol", None)
                address = getattr(symbol, "address", None)
                if address is not None:
                    addresses.setdefault(int(address), []).append(location)
                for name in _names(symbol):
                    names.setdefault(name, []).append(location)
            self._location_cache[file_id] = addresses, names
        return self._location_cache[file_id]

    def _failure(self, bv, address, name, reason, *, ambiguous=False, detail=None,
                 record_boundary=True):
        if record_boundary:
            self.boundary(reason, bv=bv, address=address, symbol=name, detail=detail)
        return ResolvedProjectCall(None, None, None, "ambiguous" if ambiguous else "unresolved",
                                   reason, self.identity(bv, address=address), None, False)

    def _success(self, bv, address, target_bv, function):
        return ResolvedProjectCall(target_bv, function, int(function.start), "resolved", None,
                                   self.identity(bv, address=address), self.identity(target_bv, function),
                                   self.file_id(bv) != self.file_id(target_bv))

    def _bound_target(self, bv, address, name, locations, *, record_boundary=True):
        candidates = {}
        failures = []
        for location in locations:
            library = getattr(location, "library", None)
            backing = getattr(library, "backing_file", None)
            if backing is None:
                failures.append("unbound_external")
                continue
            backing_id = str(backing.id)
            if backing_id in self._ambiguous_files:
                failures.append("ambiguous_database")
                continue
            if backing_id not in self._files or not _same_file(backing, self._files[backing_id]):
                failures.append("missing_project_file")
                continue
            target_bv = self.views.get(self._aliases.get(backing_id, backing_id))
            if target_bv is None:
                failures.append("provider_unavailable")
                continue
            target_address = getattr(location, "target_address", None)
            target_name = getattr(location, "target_symbol", None)
            names = {str(target_name)} if target_name else _names(getattr(location, "source_symbol", None))
            matches = []
            if target_address is not None:
                function = target_bv.get_function_at(int(target_address))
                if function is None and int(target_address) & 1:
                    function = target_bv.get_function_at(int(target_address) & ~1)
                if function is not None:
                    matches.append(function)
            else:
                for export_name in names:
                    getter = getattr(target_bv, "get_symbols_by_raw_name", None)
                    symbols = list(getter(export_name) or ()) if callable(getter) else []
                    if not symbols:
                        getter = getattr(target_bv, "get_symbols_by_name", None)
                        symbols = list(getter(export_name) or ()) if callable(getter) else []
                    for symbol in symbols:
                        if _enum_name(getattr(symbol, "type", "")) not in _EXPORT_TYPES:
                            continue
                        binding = _enum_name(getattr(symbol, "binding", ""))
                        if binding not in {"GlobalBinding", "WeakBinding"}:
                            continue
                        function = target_bv.get_function_at(int(symbol.address))
                        if function is not None:
                            matches.append(function)
            if not matches:
                failures.append("missing_export")
            for function in matches:
                candidates[self.function_key(target_bv, function)] = (target_bv, function)
        if len(candidates) == 1 and not failures:
            target_bv, function = next(iter(candidates.values()))
            return self._success(bv, address, target_bv, function)
        if len(candidates) > 1 or (candidates and failures):
            return self._failure(bv, address, name, "ambiguous_external", ambiguous=True,
                                 record_boundary=record_boundary)
        if "ambiguous_database" in failures:
            return self._failure(bv, address, name, "ambiguous_database", ambiguous=True,
                                 record_boundary=record_boundary)
        return self._failure(bv, address, name, failures[0] if failures else "unbound_external",
                             record_boundary=record_boundary)

    def resolve(self, bv, address: int | None, name: str | None = None, *,
                record_boundary: bool = True) -> ResolvedProjectCall:
        """Resolve an endpoint; nonreporting probes allow map/VSA fallbacks."""
        self._check_cancelled()
        return self._resolve(bv, address, name, set(), record_boundary=record_boundary)

    def _resolve(self, bv, address, name, seen, *, record_boundary=True):
        if address is not None:
            address = int(address)
        key = (self.file_id(bv), address, name)
        if key in seen or len(seen) >= self.limits["max_depth"] + 1:
            return self._failure(bv, address, name, "thunk_cycle" if key in seen else "depth_limit",
                                 record_boundary=record_boundary)
        seen.add(key)
        function = bv.get_function_at(address) if address is not None else None
        if function is None and address is not None and address & 1:
            function = bv.get_function_at(address & ~1)
        getter = getattr(bv, "get_symbol_at", None)
        symbol = getter(address) if address is not None and callable(getter) else None
        imported = _enum_name(getattr(symbol, "type", "")) in _IMPORT_TYPES
        by_address, _ = self._location_index(bv)
        locations = by_address.get(address, [])
        # A real local definition wins over unrelated imports with the same name.
        if not locations and function is not None and not imported:
            thunk = self._thunk(function) if getattr(function, "is_thunk", False) else None
            if thunk is not None:
                destination = getattr(thunk, "dest", None)
                target_address, target_name = _dest_facts(destination)
                concrete = self._value_targets(bv, destination)
                if len(concrete) > 1:
                    return self._failure(bv, address, name, "multiple_indirect_targets", ambiguous=True,
                                         record_boundary=record_boundary)
                if concrete:
                    target_address, target_name = concrete[0], None
                elif ("LOAD" in _enum_name(getattr(destination, "operation", ""))
                      and not self._matching_locations(bv, target_address, target_name)):
                    return self._failure(bv, address, name, "unresolved_indirect_call",
                                         record_boundary=record_boundary)
                if target_address is not None or target_name:
                    result = self._resolve(bv, target_address, target_name, seen,
                                           record_boundary=record_boundary)
                    if result.status == "resolved":
                        return self._success(bv, address, result.view, result.function)
                    return ResolvedProjectCall(None, None, None, result.status, result.reason,
                                               self.identity(bv, address=address), None, False)
            return self._success(bv, address, bv, function)
        if not locations:
            locations = self._matching_locations(bv, address, name, symbol)
        if locations:
            return self._bound_target(bv, address, name or getattr(symbol, "name", None), locations,
                                      record_boundary=record_boundary)
        if function is not None and not imported:
            return self._success(bv, address, bv, function)
        return self._failure(bv, address, name or getattr(symbol, "name", None),
                             "unbound_external" if imported or name else "unresolved_call",
                             record_boundary=record_boundary)

    def _matching_locations(self, bv, address, name=None, symbol=None):
        by_address, by_name = self._location_index(bv)
        locations = list(by_address.get(address, ()))
        if locations:
            return locations
        if symbol is None and address is not None:
            symbol = bv.get_symbol_at(address)
        search_names = _names(symbol)
        if name:
            search_names.add(str(name))
        # Native GOT relocations identify the import even for unnamed slots.
        relocations = getattr(bv, "relocations_at", None)
        if address is not None and callable(relocations):
            for relocation in relocations(address):
                relocation_symbol = getattr(relocation, "symbol", None)
                search_names.update(_names(relocation_symbol))
                locations.extend(by_address.get(getattr(relocation_symbol, "address", None), ()))
        if not locations:
            for symbol_name in search_names:
                locations.extend(by_name.get(symbol_name, ()))
        if not locations:
            normalized = {_import_name(item) for item in search_names}
            for source_name, source_locations in by_name.items():
                if _import_name(source_name) in normalized:
                    locations.extend(source_locations)
        return locations

    def _value_targets(self, bv, destination):
        """Concrete pointees, not the storage address inside MLIL_LOAD."""
        from .taint_il import targets_from_pvs
        address, name = _dest_facts(destination)
        load = "LOAD" in _enum_name(getattr(destination, "operation", ""))
        if address is not None and not load:
            return []
        if any(getattr(getattr(location, "library", None), "backing_file", None) is not None
               for location in self._matching_locations(bv, address, name)):
            return []  # An explicit bound GOT/import location is authoritative.
        return targets_from_pvs(getattr(destination, "possible_values", None))

    def indirect_targets(self, bv, instruction) -> list[int]:
        """Source-local VSA candidates, respecting authoritative import bindings."""
        self._check_cancelled()
        return self._value_targets(bv, getattr(instruction, "dest", None))

    @staticmethod
    def _thunk(function):
        iterator = _instructions(function)
        first = next(iterator, None)
        if first is not None and "TAILCALL" in _enum_name(getattr(first, "operation", "")):
            if next(iterator, None) is None:
                return first
        return None

    def resolve_call(self, bv, instruction, *, record_boundary: bool = True) -> ResolvedProjectCall:
        from .taint_il import resolve_call_target
        self._check_cancelled()
        destination = getattr(instruction, "dest", None)
        concrete = self._value_targets(bv, destination)
        if len(concrete) == 1:
            return self.resolve(bv, concrete[0], record_boundary=record_boundary)
        if concrete:
            return self._failure(bv, None, None, "multiple_indirect_targets", ambiguous=True,
                                 record_boundary=record_boundary)
        target = resolve_call_target(bv, instruction)
        address, name = _dest_facts(destination)
        # A load's address is a storage slot, never a direct callee. Preserve
        # it only when explicit import facts tie it to an ExternalLocation.
        if "LOAD" in _enum_name(getattr(destination, "operation", "")):
            locations = self._matching_locations(bv, address, name)
            if locations:
                return self._bound_target(bv, address, name, locations, record_boundary=record_boundary)
            return self._failure(bv, None, name, "unresolved_indirect_call",
                                 record_boundary=record_boundary)
        if address is None:
            address = target.address
        return self.resolve(bv, address, name, record_boundary=record_boundary)

    def callers(self, bv, function) -> list[ProjectCallSite]:
        if self._reverse is None:
            self._build_reverse()
        return list(self._reverse.get(self.function_key(bv, function), ()))

    def _build_reverse(self):
        index: dict[tuple[str, int], list[ProjectCallSite]] = {}
        seen = set()
        function_count = instruction_count = 0
        for bv in self.views.values():
            for function in bv.functions:
                self._check_cancelled()
                if function_count >= self.limits["max_functions"]:
                    self.boundary("function_limit", bv=bv)
                    self._reverse = index
                    return
                function_count += 1
                if getattr(function, "mlil", None) is None and getattr(function, "medium_level_il", None) is None:
                    self.boundary("missing_il", bv=bv, address=function.start)
                    continue
                symbol = getattr(function, "symbol", None)
                veneer = _enum_name(getattr(symbol, "type", "")) in _IMPORT_TYPES
                sections_at = getattr(bv, "get_sections_at", None)
                if callable(sections_at):
                    veneer = veneer or any(
                        getattr(section, "name", "") in {
                            ".plt", ".plt.got", ".plt.sec", ".iplt", "__stubs", "__auth_stubs"}
                        for section in sections_at(function.start))
                for instruction in _instructions(function):
                    if instruction_count % 1024 == 0:
                        self._check_cancelled()
                    if instruction_count >= self.limits["max_instructions"]:
                        self.boundary("instruction_limit", bv=bv)
                        self._reverse = index
                        return
                    instruction_count += 1
                    operation = _enum_name(getattr(instruction, "operation", ""))
                    if "CALL" not in operation or "SYSCALL" in operation or veneer:
                        continue
                    concrete = self.indirect_targets(bv, instruction)
                    targets = ([self.resolve(bv, address) for address in concrete]
                               if concrete else [self.resolve_call(bv, instruction)])
                    for target in targets:
                        target_view, target_function = target.view, target.function
                        if target.status != "resolved":
                            # Retain actual local call evidence, without
                            # inventing a provider body for unresolved imports.
                            source_address = target.source.get("address")
                            if source_address is None:
                                continue
                            local_address = int(source_address, 16)
                            local_symbol = bv.get_symbol_at(local_address)
                            target_view = bv
                            target_function = _NativeEndpoint(
                                local_address, str(getattr(local_symbol, "name", hex(local_address))), bv)
                        target_key = self.function_key(target_view, target_function)
                        site_address = int(instruction.address)
                        key = (self.function_key(bv, function), site_address, target_key)
                        if key in seen:
                            continue
                        seen.add(key)
                        index.setdefault(target_key, []).append(ProjectCallSite(
                            bv, function, site_address, instruction, target_view, target_function))
        self._reverse = index


def _same_file(left, right) -> bool:
    return (str(left.id) == str(right.id)
            and os.path.realpath(str(left.path_on_disk)) == os.path.realpath(str(right.path_on_disk)))


def _belongs(bridge, state, bv, canonical_file) -> bool:
    pf = getattr(bv, "project_file", None)
    if pf is None:
        return False
    project = getattr(pf, "project", None)
    if project is not None and str(project.id) != str(state.project_id):
        return False
    binding = bridge.targets.project_binding(bv)
    if binding is not None and str(binding[0]) == str(canonical_file.id):
        native = next((item for item in bridge.projects.files() if str(item.id) == str(pf.id)), None)
        return native is not None and _same_file(pf, native)
    return _same_file(pf, canonical_file)


def _binary_candidate(pf, path) -> bool:
    if ".bn-findings" in path.split("/"):
        return False
    try:
        with open(pf.path_on_disk, "rb") as stream:
            magic = stream.read(16)
    except OSError:
        return False
    return (magic.startswith((b"\x7fELF", b"MZ", b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
                              b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
                              b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"))
            or (path.lower().endswith(".bndb") and magic == b"SQLite format 3\x00"))


def prepare(bridge, selector, params, *, reverse: bool) -> tuple[ProjectAnalysis | None, str | None]:
    # Do not even resolve the target on the ordinary standalone dispatch path:
    # its existing binder controls validation and error ordering.
    if bridge.projects.current is None:
        return None, None
    enabled = params.get("project", True)
    if not isinstance(enabled, bool):
        raise ValueError("project must be a boolean")
    if not enabled:
        return None, None
    with bridge._target_lock.read():
        root, rows = bridge.targets.resolve_with_snapshot(selector)
        root_row = bridge._loaded_target_row(rows, root)
        state = bridge.projects.current
        if state is None or root_row is None or not root_row.get("project_file_id"):
            return None, None
        files = bridge.projects.files()
        by_id = {str(pf.id): pf for pf in files}
        root_pf = by_id.get(str(root_row["project_file_id"]))
        if root_pf is None or not _belongs(bridge, state, root, root_pf):
            return None, None
        limits = {}
        for name, default, maximum in (("max_files", 16, 256), ("max_depth", 8, 64),
                                       ("max_functions", 4096, 100000)):
            value = params.get("project_" + name, default)
            if type(value) is not int or not 1 <= value <= maximum:
                raise ValueError(f"project_{name} must be an integer between 1 and {maximum}")
            limits[name] = value
        context = ProjectAnalysis(bridge, root, root_row, state, files, **limits)
        siblings = bridge.projects.sibling_index(files)

    attempted = set()
    queue = deque([(context.root_file_id, 0)])
    expanded = set()

    def canonical(file_id):
        if file_id in context._aliases:
            return context._aliases[file_id]
        if file_id in context.views:
            return file_id
        path = context._paths[file_id]
        database = path.lower().endswith(".bndb")
        partner_path = path[:-5] if database else path + ".bndb"
        partners = siblings.get(partner_path, [])
        # Canonicalize pairs on every acquisition route, not only reverse
        # discovery. Whichever member is already prepared (especially the
        # selected root) stays the identity for both dependency spellings.
        if len(partners) == 1 and len(siblings.get(path, [])) == 1:
            partner_id = str(partners[0].id)
            if partner_id in context.views:
                context._aliases[file_id] = partner_id
                return partner_id
        with bridge._target_lock.read():
            context.validate(bridge)
            if bridge.targets.view_for_project_file(file_id) is not None:
                return file_id
        if not path.lower().endswith(".bndb"):
            matches = siblings.get(path + ".bndb", [])
            if len(matches) > 1:
                context._ambiguous_files.add(file_id)
                context.boundary("ambiguous_database", detail={"project_file_id": file_id})
                return None
            if len(matches) == 1:
                actual = str(matches[0].id)
                context._aliases[file_id] = actual
                return actual
        return file_id

    def obtain(file_id, depth):
        actual = canonical(file_id)
        if actual is None:
            return
        if actual in context.views:
            queue.append((actual, depth))
            return
        if actual in attempted:
            return
        if depth > limits["max_depth"]:
            context.boundary("depth_limit", detail={"project_file_id": actual, "depth": depth})
            return
        attempted.add(actual)
        if len(context.views) >= limits["max_files"]:
            context.boundary("file_limit", detail={"project_file_id": actual})
            return
        loaded = False
        with bridge._target_lock.read():
            context.validate(bridge)
            bv = bridge.targets.view_for_project_file(actual)
            if bv is not None and not _belongs(bridge, state, bv, by_id[actual]):
                raise RuntimeError("Project provider identity changed during preparation")
            expected_view = bv
            expected_row = bridge._loaded_target_row(bridge.targets.refresh(), bv) if bv is not None else None
        if bv is None:
            try:
                result = bridge._project_load(actual, prefer_bndb=False, quick=False, link=True)
                loaded = bool(result.get("loaded"))
                expected_row = result.get("target")
                if result.get("analysis_state") in {"quick", "unanalyzed"}:
                    context.boundary("provider_unanalyzed", detail={"project_file_id": actual})
            except Exception as exc:
                if str(exc).startswith("busy:"):
                    raise
                with bridge._target_lock.read():
                    context.validate(bridge)
                context.boundary("provider_load_failed", detail={"project_file_id": actual, "error": str(exc)})
                return
        with bridge._target_lock.read():
            context.validate(bridge)
            rows = bridge.targets.refresh()
            bv = bridge.targets.view_for_project_file(actual)
            row = bridge._loaded_target_row(rows, bv) if bv is not None else None
            if (row is None or expected_row is None
                    or str(row["target_id"]) != str(expected_row["target_id"])
                    or (expected_view is not None and bv != expected_view)
                    or not _belongs(bridge, state, bv, by_id[actual])):
                raise RuntimeError("Project provider closed or replaced during preparation")
            context._add(bv, row, loaded=loaded)
            queue.append((actual, depth))

    def expand():
        while queue:
            file_id, depth = queue.popleft()
            if file_id in expanded:
                continue
            expanded.add(file_id)
            with bridge._target_lock.read():
                context.validate(bridge)
                bv = context.views[file_id]
                getter = getattr(bv, "get_external_libraries", None)
                libraries = list(getter() or ()) if callable(getter) else list(getattr(bv, "libraries", ()) or ())
                libraries.extend(getattr(loc, "library", None) for loc in _locations(bv))
                dependencies = {}
                for library in libraries:
                    backing = getattr(library, "backing_file", None)
                    if backing is None:
                        continue  # Unused unlinked imports are not request boundaries.
                    dependency = str(backing.id)
                    if dependency not in by_id or not _same_file(backing, by_id[dependency]):
                        context.boundary("missing_project_file", bv=bv, detail={"project_file_id": dependency})
                    else:
                        dependencies[dependency] = backing
            for dependency in sorted(dependencies, key=lambda item: (context._paths[item], item)):
                obtain(dependency, depth + 1)

    expand()
    if reverse:
        # Snapshot membership was taken under the gate. Header sniffing never
        # opens a BinaryView and excludes ledger JSON and arbitrary data blobs.
        candidates = sorted(by_id, key=lambda item: (context._paths[item], item))
        for file_id in candidates:
            if file_id in context.views or file_id in context._aliases:
                continue
            if _binary_candidate(by_id[file_id], context._paths[file_id]):
                obtain(file_id, 0)
                expand()
    with bridge._target_lock.read():
        context.validate(bridge)
    return context, str(root_row["target_id"])
