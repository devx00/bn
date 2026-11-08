"""Source-only ELF chain exercised through the real project/analysis CLI.

Uses the existing project lane's native-edition gate and private bridge lifecycle.
Build products, projects and databases live only under pytest temporary paths.
No fixture function has a synthetic taint model: provider bodies must be followed.
"""
from __future__ import annotations

import shutil
import subprocess
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

import pytest
from conftest import find_rootfs_cross_compiler, refuse_silent_skip, require_real_bn
from test_project_integration import (
    Lane,
    _cache_dir_within_socket_budget,
    _require_project_edition,
    _rootfs_init,
    _rootfs_link,
    _start_instance,
    _stop_instance,
)

pytestmark = pytest.mark.real_bn
SOURCES = Path(__file__).parent / "fixtures" / "project_cross"
ROOT = "/usr/bin/cross-app"
A = "/opt/cross/lib/libcross_a.so"
B = "/opt/cross/lib/libcross_b.so"
ANALYSIS_TIMEOUT = 240.0


@pytest.fixture(scope="module")
def cross_binaries(_hermetic_session_env, tmp_path_factory) -> Path:
    require_real_bn()
    _require_project_edition()
    compiler = find_rootfs_cross_compiler()
    if compiler is None:
        refuse_silent_skip("project cross-analysis needs a Linux musl cross compiler; set CROSS_CC")
    if shutil.which("make") is None:
        pytest.fail("project cross-analysis fixture needs make", pytrace=False)
    root = tmp_path_factory.mktemp("project-cross-build") / "firmware"
    built = subprocess.run(
        ["make", "-C", str(SOURCES), f"CROSS_CC={compiler}", f"OUT={root}", "all"],
        capture_output=True, text=True, timeout=120.0,
    )
    assert built.returncode == 0, f"fixture build failed:\n{built.stdout}\n{built.stderr}"
    for path in (ROOT, A, B, "/etc/ld.so.conf"):
        assert (root / path.lstrip("/")).is_file(), path
    return root


@contextmanager
def _private_lane(tmp_path_factory, root: Path) -> Iterator[Lane]:
    instance_id = f"cross-{uuid.uuid4().hex[:8]}"
    cache, fallback = _cache_dir_within_socket_budget(tmp_path_factory, instance_id)
    lane = Lane(instance_id, cache, root.with_suffix(".bnpr"), cli_available=True)
    with pytest.MonkeyPatch.context() as env:
        env.setenv("BN_CACHE_DIR", str(cache))
        env.setenv("BN_DISABLE_USER_PLUGINS", "1")
        env.setenv("BN_REQUEST_TIMEOUT", str(int(ANALYSIS_TIMEOUT)))
        _start_instance(instance_id, lane.env())
        try:
            yield lane
        finally:
            _stop_instance(instance_id, lane.env())
            if fallback:
                shutil.rmtree(cache, ignore_errors=True)


@dataclass
class CrossProject:
    lane: Lane
    root: Path
    files: dict[str, str]

    def analysis(self, target: str, *args: str) -> dict[str, Any]:
        return self.lane.json(*args, "-t", self.files[target], timeout=ANALYSIS_TIMEOUT)

    def load(self, path: str) -> None:
        self.lane.project_load(self.files[path], prefer_bndb=False)


def _open_project(lane: Lane, root: Path) -> CrossProject:
    _rootfs_init(lane, root)
    lane.project_import(root / ROOT.lstrip("/"), "usr/bin")
    files = {row["path"]: row["id"] for row in lane.project_files()}
    assert {ROOT, A, B} <= files.keys(), files
    files = {path: files[path] for path in (ROOT, A, B)}
    project = CrossProject(lane, root, files)
    project.load(ROOT)
    # project_link's preview reads the native ExternalLocation.library binding;
    # library names alone in an ELF import table are not sufficient evidence.
    preview = _rootfs_link(lane, files[ROOT])
    locations = {row["symbol"]: row["library"] for row in preview["locations"]}
    for suffix in ("sink", "return", "buffer", "out", "safe", "source_return", "source_out"):
        assert locations[f"cross_a_{suffix}"] == "libcross_a.so", preview
    return project


@pytest.fixture(scope="module")
def _cross_project(cross_binaries, tmp_path_factory) -> Iterator[CrossProject]:
    root = Path(shutil.copytree(cross_binaries, tmp_path_factory.mktemp("cross-project") / "firmware"))
    with _private_lane(tmp_path_factory, root) as lane:
        yield _open_project(lane, root)


@pytest.fixture
def cross_project(_cross_project, monkeypatch) -> CrossProject:
    monkeypatch.setenv("BN_CACHE_DIR", str(_cross_project.lane.cache_dir))
    monkeypatch.setenv("BN_DISABLE_USER_PLUGINS", "1")
    monkeypatch.setenv("BN_REQUEST_TIMEOUT", str(int(ANALYSIS_TIMEOUT)))
    return _cross_project


def _qualified(row: dict[str, Any], project: CrossProject, path: str) -> None:
    assert row["project_file_id"] == project.files[path], row
    assert row["project_path"] == path, row


def _objects(value: Any) -> Iterator[dict[str, Any]]:
    """Visit nested endpoint dictionaries without flattening away identities."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _objects(child)


def _assert_body_path(value: Any, project: CrossProject, suffix: str) -> None:
    for path, prefix in ((A, "cross_a_"), (B, "cross_b_")):
        function = prefix + suffix
        matches = [row for row in _objects(value)
                   if row.get("project_file_id") == project.files[path]
                   and (row.get("name") == function or row.get("function") == function
                        or isinstance(row.get("function"), dict)
                        and row["function"].get("name") == function)]
        assert matches, f"missing qualified body {path}:{function}: {value}"
        assert all(row["project_path"] == path for row in matches)


def _forward(project: CrossProject, suffix: str, *extra: str) -> dict[str, Any]:
    return project.analysis(ROOT, "taint", "forward", "-f", f"cross_entry_{suffix}",
                            "--source", "param:0", "--verbose", *extra)


@pytest.mark.parametrize("suffix,sink_file", [
    ("sink", B), ("return", ROOT), ("buffer", ROOT), ("out", ROOT), ("anchor", B),
])
def test_forward_follows_real_provider_bodies(cross_project, suffix, sink_file):
    project = cross_project
    result = _forward(project, suffix)
    _qualified(result["function"], project, ROOT)
    assert result["project_analysis"]["root_file_id"] == project.files[ROOT]
    assert result["sources"], result
    for source in result["sources"]:
        _qualified(source, project, ROOT)
    findings = [finding for finding in result["reached_sinks"]
                if finding["sink"]["callee"] == "system"
                and finding["sink"]["tainted_arg_index"] == 0]
    assert findings, result
    for finding in findings:
        _qualified(finding["sink"], project, sink_file)
    # This excludes an unknown-call conservative fallback that only happens to
    # reach the root sink: BOTH real provider bodies must appear in the path.
    assert any(_has_body_path(finding["path"], project, suffix) for finding in findings), findings


def _has_body_path(value: Any, project: CrossProject, suffix: str) -> bool:
    try:
        _assert_body_path(value, project, suffix)
    except AssertionError:
        return False
    return True


def test_constant_provider_return_is_not_tainted(cross_project):
    result = _forward(cross_project, "safe")
    assert not any(row["sink"]["callee"] == "system" for row in result["reached_sinks"]), result
    files = {row["project_file_id"] for row in result["project_analysis"]["files"]}
    assert {cross_project.files[A], cross_project.files[B]} <= files


def test_backward_constant_provider_return_does_not_invent_input_origin(cross_project):
    project = cross_project
    result = project.analysis(ROOT, "taint", "backward", "-f", "cross_entry_safe",
                              "--sink", "arg:system:0", "--verbose")
    assert result["slices"], result
    assert not any(sl["origin"]["kind"] == "parameter"
                   for sl in result["slices"]), result
    constants = [sl for sl in result["slices"] if sl["origin"]["kind"] == "constant"]
    assert constants, result
    for sl in constants:
        _qualified(sl["origin"], project, B)
        _qualified(sl["sink"], project, ROOT)
    assert any(_has_body_path(sl["slice"], project, "safe") for sl in constants), constants


@pytest.mark.parametrize("suffix", ["return", "buffer", "out"])
def test_backward_follows_provider_return_and_output_writers(cross_project, suffix):
    project = cross_project
    result = project.analysis(ROOT, "taint", "backward", "-f", f"cross_entry_{suffix}",
                              "--sink", "arg:system:0", "--verbose")
    candidates = [sl for sl in result["slices"]
                  if sl["origin"]["kind"] == "parameter"
                  and sl["origin"].get("project_file_id") == project.files[ROOT]]
    assert candidates, result
    assert any(_has_body_path(sl["slice"], project, suffix) for sl in candidates), candidates


@pytest.mark.parametrize("mode", ["taint", "trace"])
@pytest.mark.parametrize("suffix", ["source_return", "source_out"])
def test_backward_reaches_provider_owned_sources(cross_project, suffix, mode):
    project = cross_project
    function = f"cross_entry_{suffix}"
    if mode == "taint":
        result = project.analysis(ROOT, "taint", "backward", "-f", function,
                                  "--sink", "arg:system:0", "--verbose")
    else:
        sites = project.analysis(ROOT, "callsites", "system", "--within", function)
        assert len(sites["items"]) == 1, sites
        result = project.analysis(ROOT, "trace", function, sites["items"][0]["call_addr"],
                                  "--arg", "0", "--interprocedural", "--ip-depth", "8")
    sources = [sl for sl in result["slices"]
               if sl["origin"].get("callee") == "getenv" and sl["origin"]["kind"] == "source"]
    assert sources, result
    for sl in sources:
        _qualified(sl["origin"], project, B)
        _qualified(sl["sink"], project, ROOT)
    assert any(_has_body_path(sl["slice"], project, suffix) for sl in sources), sources


@pytest.mark.parametrize("mode", ["taint", "trace"])
def test_backward_preserves_caller_writes_to_provider_returned_buffer(cross_project, mode):
    project = cross_project
    function = "cross_entry_modified_return"
    if mode == "taint":
        result = project.analysis(ROOT, "taint", "backward", "-f", function,
                                  "--sink", "arg:system:0", "--verbose")
    else:
        sites = project.analysis(ROOT, "callsites", "system", "--within", function)
        assert len(sites["items"]) == 1, sites
        result = project.analysis(ROOT, "trace", function, sites["items"][0]["call_addr"],
                                  "--arg", "0", "--interprocedural", "--ip-depth", "8")
    sources = [sl for sl in result["slices"]
               if sl["origin"].get("callee") == "getenv"
               and sl["origin"]["kind"] == "source"
               and sl["origin"].get("project_file_id") == project.files[ROOT]]
    assert sources, result
    for sl in sources:
        _qualified(sl["origin"], project, ROOT)
        _qualified(sl["sink"], project, ROOT)
        assert any(step.get("project_file_id") == project.files[ROOT]
                   for step in sl["slice"]), sl


def test_backward_ascends_across_two_libraries(cross_project):
    project = cross_project
    project.load(B)
    result = project.analysis(B, "taint", "backward", "-f", "cross_b_sink",
                              "--sink", "arg:system:0", "--verbose")
    _qualified(result["function"], project, B)
    roots = [sl for sl in result["slices"]
             if sl["origin"]["kind"] == "parameter"
             and sl["origin"].get("project_file_id") == project.files[ROOT]]
    assert roots, result
    assert any("cross_a_sink" in sl.get("crossed_functions", [])
               and "cross_entry_sink" in sl.get("crossed_functions", []) for sl in roots), roots
    assert any(row.get("project_file_id") == project.files[A]
               for sl in roots for row in _objects(sl["slice"])), roots


def test_graph_uses_real_qualified_provider_and_consumer_endpoints(cross_project):
    project = cross_project
    project.load(A)
    graph = project.analysis(A, "dataflow", "callgraph", "cross_a_sink", "--direction", "both")
    _qualified(graph["function"], project, A)
    callees = [row for row in graph["callees"] if row.get("target", {}).get("name") == "cross_b_sink"]
    assert callees, graph
    for row in callees:
        _qualified(row["target"], project, B)
        _qualified(row["source"], project, A)
    callers = [row for row in graph["callers"] if row.get("caller", {}).get("name") == "cross_entry_sink"]
    assert callers, graph
    for row in callers:
        _qualified(row["caller"], project, ROOT)


def test_callsites_and_xrefs_reverse_index_are_file_qualified(cross_project):
    project = cross_project
    project.load(B)
    sites = project.analysis(B, "callsites", "cross_b_sink", "--limit", "100")
    callers = [row for row in sites["items"] if row.get("containing_function", {}).get("name") == "cross_a_sink"]
    assert callers, sites
    for row in callers:
        _qualified(row, project, A)
        _qualified(row["containing_function"], project, A)
        _qualified(row["callee"], project, B)
    xrefs = project.analysis(B, "xrefs", "cross_b_sink", "--limit", "100")
    refs = [row for row in xrefs["items"] if row.get("caller_function", {}).get("name") == "cross_a_sink"]
    assert refs, xrefs
    for row in refs:
        _qualified(row, project, A)
    _qualified(xrefs["target_context"], project, B)
    assert {row["call_addr"] for row in callers} <= {row["address"] for row in refs}
    keys = [(row["project_file_id"], row["address"], row["kind"]) for row in xrefs["items"]]
    assert len(keys) == len(set(keys)), xrefs
    for command, whole in (("callsites", sites), ("xrefs", xrefs)):
        first = project.analysis(B, command, "cross_b_sink", "--limit", "1")
        rest = project.analysis(B, command, "cross_b_sink", "--offset", "1", "--limit", "100")
        assert first["items"] + rest["items"] == whole["items"]
        if whole.get("total") is not None:
            assert whole["total"] == len(whole["items"])
        else:
            assert whole["total_lower_bound"] >= len(whole["items"])
    # --within remains restricted to the selected view, not a same-named
    # function from some unrelated project file.
    local = project.analysis(B, "callsites", "cross_b_sink", "--within", "cross_b_sink")
    assert not local["items"], local


def test_equal_virtual_addresses_do_not_merge_functions(cross_project):
    project = cross_project
    for path in (A, B):
        project.load(path)
    a = project.analysis(A, "dataflow", "callgraph", "cross_a_anchor", "--direction", "callees")
    b = project.analysis(B, "dataflow", "callgraph", "cross_b_anchor", "--direction", "callers")
    assert int(a["function"]["address"], 16) == int(b["function"]["address"], 16)
    _qualified(a["function"], project, A)
    _qualified(b["function"], project, B)
    target = next(row["target"] for row in a["callees"]
                  if row.get("target", {}).get("name") == "cross_b_anchor")
    _qualified(target, project, B)
    caller = next(row["caller"] for row in b["callers"]
                  if row.get("caller", {}).get("name") == "cross_a_anchor")
    _qualified(caller, project, A)


@pytest.mark.parametrize("option,limit", [
    ("--project-max-files", "1"), ("--project-max-depth", "1"),
])
def test_project_bounds_are_explicit_not_all_clear(cross_project, option, limit):
    result = _forward(cross_project, "sink", option, limit)
    metadata = result["project_analysis"]
    assert metadata["complete"] is False, result
    assert metadata["truncated"] is True, result
    assert metadata["boundaries"], result
    assert result["diagnostics"]["safe_to_report_all_clear"] is False, result


def test_reverse_function_scan_budget_is_disclosed(cross_project):
    project = cross_project
    project.load(B)
    result = project.analysis(B, "dataflow", "callgraph", "cross_b_sink",
                              "--direction", "callers", "--project-max-functions", "1")
    metadata = result["project_analysis"]
    assert metadata["complete"] is False, result
    assert metadata["truncated"] is True, result
    assert metadata["boundaries"], result
    assert result["complete"] is False, result


def test_unknown_provider_is_an_explicit_boundary(cross_project):
    result = _forward(cross_project, "unknown")
    assert result["project_analysis"]["complete"] is False, result
    assert any(row.get("symbol") == "cross_missing_provider"
               for row in result["project_analysis"]["boundaries"]), result
    assert result["diagnostics"]["safe_to_report_all_clear"] is False, result


def test_recursive_provider_terminates_and_retains_reachable_sink(cross_project):
    result = _forward(cross_project, "cycle", "--max-depth", "8")
    sinks = [row for row in result["reached_sinks"] if row["sink"]["callee"] == "system"]
    assert sinks, result
    for row in sinks:
        _qualified(row["sink"], cross_project, B)


def test_provider_loading_is_request_bounded_and_never_saves(cross_binaries, tmp_path_factory):
    root = Path(shutil.copytree(cross_binaries, tmp_path_factory.mktemp("cross-lazy") / "firmware"))
    with _private_lane(tmp_path_factory, root) as lane:
        project = _open_project(lane, root)
        initial = lane.target_rows()
        assert {row["project_file_id"] for row in initial} == {project.files[ROOT]}, initial
        file_ids = {row["id"] for row in lane.project_files()}
        disabled = _forward(project, "sink", "--no-project")
        assert "project_analysis" not in disabled
        assert {row["target_id"] for row in lane.target_rows()} == {row["target_id"] for row in initial}
        capped = _forward(project, "sink", "--project-max-files", "1")
        assert capped["project_analysis"]["truncated"] is True, capped
        assert capped["diagnostics"]["safe_to_report_all_clear"] is False, capped
        assert {row["target_id"] for row in lane.target_rows()} == {row["target_id"] for row in initial}
        result = _forward(project, "sink")
        files = {row["project_file_id"]: row for row in result["project_analysis"]["files"]}
        assert files[project.files[A]]["loaded"] is True
        assert files[project.files[B]]["loaded"] is True
        assert {row["project_file_id"] for row in lane.target_rows()} == set(project.files.values())
        assert {row["id"] for row in lane.project_files()} == file_ids
        assert not any(row.get("is_database") for row in lane.project_files())


@pytest.mark.parametrize("args", [
    ("taint", "forward", "-f", "cross_entry_return", "--source", "param:0", "--verbose"),
    ("taint", "backward", "-f", "cross_entry_return", "--sink", "arg:system:0", "--verbose"),
    ("taint", "forward", "-f", "cross_standalone_source", "--source", "ret:getenv", "--verbose"),
    ("taint", "backward", "-f", "cross_standalone_source", "--sink", "arg:system:0", "--verbose"),
    ("dataflow", "callgraph", "cross_entry_sink", "--direction", "both"),
    ("callsites", "cross_entry_sink"),
    ("xrefs", "cross_entry_sink"),
])
def test_standalone_shape_and_loading_are_unchanged(cross_project, tmp_path, args):
    project = cross_project
    # Raw copy outside the native project's data store has no ProjectFile, even
    # while another target in this very bridge owns an open project.
    binary = Path(shutil.copy2(project.root / ROOT.lstrip("/"), tmp_path / "standalone"))
    project.lane.json("load", str(binary), "--no-bndb", timeout=ANALYSIS_TIMEOUT)
    try:
        before = {row["target_id"] for row in project.lane.target_rows()}
        enabled = project.lane.json(*args, "-t", str(binary), timeout=ANALYSIS_TIMEOUT)
        disabled = project.lane.json(*args, "-t", str(binary), "--no-project", timeout=ANALYSIS_TIMEOUT)
        assert enabled == disabled
        assert "project_analysis" not in enabled
        assert not any("project_file_id" in row or "project_path" in row for row in _objects(enabled))
        assert {row["target_id"] for row in project.lane.target_rows()} == before
        if "cross_standalone_source" in args:
            if args[1] == "forward":
                assert any(row["sink"]["callee"] == "system"
                           for row in enabled["reached_sinks"]), enabled
            else:
                assert any(row["origin"].get("callee") == "getenv"
                           and row["origin"]["kind"] == "source"
                           for row in enabled["slices"]), enabled
    finally:
        project.lane.json("close", "-t", str(binary))
