"""Invalid project analysis controls are refused before issuing a request."""
from __future__ import annotations

import bn.cli
import pytest


_COMMANDS = [
    pytest.param(["taint", "forward", "-f", "process", "--source", "param:0"],
                 id="taint-forward"),
    pytest.param(["taint", "backward", "-f", "process", "--sink", "arg:memcpy:2"],
                 id="taint-backward"),
    pytest.param(["dataflow", "callgraph", "process"], id="callgraph"),
    pytest.param(["callsites", "memcpy"], id="callsites"),
    pytest.param(["xrefs", "memcpy"], id="xrefs-identifier"),
    pytest.param(["xrefs", "--any", "memcpy", "read"], id="xrefs-any"),
    pytest.param(["trace", "process", "0x401020"], id="trace"),
]

_BOUNDS = [("files", 256), ("depth", 64), ("functions", 100000)]


@pytest.mark.parametrize("argv", _COMMANDS)
@pytest.mark.parametrize(
    "option,value",
    [
        pytest.param(f"--project-max-{name}", value, id=f"{name}-{label}")
        for name, maximum in _BOUNDS
        for label, value in (
            ("malformed", "many"),
            ("fractional", "1.5"),
            ("zero", "0"),
            ("negative", "-1"),
            ("over-maximum", str(maximum + 1)),
        )
    ],
)
def test_project_analysis_invalid_bounds_refuse_before_transport(
    fake_transport, capsys, argv, option, value,
):
    calls = fake_transport()

    with pytest.raises(SystemExit) as exc:
        bn.cli.main([*argv, option, value, "--target", "active"])

    assert exc.value.code == 2
    assert calls == []
    assert option in capsys.readouterr().err


@pytest.mark.parametrize("name,maximum", _BOUNDS)
def test_no_project_does_not_bypass_bound_validation(
    fake_transport, capsys, name, maximum,
):
    calls = fake_transport()
    option = f"--project-max-{name}"

    with pytest.raises(SystemExit) as exc:
        bn.cli.main([
            "dataflow", "callgraph", "process", "--no-project",
            option, str(maximum + 1), "--target", "active",
        ])

    assert exc.value.code == 2
    assert calls == []
    assert option in capsys.readouterr().err


@pytest.mark.parametrize(
    "options",
    [
        pytest.param(["--no-project"], id="no-project"),
        *[
            pytest.param([f"--project-max-{name}", "1"], id=name)
            for name, _maximum in _BOUNDS
        ],
    ],
)
def test_field_xrefs_refuses_explicit_project_options(fake_transport, capsys, options):
    calls = fake_transport()

    rc = bn.cli.main([
        "xrefs", "--field", "Packet.length", *options, "--target", "active",
    ])

    assert rc == 2
    assert calls == []
    error = capsys.readouterr().err
    assert "--field" in error
    assert "project" in error


