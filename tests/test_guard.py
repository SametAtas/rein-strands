"""Tests for ReinToolGuard against the real Strands SDK and rein engine."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from strands.hooks import BeforeToolCallEvent, HookRegistry

from rein.core.project import build_project_model
from rein_strands import Decision, ReinToolGuard, Severity, evaluate, extract_reviewable
from rein_strands.extraction import _inline_python

DANGER = "import os\nos.system(cmd)\n"


def _event(name: str, tool_input: dict) -> BeforeToolCallEvent:
    return BeforeToolCallEvent(
        agent=SimpleNamespace(name="test-agent"),
        selected_tool=None,
        tool_use={"name": name, "input": tool_input, "toolUseId": "tu_1"},
        invocation_state={},
    )


# --- evaluate: dangerous calls block ---

def test_python_repl_os_system_blocks():
    d = evaluate("python_repl", {"code": DANGER})
    assert d.block and d.severity == Severity.HIGH


def test_file_write_py_os_system_blocks():
    d = evaluate("file_write", {"path": "app.py", "content": DANGER})
    assert d.block and d.severity == Severity.HIGH


def test_editor_new_str_os_system_blocks():
    d = evaluate("editor", {"command": "str_replace", "path": "a.py", "new_str": DANGER})
    assert d.block and d.severity == Severity.HIGH


def test_shell_inline_python_is_extracted_and_blocks():
    # `python -c "..."` carries real code; rein must reach it, not see an opaque command.
    d = evaluate("shell", {"command": "python3 -c \"import os; os.system('rm -rf /')\""})
    assert d.block
    assert any(f.rule_id == "security.os-system" for f in d.findings)


def test_shell_hardcoded_secret_blocks():
    d = evaluate("shell", {"command": "export KEY=AKIAIOSFODNN7EXAMPLE"})
    assert d.block
    assert any(f.rule_id.startswith("secret") for f in d.findings)


def test_unparseable_py_fails_closed():
    # A .py rein cannot parse is unanalyzed code; fail closed to HIGH.
    d = evaluate("file_write", {"path": "app.py", "content": "import os\nos.system(cmd\n"})
    assert d.block and d.severity == Severity.HIGH


# --- evaluate: clean calls do NOT block and produce no spurious findings ---

def test_shell_ls_is_clean():
    # Regression: a shell command must not be parsed as Python (no names.undefined).
    d = evaluate("shell", {"command": "ls -la"})
    assert not d.block and d.findings == []


def test_shell_compound_command_is_clean():
    d = evaluate("shell", {"command": "git status && make build"})
    assert not d.block and d.findings == []


def test_python_repl_uses_prior_state_is_clean():
    # python_repl is stateful: a name bound by a prior call is not "undefined".
    d = evaluate("python_repl", {"code": "result = compute()\nprint(result)\n"})
    assert not d.block
    assert all(f.rule_id != "names.undefined" for f in d.findings)


def test_non_python_file_is_secrets_only():
    d = evaluate("file_write", {"path": "run.sh", "content": "ls -la\nrm tmp\n"})
    assert not d.block and d.findings == []


def test_clean_python_file_does_not_block():
    d = evaluate("file_write", {"path": "a.py", "content": "def add(a, b):\n    return a + b\n"})
    assert not d.block


def test_code_field_without_path_is_analyzed():
    # A custom tool with a code-named field but no path is still analyzed as
    # Python (not treated as opaque text), so dangerous code is caught.
    d = evaluate("save_code", {"content": "import os\nos.system(x)\n"})
    assert d.block and any(f.rule_id == "security.os-system" for f in d.findings)


# --- threshold ---

def test_medium_does_not_block_at_default_high():
    d = evaluate("python_repl", {"code": "import hashlib\nhashlib.md5(b'x')\n"})
    assert d.severity == Severity.MEDIUM and not d.block


def test_medium_blocks_when_threshold_lowered():
    d = evaluate(
        "python_repl",
        {"code": "import hashlib\nhashlib.md5(b'x')\n"},
        block_at=Severity.MEDIUM,
    )
    assert d.block


# --- determinism ---

def test_deterministic():
    verdicts = {evaluate("python_repl", {"code": DANGER}).block for _ in range(20)}
    assert verdicts == {True}


# --- extraction helpers ---

def test_extract_reviewable_maps_known_fields():
    content, path = extract_reviewable({"path": "a.py", "content": "x = 1\n"})
    assert content == "x = 1\n" and path == "a.py"


def test_extract_flattens_list_command():
    content, _ = extract_reviewable({"command": ["echo hi", "ls"]})
    assert "echo hi" in content and "ls" in content


def test_inline_python_extracts_dash_c():
    assert _inline_python('python3 -c "print(1)"') == ["print(1)"]
    assert _inline_python("bash -c 'echo hi'") == []  # not python
    assert _inline_python("ls -la") == []


# --- hook wiring + behavior against the real event ---

def test_register_hooks_subscribes_to_before_tool_call():
    reg = HookRegistry()
    ReinToolGuard().register_hooks(reg)
    assert reg.has_callbacks()


def test_enforce_sets_cancel_tool_on_danger():
    guard = ReinToolGuard()
    ev = _event("python_repl", {"code": DANGER})
    guard._before_tool(ev)
    assert isinstance(ev.cancel_tool, str) and "rein blocked" in ev.cancel_tool


def test_enforce_leaves_clean_call_untouched():
    guard = ReinToolGuard()
    ev = _event("shell", {"command": "ls -la"})
    guard._before_tool(ev)
    assert ev.cancel_tool is False  # default, never set


def test_audit_mode_never_cancels():
    seen: list[Decision] = []
    guard = ReinToolGuard(mode="audit", on_finding=seen.append)
    ev = _event("python_repl", {"code": DANGER})
    guard._before_tool(ev)
    assert ev.cancel_tool is False          # audit reports, does not block
    assert seen and seen[0].block is True   # but the decision still flags it


def test_invalid_mode_rejected():
    with pytest.raises(ValueError):
        ReinToolGuard(mode="nope")


# --- project-aware unresolved (hallucinated) imports ---

@pytest.fixture(scope="module")
def project(tmp_path_factory):
    d = tmp_path_factory.mktemp("proj")
    (d / "pyproject.toml").write_text(
        '[project]\nname = "demo"\nversion = "0.0.0"\ndependencies = ["requests"]\n'
    )
    pkg = d / "mypkg"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "util.py").write_text("def f():\n    return 1\n")
    return build_project_model(str(d))


def test_hallucinated_import_is_flagged(project):
    d = evaluate(
        "file_write",
        {"path": "app.py", "content": "import totally_fake_xyz123\n"},
        block_at=Severity.MEDIUM,
        model=project,
    )
    assert d.block
    assert any(f.rule_id == "imports.unresolved" for f in d.findings)


def test_real_imports_not_flagged(project):
    d = evaluate(
        "file_write",
        {"path": "app.py", "content": "import os\nimport requests\nimport mypkg.util\n"},
        model=project,
    )
    assert all(f.rule_id != "imports.unresolved" for f in d.findings)


def test_import_check_inert_without_model():
    d = evaluate("file_write", {"path": "app.py", "content": "import totally_fake_xyz123\n"})
    assert all(f.rule_id != "imports.unresolved" for f in d.findings)


def test_inline_python_c_import_is_checked(project):
    d = evaluate(
        "shell",
        {"command": 'python3 -c "import totally_fake_xyz123"'},
        block_at=Severity.MEDIUM,
        model=project,
    )
    assert any(f.rule_id == "imports.unresolved" for f in d.findings)


def test_repl_keeps_import_check(project):
    # repl drops undefined-name (stateful), but a missing import is still missing.
    d = evaluate(
        "python_repl",
        {"code": "import totally_fake_xyz123\n"},
        block_at=Severity.MEDIUM,
        model=project,
    )
    assert any(f.rule_id == "imports.unresolved" for f in d.findings)


def test_guard_with_project_root_flags_hallucination(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "d"\nversion = "0"\ndependencies = ["requests"]\n'
    )
    guard = ReinToolGuard(block_at=Severity.MEDIUM, project_root=str(tmp_path))
    ev = _event("file_write", {"path": "app.py", "content": "import totally_fake_xyz123\n"})
    guard._before_tool(ev)
    assert isinstance(ev.cancel_tool, str) and "imports.unresolved" in ev.cancel_tool
