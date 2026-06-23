"""A deterministic, no-LLM tool-call guardrail for Strands agents, backed by rein.

Strands' `shell`, `file_write`, `editor`, and `python_repl` tools let an agent
write and run code. This hook reviews that code or command BEFORE the tool runs,
using the `BeforeToolCallEvent` seam, and blocks the call when rein's verdict is
at or above a severity threshold. There is no LLM and the verdict is the same
every run, so the human who owns the decision can see exactly why something was
stopped, and the same check behaves identically whether a person, CI, or the
agent triggers it.

The decision logic (`evaluate`) is a pure function with no Strands dependency;
`ReinToolGuard` is the thin hook that wires it into an agent.
"""

from __future__ import annotations

import logging
import shlex
from dataclasses import dataclass

from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from rein.core.code import code_domain
from rein.core.findings import Finding, Severity

logger = logging.getLogger("rein_strands")

# Tool-input fields that carry code or a command the agent will write or run.
# Verified against strands-agents 1.44 tool schemas: shell(command),
# file_write(content), editor(file_text/new_str), python_repl(code). `old_str`
# is deliberately excluded: it is the text being removed, not added.
_CONTENT_KEYS = ("content", "code", "command", "file_text", "new_str")
# Fields that name a path, so rein gates the right (e.g. Python) checks.
_PATH_KEYS = ("path", "file_path")
# Shell argv[0] values that run inline Python passed via `-c`.
_PYTHON_EXES = ("python", "python3", "py")
# Tools whose payload is Python source, but executed in a persistent session, so
# `names.undefined` is unsound (a name may be bound by an earlier call).
_REPL_TOOLS = ("python_repl",)


def _as_text(value: object) -> str:
    """Flatten a tool-input value (str, list, or dict) into reviewable text."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(_as_text(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(_as_text(v) for v in value.values())
    return str(value)


def _inline_python(command_text: str) -> list[str]:
    """Extract code from `python -c "<code>"` invocations inside a shell command.

    Conservative: only the unambiguous `python -c <code>` form. If the command
    cannot be tokenized (unbalanced quotes), nothing is extracted rather than
    guessing.
    """
    try:
        tokens = shlex.split(command_text)
    except ValueError:
        return []
    out: list[str] = []
    for i, tok in enumerate(tokens):
        base = tok.rsplit("/", 1)[-1]
        if base in _PYTHON_EXES:
            for j in range(i + 1, len(tokens)):
                if tokens[j] == "-c" and j + 1 < len(tokens):
                    out.append(tokens[j + 1])
                    break
    return out


def extract_reviewable(tool_input: object) -> tuple[str, str | None]:
    """Pull the primary reviewable content and a path hint out of a tool input."""
    if not isinstance(tool_input, dict):
        return _as_text(tool_input), None
    path = next((str(tool_input[k]) for k in _PATH_KEYS if tool_input.get(k)), None)
    parts = [_as_text(tool_input[k]) for k in _CONTENT_KEYS if tool_input.get(k)]
    return ("\n".join(parts) if parts else ""), path


def _segments(tool_name: str, tool_input: object) -> list[tuple[str, str | None, str]]:
    """All (content, path, kind) pieces to review for one tool call.

    `kind` selects how rein's findings are used, so the Python analyzer only runs
    on actual Python and never misreads a shell command:
      - "module": complete Python source (a `.py` write, or inline `python -c`)
        - full analysis, including undefined-name detection.
      - "repl":   python_repl source - full analysis EXCEPT undefined names, since
        the session is stateful and a name may be bound by a prior call.
      - "text":   a shell command or non-Python file - secrets only; the Python
        AST checks do not apply and would misfire on shell syntax.
    """
    segments: list[tuple[str, str | None, str]] = []
    content, path = extract_reviewable(tool_input)
    if content.strip():
        if tool_name in _REPL_TOOLS:
            kind = "repl"
        elif path is not None and path.endswith(".py"):
            kind = "module"
        else:
            kind = "text"
        segments.append((content, path, kind))
    if isinstance(tool_input, dict) and tool_input.get("command"):
        for code in _inline_python(_as_text(tool_input["command"])):
            if code.strip():
                segments.append((code, None, "module"))
    return segments


def _dedup(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.message, f.line)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def _summarize(findings: list[Finding], limit: int = 3) -> str:
    top = sorted(findings, key=lambda f: f.severity, reverse=True)[:limit]
    bits = [f"{f.rule_id} ({f.severity.name.lower()}): {f.message}" for f in top]
    extra = len(findings) - len(top)
    if extra > 0:
        bits.append(f"and {extra} more")
    return "; ".join(bits)


@dataclass(frozen=True)
class Decision:
    """The outcome of reviewing one tool call."""

    block: bool
    severity: Severity
    findings: list[Finding]
    reason: str


def evaluate(
    tool_name: str, tool_input: object, *, block_at: Severity = Severity.HIGH
) -> Decision:
    """Review a tool call's code/command with rein and decide whether to block.

    Pure and deterministic: no I/O, no Strands or LLM dependency. Blocks when the
    worst finding is at or above ``block_at``. Fails closed on a ``.py`` that will
    not parse (rein could not analyze real code, and unanalyzed is not safe); a
    parse failure on non-Python content (e.g. a shell command) carries no security
    signal and is dropped.
    """
    findings: list[Finding] = []
    forced_high = False
    forced_reason = ""
    for content, path, kind in _segments(tool_name, tool_input):
        found = code_domain(content, path)
        if kind == "text":
            # Not Python: keep only secret detection (regex, content-agnostic);
            # drop the AST-based findings that misread shell/markup as Python.
            findings.extend(f for f in found if f.rule_id.startswith("secret"))
            continue
        if any(f.rule_id == "lint.syntax-error" for f in found):
            if path is not None and path.endswith(".py"):
                forced_high = True
                forced_reason = f"rein could not parse {path}; refusing unanalyzable code"
            found = [f for f in found if f.rule_id != "lint.syntax-error"]
        if kind == "repl":
            found = [f for f in found if f.rule_id != "names.undefined"]
        findings.extend(found)

    findings = _dedup(findings)
    worst = max((f.severity for f in findings), default=Severity.INFO)
    if forced_high:
        worst = max(worst, Severity.HIGH)

    block = forced_high or (bool(findings) and worst >= block_at)
    if not block:
        reason = _summarize(findings) if findings else ""
    elif findings:
        reason = f"rein blocked tool '{tool_name}': {_summarize(findings)}"
    else:
        reason = f"rein blocked tool '{tool_name}': {forced_reason}"
    return Decision(block, worst, findings, reason)


class ReinToolGuard(HookProvider):
    """Strands hook that gates tool calls with rein before they execute.

    Register it on an agent::

        from strands import Agent
        from rein_strands import ReinToolGuard

        agent = Agent(model=model, tools=tools, hooks=[ReinToolGuard()])

    Args:
        block_at: minimum severity that blocks a call (default ``Severity.HIGH``).
        mode: ``"enforce"`` (default) cancels a call whose verdict is at or above
            ``block_at``; ``"audit"`` never cancels and only reports findings, for
            human-in-the-loop setups where a person owns the final decision.
        on_finding: optional callback ``(Decision) -> None`` invoked whenever a
            call produces findings. Defaults to logging at WARNING.
    """

    def __init__(
        self,
        *,
        block_at: Severity = Severity.HIGH,
        mode: str = "enforce",
        on_finding=None,
    ) -> None:
        if mode not in ("enforce", "audit"):
            raise ValueError("mode must be 'enforce' or 'audit'")
        self.block_at = block_at
        self.mode = mode
        self.on_finding = on_finding

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self._before_tool)

    def _before_tool(self, event: BeforeToolCallEvent) -> None:
        tool_use = event.tool_use or {}
        decision = evaluate(
            tool_use.get("name", "?"), tool_use.get("input"), block_at=self.block_at
        )
        if decision.findings:
            if self.on_finding is not None:
                self.on_finding(decision)
            else:
                logger.warning("rein: %s", decision.reason or _summarize(decision.findings))
        if decision.block and self.mode == "enforce":
            event.cancel_tool = decision.reason
