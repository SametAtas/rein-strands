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
from dataclasses import dataclass
from pathlib import Path

from strands.hooks import BeforeToolCallEvent, HookProvider, HookRegistry

from rein.core.code import code_domain
from rein.core.findings import Finding, Severity
from rein.core.parsing import safe_parse
from rein.core.project import ProjectModel, build_project_model
from rein.core.resolution import check_unresolved_imports

from .extraction import segments

logger = logging.getLogger("rein_strands")


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


def _review_python(
    content: str, path: str | None, kind: str, model: ProjectModel | None
) -> tuple[list[Finding], bool, str]:
    """Findings for one Python segment, plus a fail-closed flag and reason for a
    ``.py`` that will not parse."""
    tree = safe_parse(content)  # parse once; reused for both passes
    found = list(code_domain(content, path, tree=tree))
    if model is not None and tree is not None:
        found.extend(check_unresolved_imports(tree, path, model, text=content))
    forced_high, reason = False, ""
    if any(f.rule_id == "lint.syntax-error" for f in found):
        if path is not None and path.endswith(".py"):
            forced_high = True
            reason = f"rein could not parse {path}; refusing unanalyzable code"
        found = [f for f in found if f.rule_id != "lint.syntax-error"]
    if kind == "repl":
        # Stateful session: a name may be bound by a prior call. Imports are
        # still real (a missing package is missing either way).
        found = [f for f in found if f.rule_id != "names.undefined"]
    return found, forced_high, reason


def evaluate(
    tool_name: str,
    tool_input: object,
    *,
    block_at: Severity = Severity.HIGH,
    model: ProjectModel | None = None,
) -> Decision:
    """Review a tool call's code/command with rein and decide whether to block.

    Pure and deterministic: no I/O, no Strands or LLM dependency. Blocks when the
    worst finding is at or above ``block_at``. Fails closed on a ``.py`` that will
    not parse. When ``model`` (a rein ``ProjectModel``) is supplied, Python code
    is also checked for unresolved imports, catching a hallucinated or undeclared
    module before the agent writes or runs it.
    """
    findings: list[Finding] = []
    forced_high = False
    forced_reason = ""
    for content, path, kind in segments(tool_name, tool_input):
        if kind == "text":
            # Not Python: keep only secret detection (regex, content-agnostic);
            # the AST checks would misread shell/markup as Python.
            findings.extend(
                f for f in code_domain(content, path) if f.rule_id.startswith("secret")
            )
            continue
        found, seg_high, seg_reason = _review_python(content, path, kind, model)
        findings.extend(found)
        if seg_high:
            forced_high, forced_reason = True, seg_reason

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
        project_root: path to the agent's project. When given (and the project
            declares dependencies via pyproject or requirements), Python code is
            also checked for unresolved imports, catching hallucinated or
            undeclared modules. Inert when omitted or when no dependencies are
            declared.
        on_finding: optional callback ``(Decision) -> None`` invoked whenever a
            call produces findings. Defaults to logging at WARNING.
    """

    def __init__(
        self,
        *,
        block_at: Severity = Severity.HIGH,
        mode: str = "enforce",
        project_root: str | Path | None = None,
        on_finding=None,
    ) -> None:
        if mode not in ("enforce", "audit"):
            raise ValueError("mode must be 'enforce' or 'audit'")
        self.block_at = block_at
        self.mode = mode
        self.on_finding = on_finding
        # Built once: scanning the project on every tool call would be wasteful.
        self.project_model = (
            build_project_model(project_root) if project_root is not None else None
        )

    def register_hooks(self, registry: HookRegistry, **kwargs) -> None:
        registry.add_callback(BeforeToolCallEvent, self._before_tool)

    def _before_tool(self, event: BeforeToolCallEvent) -> None:
        tool_use = event.tool_use or {}
        decision = evaluate(
            tool_use.get("name", "?"),
            tool_use.get("input"),
            block_at=self.block_at,
            model=self.project_model,
        )
        if decision.findings:
            if self.on_finding is not None:
                self.on_finding(decision)
            else:
                logger.warning("rein: %s", decision.reason or _summarize(decision.findings))
        if decision.block and self.mode == "enforce":
            event.cancel_tool = decision.reason
