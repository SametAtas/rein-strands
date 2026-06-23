"""Map a Strands tool call's input onto reviewable (content, path, kind) pieces.

This is the Strands-specific knowledge: which fields of which tools carry code
or commands, and how each piece should be analyzed. Kept separate from the
decision logic so the rein side stays framework-agnostic.
"""

from __future__ import annotations

import shlex

# Tool-input fields that carry code or a command the agent will write or run.
# Verified against strands-agents 1.44 tool schemas: shell(command),
# file_write(content), editor(file_text/new_str), python_repl(code). `old_str`
# is deliberately excluded: it is the text being removed, not added.
_CONTENT_KEYS = ("content", "code", "command", "file_text", "new_str")
# Fields that name a path, so rein gates the right (e.g. Python) checks.
_PATH_KEYS = ("path", "file_path")
# Shell argv[0] values that run inline Python passed via `-c`.
_PYTHON_EXES = ("python", "python3", "py")
# Tools whose payload is Python source executed in a persistent session, so
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
        if tok.rsplit("/", 1)[-1] in _PYTHON_EXES:
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


def segments(tool_name: str, tool_input: object) -> list[tuple[str, str | None, str]]:
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
    out: list[tuple[str, str | None, str]] = []
    content, path = extract_reviewable(tool_input)
    if content.strip():
        if tool_name in _REPL_TOOLS:
            kind = "repl"
        elif path is not None and path.endswith(".py"):
            kind = "module"
        else:
            kind = "text"
        out.append((content, path, kind))
    if isinstance(tool_input, dict) and tool_input.get("command"):
        for code in _inline_python(_as_text(tool_input["command"])):
            if code.strip():
                out.append((code, None, "module"))
    return out
