# rein-strands

A deterministic, no-LLM tool-call guardrail for [Strands](https://strandsagents.com)
agents, backed by the [rein](https://github.com/SametAtas/rein) engine.

Strands' `shell`, `file_write`, `editor`, and `python_repl` tools let an agent
write and run code. `rein-strands` reviews that code or command **before the tool
runs**, using Strands' `BeforeToolCallEvent` hook, and blocks the call when rein's
verdict is at or above a severity threshold.

There is no LLM, so the verdict is the same every run and you can see exactly why
a call was stopped. The same check behaves identically whether a person, CI, or
the agent triggers it, which keeps accountability clear.

## Install

```bash
pip install rein-strands
```

## Use

Register the hook on your agent:

```python
from strands import Agent
from strands_tools import shell, file_write, python_repl

from rein_strands import ReinToolGuard

agent = Agent(
    model=model,
    tools=[shell, file_write, python_repl],
    hooks=[ReinToolGuard()],   # blocks HIGH+ verdicts before the tool runs
)
```

That is all. When the agent tries to run code or a command that rein flags at or
above the threshold, the call is cancelled with the reason attached.

## What it reviews

| Tool | Field reviewed | Analysis |
|------|----------------|----------|
| `python_repl` | `code` | Full rein code analysis (stateful session, so undefined-name is not enforced) |
| `file_write` | `content` (`.py`) | Full rein code analysis, fails closed if the file will not parse |
| `editor` | `file_text` / `new_str` (`.py`) | Full rein code analysis on the added text |
| `shell` | `command` | Secrets, plus full analysis of any inline `python -c "..."` code |
| any | non-`.py` content | Secrets only (the Python AST checks do not apply) |

rein catches hard-coded secrets, unsafe calls (`os.system`, `eval`, `pickle`,
weak hashes, and so on), and hallucinated or undefined names in the code an agent
writes. Each finding comes with the reason and a remedy, not just an alert.

## Catching hallucinated imports

Pass `project_root` and rein also checks every Python import the agent writes
against the project's stdlib, declared dependencies, and own modules, so a
hallucinated or undeclared module is caught before the file is written or run:

```python
ReinToolGuard(project_root=".", block_at=Severity.MEDIUM)
```

```python
# the agent writes this; rein flags `import nonexistent_pkg` as imports.unresolved
import os
import nonexistent_pkg   # not stdlib, not a declared dependency, not in the project
```

This needs the project to declare dependencies (a `pyproject.toml` `[project]`
table or a `requirements*.txt`); without one rein cannot know what is installed,
so the import check stays inert rather than guessing. `imports.unresolved` is
`MEDIUM`, so set `block_at=Severity.MEDIUM` to block on it (or leave it advisory
at the default).

## Modes and threshold

```python
from rein_strands import ReinToolGuard, Severity

# Report only, never block (for human-in-the-loop, where a person owns the call):
ReinToolGuard(mode="audit", on_finding=lambda d: print(d.reason))

# Stricter: also block MEDIUM findings (e.g. weak hashes):
ReinToolGuard(block_at=Severity.MEDIUM)
```

- `mode="enforce"` (default) cancels a call whose verdict is at or above `block_at`.
- `mode="audit"` never cancels and only reports findings.
- `block_at` defaults to `Severity.HIGH`.

## Example

```text
[BLOCK] python_repl  HIGH     -> rein blocked tool 'python_repl': security.os-system (high): os.system/os.popen invokes a shell; use subprocess with a list and shell=False.
[BLOCK] file_write   HIGH     -> rein blocked tool 'file_write': security.pickle-load (high): pickle executes arbitrary code on untrusted data; use json or a safe format.
[BLOCK] shell        HIGH     -> rein blocked tool 'shell': security.os-system (high): ... (extracted from python -c)
[BLOCK] shell        CRITICAL -> rein blocked tool 'shell': secret.aws-access-key (critical): Possible AWS access key ID committed in source.
[allow] shell        INFO        (ls -la && git status)
[allow] python_repl  INFO        (uses a name bound in a prior call)
```

See [`examples/quickstart.py`](examples/quickstart.py) for the runnable version
(no model or cloud credentials required).

## How it fits with Strands' own safety

Strands shell relies on up-front **isolation** (declare what the agent can reach;
everything else does not exist), and Strands offers model-level **guardrails**.
`rein-strands` is the complementary **deterministic, code-level** layer: isolation
controls what an action can touch, rein judges what the code itself does, before
it runs. It is intentionally narrow and precise rather than a broad shell-pattern
scanner, so it does not cry wolf on ordinary commands.

## Design

The decision logic (`evaluate`) is a pure function with no Strands or LLM
dependency; `ReinToolGuard` is the thin hook that wires it into an agent. The core
has no dependencies beyond rein. Verified against `strands-agents` 1.44.

## License

Apache-2.0.
