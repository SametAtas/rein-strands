# rein-strands

[![CI](https://github.com/SametAtas/rein-strands/actions/workflows/ci.yml/badge.svg)](https://github.com/SametAtas/rein-strands/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/rein-strands.svg)](https://pypi.org/project/rein-strands/)
[![Python](https://img.shields.io/pypi/pyversions/rein-strands.svg)](https://pypi.org/project/rein-strands/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A deterministic, no-LLM guardrail for [Strands](https://strandsagents.com) agents.
It reviews the code or command a tool is about to run and **cancels the call before
the tool executes** when the verdict crosses a severity threshold. Backed by the
[rein](https://github.com/SametAtas/rein) engine.

No LLM judges the action, so the verdict is the same every run and you can see
exactly why a call was stopped. The same check behaves identically whether a
person, CI, or the agent triggers it, which keeps accountability clear.

## See it block a real agent

`examples/agent_demo.py` runs an actual Strands `Agent` (a scripted model stands
in for the LLM, so no API key is needed) and lets rein gate its tool calls:

```text
[1] dangerous code
    agent tried: save_code('import os\nos.system(user_input)\n')
    -> BLOCKED before execution; tool body never ran
       rein blocked tool 'save_code': security.os-system (high): os.system/os.popen
       invokes a shell; use subprocess with a list and shell=False.

[2] clean code
    agent tried: save_code('def add(a, b):\n    return a + b\n')
    -> allowed; tool ran
```

The dangerous tool call is cancelled at the boundary; the tool function never
runs. The clean one goes through untouched.

## Install

```bash
pip install rein-strands
```

## Use

Attach the hook to your agent. That is the whole integration:

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

## What it reviews

| Tool | Field reviewed | Analysis |
|------|----------------|----------|
| `python_repl` | `code` | Full rein code analysis (stateful session, so undefined-name is not enforced) |
| `file_write` | `content` (`.py`) | Full rein code analysis, fails closed if the file will not parse |
| `editor` | `file_text` / `new_str` (`.py`) | Full rein code analysis on the added text |
| `shell` | `command` | Secrets, plus full analysis of any inline `python -c "..."` code |
| custom | `content` / `code` (no path) | Treated as Python so dangerous code is still caught |
| any | non-`.py` file content | Secrets only (the Python AST checks do not apply) |

rein catches hard-coded secrets, unsafe calls (`os.system`, `eval`, `pickle`,
weak hashes, and so on), undefined names, and (with `project_root`) hallucinated
imports. Each finding carries the reason and a remedy, not just an alert.

## Modes and threshold

```python
from rein_strands import ReinToolGuard, Severity

# Report only, never block (human-in-the-loop, where a person owns the call):
ReinToolGuard(mode="audit", on_finding=lambda d: print(d.reason))

# Stricter: also block MEDIUM findings (e.g. weak hashes, hallucinated imports):
ReinToolGuard(block_at=Severity.MEDIUM)
```

- `mode="enforce"` (default) cancels a call whose verdict is at or above `block_at`.
- `mode="audit"` never cancels and only reports findings.
- `block_at` defaults to `Severity.HIGH`.

## Catching hallucinated imports

Pass `project_root` and rein also checks every Python import the agent writes
against the project's stdlib, declared dependencies, and own modules, so a
hallucinated or undeclared module is caught before the file is written or run:

```python
ReinToolGuard(project_root=".", block_at=Severity.MEDIUM)
```

This needs the project to declare dependencies (a `pyproject.toml` `[project]`
table or a `requirements*.txt`); without one rein cannot know what is installed,
so the import check stays inert rather than guessing.

## How it fits with Strands' own safety

Strands shell relies on up-front **isolation** (declare what the agent can reach;
everything else does not exist), and Strands offers model-level **guardrails**.
`rein-strands` is the complementary **deterministic, code-level** layer: isolation
controls what an action can touch, rein judges what the code itself does, before
it runs. It is intentionally narrow and precise rather than a broad shell-pattern
scanner, so it does not cry wolf on ordinary commands.

## Design

The decision logic (`evaluate`) is a pure function with no Strands or LLM
dependency; `ReinToolGuard` is the thin hook that wires it into an agent, and
`extraction.py` holds the Strands-specific tool-shape mapping. The core has no
dependencies beyond rein. Verified against `strands-agents` 1.44, with an
end-to-end test that drives a real agent.

## License

Apache-2.0.
