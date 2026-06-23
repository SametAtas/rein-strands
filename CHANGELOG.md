# Changelog

## 0.3.0

- End-to-end coverage: a real Strands `Agent`, driven by a scripted model, proves
  `ReinToolGuard` cancels a dangerous tool call before the tool body runs, with no
  LLM or cloud credentials. See `examples/agent_demo.py` and `tests/test_integration.py`.
- Code-bearing tool fields (`content`/`code`/`file_text`/`new_str`) with no path
  are now analyzed as Python, so a custom tool that writes code without a path hint
  is still gated. Previously such input was treated as opaque text and missed.
- Added a PyPI publish workflow (OIDC trusted publishing).

## 0.2.0

- Project-aware hallucinated-import detection via `ReinToolGuard(project_root=...)`:
  flags an import that does not resolve to the stdlib, a declared dependency, or a
  project module. Requires `rein-engine>=0.2.0`.

## 0.1.0

- Initial release. `ReinToolGuard`, a deterministic `BeforeToolCallEvent` hook that
  gates Strands tool calls with rein: shell, file_write, editor, python_repl,
  inline `python -c`, secrets, fail-closed on unparseable `.py`, enforce/audit
  modes, configurable severity threshold.
