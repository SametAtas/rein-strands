"""End-to-end: a real Strands Agent with ReinToolGuard cancels a dangerous tool
call before the tool function runs. Driven by a scripted model, so no LLM or
cloud credentials are needed - the agent's real event loop and the real
BeforeToolCallEvent dispatch do the work.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable

from strands import Agent, tool
from strands.models.model import Model

from rein_strands import ReinToolGuard, Severity

# Records whether the tool's BODY actually executed, so a test can prove rein
# stopped execution rather than merely flagged it.
EXECUTED: list[str] = []


@tool
def save_code(content: str) -> str:
    """Save Python code to the project."""
    EXECUTED.append(content)
    return "saved"


class _ScriptedModel(Model):
    """A model with no LLM: the first turn emits one tool call, then it ends."""

    def __init__(self, tool_name: str, tool_input: dict) -> None:
        self._tool_name = tool_name
        self._tool_input = tool_input
        self._calls = 0

    def get_config(self) -> dict:
        return {}

    def update_config(self, **kwargs) -> None:
        pass

    async def structured_output(self, *args, **kwargs):
        raise NotImplementedError
        yield  # pragma: no cover - never reached, makes this an async generator

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterable[dict]:
        self._calls += 1
        usage = {"usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                 "metrics": {"latencyMs": 1}}
        if self._calls == 1:
            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockStart": {"contentBlockIndex": 0,
                   "start": {"toolUse": {"toolUseId": "t1", "name": self._tool_name}}}}
            yield {"contentBlockDelta": {"contentBlockIndex": 0,
                   "delta": {"toolUse": {"input": json.dumps(self._tool_input)}}}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "tool_use"}}
            yield {"metadata": usage}
        else:
            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockDelta": {"contentBlockIndex": 0, "delta": {"text": "done"}}}
            yield {"contentBlockStop": {"contentBlockIndex": 0}}
            yield {"messageStop": {"stopReason": "end_turn"}}
            yield {"metadata": usage}


def _run(tool_input: dict, **guard_kwargs) -> None:
    EXECUTED.clear()
    agent = Agent(
        model=_ScriptedModel("save_code", tool_input),
        tools=[save_code],
        hooks=[ReinToolGuard(**guard_kwargs)],
    )
    agent("save the code")


def test_dangerous_tool_call_is_cancelled_before_execution():
    _run({"content": "import os\nos.system(cmd)\n"})
    assert EXECUTED == []  # rein cancelled the call; the tool body never ran


def test_clean_tool_call_executes():
    _run({"content": "def add(a, b):\n    return a + b\n"})
    assert EXECUTED == ["def add(a, b):\n    return a + b\n"]


def test_audit_mode_lets_the_call_through():
    # In audit mode rein reports but never cancels, so even a dangerous call runs.
    _run({"content": "import os\nos.system(cmd)\n"}, mode="audit")
    assert EXECUTED == ["import os\nos.system(cmd)\n"]
