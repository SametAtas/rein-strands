"""See rein cancel a dangerous tool call inside a real Strands agent.

This runs an actual Strands `Agent` with `ReinToolGuard` attached. A scripted
model stands in for the LLM (so no API key or cloud access is needed) and asks
the agent to call a `save_code` tool. rein reviews the code in the tool call via
the `BeforeToolCallEvent` hook and cancels it before the tool body runs.

    pip install rein-strands strands-agents
    python examples/agent_demo.py
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterable

from strands import Agent, tool
from strands.models.model import Model

from rein_strands import ReinToolGuard

EXECUTED: list[str] = []


@tool
def save_code(content: str) -> str:
    """Save Python code to the project (records that it actually ran)."""
    EXECUTED.append(content)
    return "saved"


class ScriptedModel(Model):
    """Stands in for the LLM: first turn emits one tool call, then ends."""

    def __init__(self, tool_input: dict) -> None:
        self._tool_input = tool_input
        self._calls = 0

    def get_config(self) -> dict:
        return {}

    def update_config(self, **kwargs) -> None:
        pass

    async def structured_output(self, *args, **kwargs):
        raise NotImplementedError
        yield

    async def stream(self, messages, tool_specs=None, system_prompt=None, **kwargs) -> AsyncIterable[dict]:
        self._calls += 1
        usage = {"usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                 "metrics": {"latencyMs": 1}}
        if self._calls == 1:
            yield {"messageStart": {"role": "assistant"}}
            yield {"contentBlockStart": {"contentBlockIndex": 0,
                   "start": {"toolUse": {"toolUseId": "t1", "name": "save_code"}}}}
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


def run(label: str, code: str) -> None:
    EXECUTED.clear()
    seen: dict[str, str] = {}
    agent = Agent(
        model=ScriptedModel({"content": code}),
        tools=[save_code],
        # on_finding captures rein's reason; callback_handler=None silences the
        # agent's own streaming console output so the demo reads cleanly.
        hooks=[ReinToolGuard(on_finding=lambda d: seen.update(reason=d.reason))],
        callback_handler=None,
    )
    agent("save the code")
    print(f"{label}")
    print(f"    agent tried: save_code({code!r})")
    if EXECUTED:
        print("    -> allowed; tool ran\n")
    else:
        print("    -> BLOCKED before execution; tool body never ran")
        print(f"       {seen.get('reason', '')}\n")


def main() -> int:
    print("A real Strands agent + ReinToolGuard (deterministic, no LLM):\n")
    run("[1] dangerous code", "import os\nos.system(user_input)\n")
    run("[2] clean code", "def add(a, b):\n    return a + b\n")
    print("Same verdict every run, with no model in the review loop.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
