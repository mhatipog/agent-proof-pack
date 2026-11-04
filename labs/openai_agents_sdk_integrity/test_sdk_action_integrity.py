"""Offline regressions for OpenAI Agents SDK approval and audit records.

Requires the optional dependency openai-agents==0.24.0. The tests make no
network requests and use no real model, credential or external side effect.
Two regression assertions are expected to FAIL on affected SDK versions.
"""

import unittest

from agents import (
    Agent,
    Runner,
    ToolGuardrailFunctionOutput,
    function_tool,
    tool_input_guardrail,
    tool_output_guardrail,
)
from agents.exceptions import UserError
from agents.testing import ScriptedModel, assistant_message, function_call


class ActionIntegrityTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_approval_means_no_execution(self):
        writes = []

        @function_tool(needs_approval=True)
        def write_marker(path: str) -> str:
            writes.append(path)
            return "written"

        agent = Agent(
            name="operator",
            tools=[write_marker],
            model=ScriptedModel(
                [[function_call("write_marker", {"path": "A"}, call_id="call_fixed")]]
            ),
        )
        result = await Runner.run(agent, "write marker")
        self.assertEqual(len(result.interruptions), 1)
        self.assertEqual(writes, [])

    async def test_stale_approval_cannot_authorize_a_separate_run(self):
        """#5413: an old approval must not grant a fresh run's tool call."""
        writes = []

        @function_tool(needs_approval=True)
        def write_marker(path: str) -> str:
            writes.append(path)
            return "written"

        agent = Agent(
            name="operator",
            tools=[write_marker],
            model=ScriptedModel(
                [
                    [function_call("write_marker", {"path": "A"}, call_id="call_fixed")],
                    [assistant_message("done")],
                ]
            ),
        )
        first = await Runner.run(agent, "write once")
        self.assertEqual(len(first.interruptions), 1)
        stale_item = first.interruptions[0]
        first_state = first.to_state()
        first_state.approve(stale_item)
        await Runner.run(agent, first_state)
        self.assertEqual(writes, ["A"])

        # Reusing the SAME Agent instance is necessary for this specific
        # offline state-machine regression. The model is deterministic.
        agent.model = ScriptedModel(
            [
                [function_call("write_marker", {"path": "A"}, call_id="call_fixed")],
                [assistant_message("done")],
            ]
        )
        second = await Runner.run(agent, "start an independent run")
        self.assertEqual(len(second.interruptions), 1)
        second_state = second.to_state()
        try:
            second_state.approve(stale_item)
        except UserError:
            # Refusing a foreign approval is a valid future fix.
            pass
        else:
            await Runner.run(agent, second_state)

        self.assertEqual(
            writes,
            ["A"],
            "A foreign approval caused an additional action in the second run",
        )

    async def test_approved_tool_guardrail_results_survive_resume(self):
        """#5470: guardrail results must remain in the returned audit record."""
        executed = []
        input_checks = []
        output_checks = []

        @tool_input_guardrail
        def input_check(data):
            input_checks.append(data.context.tool_call_id)
            return ToolGuardrailFunctionOutput.allow(
                output_info=data.context.tool_call_id
            )

        @tool_output_guardrail
        def output_check(data):
            output_checks.append(data.context.tool_call_id)
            return ToolGuardrailFunctionOutput.allow(
                output_info=data.context.tool_call_id
            )

        @function_tool(
            needs_approval=True,
            tool_input_guardrails=[input_check],
            tool_output_guardrails=[output_check],
        )
        def write_marker(path: str) -> str:
            executed.append(path)
            return "written"

        agent = Agent(
            name="operator",
            tools=[write_marker],
            model=ScriptedModel(
                [
                    [function_call("write_marker", {"path": "A"}, call_id="call_1")],
                    [assistant_message("done")],
                ]
            ),
        )
        first = await Runner.run(agent, "write once")
        self.assertEqual(len(first.interruptions), 1)
        state = first.to_state()
        state.approve(first.interruptions[0])
        result = await Runner.run(agent, state)

        self.assertEqual(executed, ["A"])
        self.assertIn("call_1", input_checks)
        self.assertIn("call_1", output_checks)
        self.assertIn(
            "call_1",
            [r.output.output_info for r in result.tool_input_guardrail_results],
            "Input guardrail ran but its evidence was lost",
        )
        self.assertIn(
            "call_1",
            [r.output.output_info for r in result.tool_output_guardrail_results],
            "Output guardrail ran but its evidence was lost",
        )


if __name__ == "__main__":
    unittest.main()
