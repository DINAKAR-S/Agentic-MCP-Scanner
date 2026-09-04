"""DELIBERATELY VULNERABLE. Agentic AI layer.

An agent handed unrestricted tools, and a memory store queried without scoping.
"""

from langchain.agents import initialize_agent
from langchain_experimental.tools import PythonREPLTool

# Agentic AI: the model can execute shell and Python directly, so a successful
# prompt attack becomes a real action rather than a bad answer.
tools = [PythonREPLTool(), ShellTool(), FileWriteTool()]

agent = initialize_agent(tools=tools, llm=None)

memory_store = None


def recall(embedding, top_k: int = 10):
    """Agentic AI: no agent_id or tenant filter, so this reads every namespace."""
    return memory_store.search(embedding, top_k=top_k)


def update_goal(agent_id: str, new_goal: str):
    """Agentic AI: the goal is overwritten with no integrity check."""
    goals[agent_id] = new_goal
    return goals[agent_id]
