"""The same agent as demo/vulnerable, with every issue fixed."""

from langchain.agents import initialize_agent

# Fixed: read-only, sandboxed tools. No shell, no REPL, no filesystem writes.
tools = [SearchTool(), ReadOnlyDocumentTool()]

agent = initialize_agent(tools=tools, llm=None)

memory_store = None


def recall(agent_id: str, embedding, top_k: int = 10):
    """Fixed: the query is scoped to the calling agent."""
    return memory_store.search(embedding, top_k=top_k, filter={"agent_id": agent_id})


def update_goal(agent_id: str, new_goal: str, signature: bytes):
    """Fixed: goal changes are signed and the signer is verified first."""
    verify_signature(agent_id, new_goal, signature)
    goals[agent_id] = new_goal
    return goals[agent_id]
