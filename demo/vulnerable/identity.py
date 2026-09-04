"""DELIBERATELY VULNERABLE. Identity and trust-chain failures.

These are the MCP-native classes: an agent presenting a forged identity that the
system accepts, and a trust score that is calculated but never enforced.
"""

import jwt

# The signing secret is short, symmetric and committed.
JWT_SECRET = "devsecret"
JWT_ALGORITHM = "HS256"


def decode_token(token: str):
    """Signature verification is switched off, so any forged claim is accepted."""
    return jwt.decode(token, JWT_SECRET, options={"verify_signature": False})


def issue_card(agent_name: str, capabilities: list):
    """An agent card is marked verified without any issuer check."""
    return {
        "agent": agent_name,
        "capabilities": capabilities,
        "is_verified": True,
    }


def extend_delegation_chain(chain: list, agent_id: str):
    """The trust score decays per hop but is never compared against a floor.

    The action below executes whatever the score has fallen to, including zero.
    """
    trust = chain[-1]["trust"] - 20 if chain else 100
    chain.append({"agent": agent_id, "trust": trust})
    return chain


def act_on_behalf(chain: list, action):
    # No authorisation gate on chain[-1]["trust"].
    return action()
