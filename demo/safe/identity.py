"""The same identity layer as demo/vulnerable, with every issue fixed."""

import os

import jwt

# Fixed: asymmetric signing, key held outside the source tree.
JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
JWT_ALGORITHM = "RS256"

MINIMUM_TRUST = 40


def decode_token(token: str):
    """Fixed: the signature is verified on every decode."""
    return jwt.decode(token, JWT_PUBLIC_KEY, algorithms=[JWT_ALGORITHM])


def issue_card(agent_name: str, capabilities: list, issuer_signature: bytes):
    """Fixed: verified only after the issuer's signature checks out."""
    verified = verify_issuer_signature(agent_name, issuer_signature)
    return {
        "agent": agent_name,
        "capabilities": capabilities,
        "is_verified": verified,
    }


def extend_delegation_chain(chain: list, agent_id: str):
    trust = chain[-1]["trust"] - 20 if chain else 100
    chain.append({"agent": agent_id, "trust": trust})
    return chain


def act_on_behalf(chain: list, action):
    """Fixed: the trust score is enforced as an authorisation floor."""
    if not chain or chain[-1]["trust"] < MINIMUM_TRUST:
        raise PermissionError("delegation trust below the minimum threshold")
    return action()
