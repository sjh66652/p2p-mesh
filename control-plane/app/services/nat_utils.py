"""
NAT Traversal Utilities — STUN probing, NAT classification, path analysis.

Provides helper functions for the control plane to:
- Classify NAT types from client-reported probe results
- Determine P2P feasibility between NAT types
- Generate STUN server configurations
- Calculate candidate priorities

This module complements the Rust data plane's STUN implementation.
"""

import logging
from typing import List, Tuple, Dict

logger = logging.getLogger(__name__)


# NAT compatibility matrix: whether two NAT types can establish direct P2P.
# Based on RFC 4787 and RFC 5389 NAT behavior discovery.
# True = direct P2P possible, False = relay required.
NAT_COMPATIBILITY: Dict[Tuple[str, str], bool] = {
    ("open", "open"): True,
    ("open", "full_cone"): True,
    ("open", "restricted_cone"): True,
    ("open", "port_restricted"): True,
    ("open", "symmetric"): True,
    ("open", "unknown"): True,
    ("full_cone", "open"): True,
    ("full_cone", "full_cone"): True,
    ("full_cone", "restricted_cone"): True,
    ("full_cone", "port_restricted"): True,
    ("full_cone", "symmetric"): False,
    ("full_cone", "unknown"): True,
    ("restricted_cone", "open"): True,
    ("restricted_cone", "full_cone"): True,
    ("restricted_cone", "restricted_cone"): True,
    ("restricted_cone", "port_restricted"): True,
    ("restricted_cone", "symmetric"): False,
    ("restricted_cone", "unknown"): True,
    ("port_restricted", "open"): True,
    ("port_restricted", "full_cone"): True,
    ("port_restricted", "restricted_cone"): True,
    ("port_restricted", "port_restricted"): True,
    ("port_restricted", "symmetric"): False,
    ("port_restricted", "unknown"): True,
    ("symmetric", "open"): True,
    ("symmetric", "symmetric"): False,
    ("unknown", "unknown"): True,
}


def can_establish_p2p(nat_a: str, nat_b: str) -> bool:
    """
    Determine if two devices can establish a direct P2P connection
    based on their NAT types.

    For unknown NAT types, assume P2P is possible (optimistic) —
    the client will try hole punching and fall back to relay.
    """
    if nat_a == "unknown" or nat_b == "unknown":
        return True
    return NAT_COMPATIBILITY.get((nat_a, nat_b), False)


def classify_nat_from_addresses(mapped_addresses: List[str]) -> str:
    """
    Classify NAT type from multi-server STUN probe results.

    Each entry in mapped_addresses is "ip:port" from a different STUN server.

    Returns one of: open, full_cone, restricted_cone, port_restricted,
    symmetric, unknown
    """
    if not mapped_addresses:
        return "unknown"

    parsed: List[Tuple[str, int]] = []
    for addr in mapped_addresses:
        try:
            ip, port = addr.rsplit(":", 1)
            parsed.append((ip, int(port)))
        except (ValueError, IndexError):
            continue

    if len(parsed) < 1:
        return "unknown"

    if len(parsed) == 1:
        return "full_cone"

    first = parsed[0]
    all_identical = all(a == first for a in parsed)

    if all_identical:
        return "full_cone"

    same_ip = all(a[0] == first[0] for a in parsed)
    if same_ip:
        return "symmetric"

    return "unknown"


def generate_candidate(
    ip: str,
    port: int,
    candidate_type: str = "host",
) -> dict:
    """
    Generate a candidate entry in the standard format.

    Candidate types:
    - host: local interface address
    - srflx: server-reflexive (STUN-mapped) address
    - relay: relay server address
    """
    priority = {
        "host": 100,
        "srflx": 90,
        "relay": 50,
    }.get(candidate_type, 50)

    return {
        "addr": f"{ip}:{port}",
        "candidate_type": candidate_type,
        "priority": priority,
    }


def rank_candidates(candidates: List[dict]) -> List[dict]:
    """
    Sort candidates by priority (higher = better).
    For equal priority, host > srflx > relay.
    """
    type_order = {"host": 0, "srflx": 1, "relay": 2}
    return sorted(
        candidates,
        key=lambda c: (
            -c.get("priority", 0),
            type_order.get(c.get("candidate_type", "relay"), 99),
        ),
    )


def get_default_stun_servers() -> List[str]:
    """Return default STUN server addresses."""
    return [
        "stun.l.google.com:19302",
        "stun1.l.google.com:19302",
        "stun2.l.google.com:19302",
    ]


def estimate_p2p_success_rate(
    nat_type_a: str,
    nat_type_b: str,
    num_candidates_a: int = 1,
    num_candidates_b: int = 1,
) -> float:
    """
    Estimate P2P connection success rate based on NAT types and candidates.

    Returns a probability between 0.0 and 1.0.
    """
    if not can_establish_p2p(nat_type_a, nat_type_b):
        return 0.0

    base_rate = {
        "open": 1.0,
        "full_cone": 0.95,
        "restricted_cone": 0.85,
        "port_restricted": 0.75,
        "symmetric": 0.3,  # Only works if one side is open
        "unknown": 0.6,
    }

    rate_a = base_rate.get(nat_type_a, 0.5)
    rate_b = base_rate.get(nat_type_b, 0.5)

    # Multiple candidates improve success rate multiplicatively
    candidate_bonus_a = 1.0 - (1.0 - 0.1) ** max(num_candidates_a - 1, 0)
    candidate_bonus_b = 1.0 - (1.0 - 0.1) ** max(num_candidates_b - 1, 0)

    base = min(rate_a, rate_b)
    adjusted = base + (1.0 - base) * (candidate_bonus_a + candidate_bonus_b) / 2

    return min(adjusted, 1.0)
