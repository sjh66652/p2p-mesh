"""
Candidate schemas — NAT traversal candidate exchange.

Candidates represent potential network paths for establishing
a direct P2P connection. They are discovered via STUN (server-reflexive)
and local interface enumeration (host).
"""

from pydantic import BaseModel, Field
from typing import List, Optional


class CandidateEntry(BaseModel):
    """A single network candidate for NAT traversal."""
    addr: str = Field(..., description="Socket address (ip:port)")
    candidate_type: str = Field(
        ..., description="Candidate type: host, srflx (server-reflexive), relay"
    )
    priority: int = Field(default=100, description="Candidate priority (higher = preferred)")


class CandidateRegister(BaseModel):
    """Register candidates for a device."""
    device_id: str = Field(..., description="Device UUID")
    candidates: List[CandidateEntry] = Field(..., description="List of network candidates")


class CandidateResponse(BaseModel):
    """Response containing candidates for a device."""
    device_id: str
    candidates: List[CandidateEntry]
    updated_at: str


class CandidateListResponse(BaseModel):
    """List of all candidate registrations."""
    candidates: List[CandidateResponse]


class NATProbeRequest(BaseModel):
    """Request to probe NAT type."""
    device_id: str = Field(..., description="Device UUID")
    stun_servers: Optional[List[str]] = Field(
        default=None,
        description="STUN servers to probe (defaults to configured servers)"
    )


class NATProbeResponse(BaseModel):
    """NAT probe result."""
    device_id: str
    nat_type: str
    mapped_addrs: List[str] = Field(
        default_factory=list,
        description="Mapped addresses from each STUN server"
    )
