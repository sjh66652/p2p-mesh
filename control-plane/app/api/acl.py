"""
ACL (Access Control List) API — Network policy management.

Manages network access control policies for the overlay network:
- Device groups
- Allow/deny rules
- Device isolation
- Policy enforcement mode

Endpoints:
- GET /api/v1/acl/policy — get current policy
- PUT /api/v1/acl/policy — update policy
- POST /api/v1/acl/groups/{name}/devices — add device to group
- DELETE /api/v1/acl/groups/{name}/devices/{device_id} — remove from group
- POST /api/v1/acl/rules — add a rule
- DELETE /api/v1/acl/rules/{rule_id} — remove a rule
- POST /api/v1/acl/isolate/{device_id} — isolate a device
- DELETE /api/v1/acl/isolate/{device_id} — remove isolation
"""

from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

import logging
log = logging.getLogger("p2p-mesh.acl")

router = APIRouter(prefix="/api/v1/acl", tags=["ACL"])


# ---- Models ----

class AclRule(BaseModel):
    """A single ACL rule."""
    id: Optional[str] = None
    action: str = Field(..., pattern="^(allow|deny)$")
    src: str = Field(..., min_length=1, description="Source group or device ID, or '*' for any")
    dst: str = Field(..., min_length=1, description="Destination group or device ID, or '*' for any")
    protocol: str = Field(default="any", pattern="^(any|tcp|udp|icmp)$")
    ports: list[int] = Field(default_factory=list)
    src_cidrs: list[str] = Field(default_factory=list)
    priority: int = Field(default=0, ge=0)


class AclPolicy(BaseModel):
    """The full ACL policy document."""
    mode: str = Field(default="default-deny", pattern="^(default-deny|default-allow)$")
    groups: dict[str, list[str]] = Field(default_factory=dict)
    rules: list[AclRule] = Field(default_factory=list)
    isolated_devices: list[str] = Field(default_factory=list)
    bypass_devices: list[str] = Field(default_factory=list)


class AddDeviceToGroupRequest(BaseModel):
    device_id: str = Field(..., min_length=1)


class IsolateRequest(BaseModel):
    reason: Optional[str] = Field(default=None, description="Reason for isolation")


# ---- In-memory policy store (PostgreSQL-backed in production) ----

_current_policy: AclPolicy = AclPolicy(
    mode="default-deny",
    groups={
        "admin": [],
        "database": [],
        "web": [],
    },
    rules=[
        AclRule(
            id="rule-default-icmp",
            action="allow",
            src="*",
            dst="*",
            protocol="icmp",
            priority=0,
        ),
    ],
    isolated_devices=[],
    bypass_devices=["control-plane"],
)


def _generate_rule_id() -> str:
    return f"rule-{uuid4().hex[:8]}"


# ---- Endpoints ----

@router.get(
    "/policy",
    response_model=AclPolicy,
    summary="Get current ACL policy",
)
async def get_policy():
    """Retrieve the current network access control policy."""
    return _current_policy


@router.put(
    "/policy",
    response_model=AclPolicy,
    summary="Update the full ACL policy",
)
async def update_policy(policy: AclPolicy):
    """Replace the current ACL policy with a new one.

    This is a full replacement — the new policy completely replaces
    the existing one. Use the granular endpoints for incremental changes.
    """
    global _current_policy
    _current_policy = policy
    log.info("ACL policy updated: mode=%s, groups=%d, rules=%d",
             policy.mode, len(policy.groups), len(policy.rules))
    return _current_policy


@router.post(
    "/groups/{group_name}/devices",
    status_code=status.HTTP_201_CREATED,
    summary="Add a device to a group",
)
async def add_device_to_group(group_name: str, request: AddDeviceToGroupRequest):
    """Add a device to a named group.

    If the group doesn't exist, it will be created automatically.
    """
    if group_name not in _current_policy.groups:
        _current_policy.groups[group_name] = []

    if request.device_id in _current_policy.groups[group_name]:
        return {"status": "already_exists", "group": group_name, "device_id": request.device_id}

    _current_policy.groups[group_name].append(request.device_id)
    log.info("ACL: Added device %s to group %s", request.device_id, group_name)
    return {"status": "added", "group": group_name, "device_id": request.device_id}


@router.delete(
    "/groups/{group_name}/devices/{device_id}",
    summary="Remove a device from a group",
)
async def remove_device_from_group(group_name: str, device_id: str):
    """Remove a device from a named group."""
    if group_name not in _current_policy.groups:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

    if device_id not in _current_policy.groups[group_name]:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not in group '{group_name}'")

    _current_policy.groups[group_name].remove(device_id)
    log.info("ACL: Removed device %s from group %s", device_id, group_name)
    return {"status": "removed", "group": group_name, "device_id": device_id}


@router.post(
    "/rules",
    response_model=AclRule,
    status_code=status.HTTP_201_CREATED,
    summary="Add an ACL rule",
)
async def add_rule(rule: AclRule):
    """Add a new access control rule to the policy.

    Rules are evaluated in priority order (highest first).
    """
    rule.id = _generate_rule_id()
    _current_policy.rules.append(rule)
    log.info("ACL: Added rule %s: %s %s->%s proto=%s ports=%s",
             rule.id, rule.action, rule.src, rule.dst, rule.protocol, rule.ports)
    return rule


@router.delete(
    "/rules/{rule_id}",
    summary="Remove an ACL rule",
)
async def remove_rule(rule_id: str):
    """Remove a specific ACL rule by its ID."""
    for i, rule in enumerate(_current_policy.rules):
        if rule.id == rule_id:
            removed = _current_policy.rules.pop(i)
            log.info("ACL: Removed rule %s", rule_id)
            return {"status": "removed", "rule_id": rule_id, "action": removed.action}
    raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.post(
    "/isolate/{device_id}",
    status_code=status.HTTP_200_OK,
    summary="Isolate a device (emergency containment)",
)
async def isolate_device(device_id: str, request: IsolateRequest = IsolateRequest()):
    """Isolate a device from all other devices except bypass devices.

    This is an emergency measure — isolated devices cannot communicate
    with any other device except those in the bypass list (e.g., control plane).
    """
    if device_id in _current_policy.isolated_devices:
        return {"status": "already_isolated", "device_id": device_id}

    _current_policy.isolated_devices.append(device_id)
    log.warning(
        "ACL: Device %s isolated. Reason: %s",
        device_id, request.reason or "unspecified",
    )
    return {"status": "isolated", "device_id": device_id, "reason": request.reason}


@router.delete(
    "/isolate/{device_id}",
    summary="Remove device isolation",
)
async def unisolate_device(device_id: str):
    """Remove a device from the isolation list, restoring normal access."""
    if device_id not in _current_policy.isolated_devices:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' is not isolated")

    _current_policy.isolated_devices.remove(device_id)
    log.info("ACL: Device %s removed from isolation", device_id)
    return {"status": "un-isolated", "device_id": device_id}


@router.get(
    "/groups",
    summary="List all device groups",
)
async def list_groups():
    """List all configured device groups and their members."""
    return {
        "groups": _current_policy.groups,
        "total": len(_current_policy.groups),
    }
