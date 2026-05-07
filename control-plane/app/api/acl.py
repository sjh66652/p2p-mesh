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

from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.dependencies import get_current_user
from app.models.network import AclPolicyStore

import logging
log = logging.getLogger("p2p-mesh.acl")

router = APIRouter(prefix="/api/v1/acl", tags=["ACL"])


# ---- Models ----

class AclRule(BaseModel):
    """A single ACL rule."""
    id: str | None = None
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
    reason: str | None = Field(default=None, description="Reason for isolation")


# ---- In-memory policy store (backed by PostgreSQL acl_policies table) ----

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
_db_loaded: bool = False
_current_version: int = 0


def _generate_rule_id() -> str:
    return f"rule-{uuid4().hex[:8]}"


# ---- Database persistence ----


async def _ensure_acl_table(db: AsyncSession):
    """Ensure the acl_policies table exists."""
    try:
        await db.execute(text("""
            CREATE TABLE IF NOT EXISTS acl_policies (
                id UUID PRIMARY KEY,
                version INTEGER DEFAULT 1,
                policy_json JSONB NOT NULL,
                status VARCHAR(20) DEFAULT 'active',
                created_by VARCHAR(255),
                created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                comment TEXT,
                UNIQUE (version)
            )
        """))
        await db.commit()
        log.info("acl_policies table ensured")
    except Exception as e:
        log.debug("acl_policies table may already exist: %s", e)
        await db.rollback()


async def _load_policy_from_db(db: AsyncSession):
    """Load the latest active policy from PostgreSQL into _current_policy.

    Called lazily on first access to restore state across restarts.
    """
    global _current_policy, _db_loaded, _current_version
    if _db_loaded:
        return
    try:
        await _ensure_acl_table(db)
        result = await db.execute(
            select(AclPolicyStore)
            .where(AclPolicyStore.status == "active")
            .order_by(AclPolicyStore.version.desc())
            .limit(1)
        )
        row = result.scalar_one_or_none()
        if row is not None:
            _current_policy = AclPolicy.model_validate(row.policy_json)
            _current_version = row.version
            log.info(
                "ACL: Loaded policy from database (version=%d, mode=%s)",
                _current_version, _current_policy.mode,
            )
        else:
            # No policy in DB yet — save the current default
            log.info("ACL: No policy found in database, saving default policy")
            await _save_policy_to_db(db, comment="default policy")
        _db_loaded = True
    except Exception as e:
        log.warning("ACL: Failed to load policy from database (non-fatal): %s", e)
        _db_loaded = True


async def _save_policy_to_db(db: AsyncSession, comment: str | None = None):
    """Save the current _current_policy to the acl_policies table.

    Increments the version number on each save.
    """
    global _current_version
    _current_version += 1
    try:
        await _ensure_acl_table(db)
        # Archive any previous active policies
        await db.execute(
            text("UPDATE acl_policies SET status = 'archived' WHERE status = 'active'")
        )
        # Insert new version
        new_entry = AclPolicyStore(
            version=_current_version,
            policy_json=_current_policy.model_dump(),
            status="active",
            created_by="api",
            comment=comment or f"policy version {_current_version}",
        )
        db.add(new_entry)
        await db.commit()
        log.info("ACL: Saved policy to database (version=%d)", _current_version)
    except Exception as e:
        log.warning("ACL: Failed to save policy to database (non-fatal): %s", e)
        await db.rollback()
        _current_version -= 1  # Roll back version counter


# ---- Endpoints ----

@router.get(
    "/policy",
    response_model=AclPolicy,
    summary="Get current ACL policy",
)
async def get_policy(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve the current network access control policy."""
    await _load_policy_from_db(db)
    return _current_policy


@router.put(
    "/policy",
    response_model=AclPolicy,
    summary="Update the full ACL policy",
)
async def update_policy(
    policy: AclPolicy,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Replace the current ACL policy with a new one.

    This is a full replacement — the new policy completely replaces
    the existing one. Use the granular endpoints for incremental changes.
    """
    global _current_policy
    await _load_policy_from_db(db)
    _current_policy = policy
    log.info("ACL policy updated: mode=%s, groups=%d, rules=%d",
             policy.mode, len(policy.groups), len(policy.rules))
    await _save_policy_to_db(db, comment="policy replaced via PUT")
    return _current_policy


@router.post(
    "/groups/{group_name}/devices",
    status_code=status.HTTP_201_CREATED,
    summary="Add a device to a group",
)
async def add_device_to_group(
    group_name: str,
    request: AddDeviceToGroupRequest,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a device to a named group.

    If the group doesn't exist, it will be created automatically.
    """
    await _load_policy_from_db(db)
    if group_name not in _current_policy.groups:
        _current_policy.groups[group_name] = []

    if request.device_id in _current_policy.groups[group_name]:
        return {"status": "already_exists", "group": group_name, "device_id": request.device_id}

    _current_policy.groups[group_name].append(request.device_id)
    log.info("ACL: Added device %s to group %s", request.device_id, group_name)
    await _save_policy_to_db(db, comment=f"added device {request.device_id} to group {group_name}")
    return {"status": "added", "group": group_name, "device_id": request.device_id}


@router.delete(
    "/groups/{group_name}/devices/{device_id}",
    summary="Remove a device from a group",
)
async def remove_device_from_group(
    group_name: str,
    device_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a device from a named group."""
    await _load_policy_from_db(db)
    if group_name not in _current_policy.groups:
        raise HTTPException(status_code=404, detail=f"Group '{group_name}' not found")

    if device_id not in _current_policy.groups[group_name]:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not in group '{group_name}'")

    _current_policy.groups[group_name].remove(device_id)
    log.info("ACL: Removed device %s from group %s", device_id, group_name)
    await _save_policy_to_db(db, comment=f"removed device {device_id} from group {group_name}")
    return {"status": "removed", "group": group_name, "device_id": device_id}


@router.post(
    "/rules",
    response_model=AclRule,
    status_code=status.HTTP_201_CREATED,
    summary="Add an ACL rule",
)
async def add_rule(
    rule: AclRule,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Add a new access control rule to the policy.

    Rules are evaluated in priority order (highest first).
    """
    await _load_policy_from_db(db)
    rule.id = _generate_rule_id()
    _current_policy.rules.append(rule)
    log.info("ACL: Added rule %s: %s %s->%s proto=%s ports=%s",
             rule.id, rule.action, rule.src, rule.dst, rule.protocol, rule.ports)
    await _save_policy_to_db(db, comment=f"added rule {rule.id}")
    return rule


@router.delete(
    "/rules/{rule_id}",
    summary="Remove an ACL rule",
)
async def remove_rule(
    rule_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a specific ACL rule by its ID."""
    await _load_policy_from_db(db)
    for i, rule in enumerate(_current_policy.rules):
        if rule.id == rule_id:
            removed = _current_policy.rules.pop(i)
            log.info("ACL: Removed rule %s", rule_id)
            await _save_policy_to_db(db, comment=f"removed rule {rule_id}")
            return {"status": "removed", "rule_id": rule_id, "action": removed.action}
    raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


@router.post(
    "/isolate/{device_id}",
    status_code=status.HTTP_200_OK,
    summary="Isolate a device (emergency containment)",
)
async def isolate_device(
    device_id: str,
    request: IsolateRequest = IsolateRequest(),
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Isolate a device from all other devices except bypass devices.

    This is an emergency measure — isolated devices cannot communicate
    with any other device except those in the bypass list (e.g., control plane).
    """
    await _load_policy_from_db(db)
    if device_id in _current_policy.isolated_devices:
        return {"status": "already_isolated", "device_id": device_id}

    _current_policy.isolated_devices.append(device_id)
    log.warning(
        "ACL: Device %s isolated. Reason: %s",
        device_id, request.reason or "unspecified",
    )
    await _save_policy_to_db(db, comment=f"isolated device {device_id}: {request.reason or 'unspecified'}")
    return {"status": "isolated", "device_id": device_id, "reason": request.reason}


@router.delete(
    "/isolate/{device_id}",
    summary="Remove device isolation",
)
async def unisolate_device(
    device_id: str,
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Remove a device from the isolation list, restoring normal access."""
    await _load_policy_from_db(db)
    if device_id not in _current_policy.isolated_devices:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' is not isolated")

    _current_policy.isolated_devices.remove(device_id)
    log.info("ACL: Device %s removed from isolation", device_id)
    await _save_policy_to_db(db, comment=f"un-isolated device {device_id}")
    return {"status": "un-isolated", "device_id": device_id}


@router.get(
    "/groups",
    summary="List all device groups",
)
async def list_groups(
    user=Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all configured device groups and their members."""
    await _load_policy_from_db(db)
    return {
        "groups": _current_policy.groups,
        "total": len(_current_policy.groups),
    }
