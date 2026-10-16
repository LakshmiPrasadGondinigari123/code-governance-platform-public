"""Owner and progress for each governance control: who is fixing it and how far along it is."""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from . import auth, bus, db
from .common import audit, now

router = APIRouter()
STATUSES = ("open", "in_progress", "done")


class ActionIn(BaseModel):
    owner: Optional[str] = None
    status: Optional[str] = None


@router.get("/governance/control-actions")
def list_actions(user: dict = Depends(auth.current_user)):
    t = user["tenant_id"]
    return {"actions": {a["control_id"]: a for a in db.items("control_actions", t)}}


@router.put("/governance/control-actions/{control_id}")
def set_action(control_id: str, body: ActionIn, user: dict = Depends(auth.require("admin", "reviewer"))):
    t = user["tenant_id"]
    if not control_id.startswith("CTRL-") or len(control_id) > 64:
        raise HTTPException(400, "unknown control")
    cur = db.get("control_actions", t, control_id) or {"control_id": control_id, "owner": "", "status": "open"}
    if body.owner is not None:
        cur["owner"] = body.owner.strip()[:80]
    if body.status is not None:
        if body.status not in STATUSES:
            raise HTTPException(400, f"status must be one of {STATUSES}")
        cur["status"] = body.status
    cur["updated_at"] = now()
    cur["updated_by"] = user["username"]
    db.put("control_actions", t, control_id, cur)
    audit(user, "control.action", control_id, {"owner": cur["owner"], "status": cur["status"]})
    bus.publish(t, "findings", {"type": "findings_updated", "reason": "control_action", "control_id": control_id})
    return cur