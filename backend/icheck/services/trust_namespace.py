"""Trust is an explicit tenant/region decision, never a global fingerprint lookup."""
from __future__ import annotations

from sqlalchemy.orm import Session

from ..config import get_settings
from ..database import Base, DEFAULT_REGION_ID, DEFAULT_TENANT_ID, session_namespace


def selected_trust_namespace(db: Session) -> tuple[str, str]:
    selected = session_namespace(db)
    if selected is not None:
        return selected
    if db.info.get("namespace_enforced") or get_settings().control_plane_auth_mode == "required":
        raise ValueError("Trust operations require an explicitly selected tenant and region")
    # Legacy, unauthenticated local service callers may use only the default
    # namespace. An unbound session must never search all tenants for a signer.
    return DEFAULT_TENANT_ID, DEFAULT_REGION_ID


def assert_selected_trust_namespace(db: Session, row: Base) -> None:
    if (row.tenant_id, row.region_id) != selected_trust_namespace(db):
        raise ValueError("Trust identity is outside the selected tenant and region")
