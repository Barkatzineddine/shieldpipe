import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from sqlalchemy import ColumnElement, select, true
from sqlalchemy.orm import Session

from ..audit import audit
from ..deps import get_current_user, get_db, require_admin
from ..models import Incident, Role, Severity, Status, User
from ..schemas import IncidentCreate, IncidentOut, IncidentUpdate

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])

_NOT_FOUND = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")


def _visible_to(user: User) -> ColumnElement[bool]:
    """Analysts only see their own incidents; admins see everything."""
    if user.role == Role.ADMIN:
        return true()
    return Incident.owner_id == user.id


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _get_visible(db: Session, incident_id: uuid.UUID, user: User) -> Incident:
    # 404 rather than 403 for other users' incidents, so IDs cannot be probed.
    incident = db.scalar(select(Incident).where(Incident.id == str(incident_id), _visible_to(user)))
    if incident is None:
        raise _NOT_FOUND
    return incident


@router.get("", response_model=list[IncidentOut])
def list_incidents(
    q: str | None = Query(default=None, max_length=100, description="Search in titles"),
    severity: Severity | None = None,
    incident_status: Status | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=100),
    offset: int = Query(default=0, ge=0, le=10_000),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[Incident]:
    stmt = select(Incident).where(_visible_to(user))
    if q:
        # Bound parameter plus escaped wildcards: user input never becomes SQL.
        stmt = stmt.where(Incident.title.ilike(f"%{_escape_like(q)}%", escape="\\"))
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if incident_status:
        stmt = stmt.where(Incident.status == incident_status)
    stmt = stmt.order_by(Incident.created_at.desc()).limit(limit).offset(offset)
    return list(db.scalars(stmt))


@router.post("", response_model=IncidentOut, status_code=status.HTTP_201_CREATED)
def create_incident(
    body: IncidentCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Incident:
    incident = Incident(**body.model_dump(), owner_id=user.id)
    db.add(incident)
    db.commit()
    db.refresh(incident)
    audit(
        "incident.create",
        outcome="success",
        request=request,
        actor=user.username,
        incident_id=incident.id,
        severity=incident.severity,
    )
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
def get_incident(
    incident_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Incident:
    return _get_visible(db, incident_id, user)


@router.patch("/{incident_id}", response_model=IncidentOut)
def update_incident(
    incident_id: uuid.UUID,
    body: IncidentUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> Incident:
    incident = _get_visible(db, incident_id, user)
    changes = body.model_dump(exclude_unset=True, exclude_none=True)
    for field, value in changes.items():
        setattr(incident, field, value)
    db.commit()
    db.refresh(incident)
    audit(
        "incident.update",
        outcome="success",
        request=request,
        actor=user.username,
        incident_id=incident.id,
        fields=sorted(changes),
    )
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_incident(
    incident_id: uuid.UUID,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
) -> Response:
    incident = _get_visible(db, incident_id, admin)
    db.delete(incident)
    db.commit()
    audit(
        "incident.delete",
        outcome="success",
        request=request,
        actor=admin.username,
        incident_id=str(incident_id),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
