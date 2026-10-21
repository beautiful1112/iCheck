"""Simple package sharing, local binding and shipped operation catalog."""
from fastapi import APIRouter, Depends, HTTPException, Response
from uuid import UUID
from sqlalchemy.orm import Session

from .auth import require_global_permissions
from .database import get_db
from .operations_package_schemas import OperationsExport, OperationsReview, OperationsInstall
from .sandbox import SandboxUnavailable
from .services import operations_packages as service
from .builtin_operations import packages

router = APIRouter(prefix="/api/v1/operations-packages", tags=["operations-packages"])
reader = require_global_permissions("capabilities.read")
manager = require_global_permissions("capabilities.manage")


def invoke(response, db, action, *args, **kwargs):
    response.headers["Cache-Control"] = "no-store"
    try:
        return action(db, *args, **kwargs)
    except PermissionError as error:
        db.rollback()
        raise HTTPException(403, str(error)) from None
    except SandboxUnavailable:
        db.rollback()
        raise HTTPException(503, "The native validation sandbox is not available") from None
    except (ValueError, LookupError):
        db.rollback()
        # Validation errors can contain uploaded source code or credentials.
        raise HTTPException(422, "Package validation failed. Review bindings, dependencies and portable content.") from None


@router.get("/builtins")
def builtins(response: Response, actor=Depends(reader), db: Session = Depends(get_db)):
    def catalog(db, actor):
        service.guard(db, actor)
        return [p.model_dump(mode="json") for p in packages()]
    return invoke(response, db, catalog, actor)


@router.get("/choices")
def choices(response: Response, actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, service.choices, actor)


@router.get("")
def listing(response: Response, actor=Depends(reader), db: Session = Depends(get_db)):
    return invoke(response, db, service.listing, actor)


@router.post("/export")
def export(payload: OperationsExport, response: Response, actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, service.export, payload, actor)


@router.post("/preview")
def preview(payload: OperationsReview, response: Response, actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, service.review, payload, actor)


@router.post("/import", status_code=201)
def install(payload: OperationsInstall, response: Response, actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, service.install, payload, actor)


@router.post("/{identifier}/prepare")
def prepare(identifier: UUID, response: Response, actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, service.prepare, str(identifier), actor)


def builtin_review(db, name, payload, actor, *, install=False):
    package = next((item for item in packages() if item.name == name), None)
    if package is None or payload.package != package:
        raise ValueError("Built-in package does not match the shipped content")
    return (service.install if install else service.review)(db, payload, actor, builtin=True)


@router.post("/builtins/{name}/preview")
def preview_builtin(name: str, payload: OperationsReview, response: Response,
                    actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, builtin_review, name, payload, actor)


@router.post("/builtins/{name}/import", status_code=201)
def install_builtin(name: str, payload: OperationsInstall, response: Response,
                    actor=Depends(manager), db: Session = Depends(get_db)):
    return invoke(response, db, builtin_review, name, payload, actor, install=True)
