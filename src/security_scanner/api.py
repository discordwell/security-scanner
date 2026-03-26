from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from .auth import _extract_and_verify, require_scope
from .config import Settings, get_settings
from .logging_config import setup_logging
from .middleware import (
    ErrorHandlerMiddleware,
    RequestLoggingMiddleware,
    RequestSizeLimitMiddleware,
    SecurityHeadersMiddleware,
)
from .models import ExecutionPolicy, ProvenanceBundle
from .service import AnalysisService

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("Security scanner starting up")
    settings = get_settings()
    app.state.settings = settings
    if not hasattr(app.state, "service"):
        app.state.service = AnalysisService()
    yield
    logger.info("Security scanner shutting down")


app = FastAPI(title="Security Scanner", version="0.1.0", lifespan=lifespan)

# Middleware (order matters: first added = outermost)
settings = get_settings()
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(ErrorHandlerMiddleware)
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_service() -> AnalysisService:
    service = getattr(app.state, "service", None)
    if service is None:
        service = AnalysisService()
        app.state.service = service
    return service


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "security-scanner", "status": "ok"}


@app.get("/health")
async def health() -> dict:
    checks = {"api": "ok"}
    # Check artifact storage
    try:
        s = get_settings()
        checks["storage"] = "ok" if s.artifact_dir.is_dir() else "unavailable"
    except Exception:
        checks["storage"] = "error"

    all_ok = all(v == "ok" for v in checks.values())
    return {"status": "healthy" if all_ok else "degraded", "checks": checks}


@app.post("/submissions")
async def create_submission(
    file: Annotated[UploadFile, File(...)],
    claimed_product: Annotated[str | None, Form()] = None,
    claimed_signer: Annotated[str | None, Form()] = None,
    authenticode_trusted: Annotated[bool | None, Form()] = None,
    enable_dynamic_analysis: Annotated[bool, Form()] = False,
    enable_symbolic_execution: Annotated[bool, Form()] = False,
    allow_external_intel: Annotated[bool, Form()] = False,
    service: AnalysisService = Depends(get_service),
    _auth=Depends(require_scope("submit")),
):
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    policy = ExecutionPolicy(
        allow_external_intel=allow_external_intel,
        enable_dynamic_analysis=enable_dynamic_analysis,
        enable_symbolic_execution=enable_symbolic_execution,
    )
    provenance = ProvenanceBundle(
        claimed_signer=claimed_signer,
        authenticode_trusted=authenticode_trusted,
    )
    result = await service.submit(
        filename=file.filename or "sample.bin",
        data=payload,
        policy=policy,
        claimed_product=claimed_product,
        provenance_bundle=provenance,
    )
    return {
        "submission": result.submission,
        "verdict": result.verdict,
        "artifacts": result.artifacts,
    }


@app.get("/submissions/{submission_id}")
async def get_submission(
    submission_id: str,
    service: AnalysisService = Depends(get_service),
    _auth=Depends(require_scope("read")),
):
    submission = await service.get_submission(submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="Submission not found.")
    return submission


@app.get("/artifacts/{sha256}")
async def get_artifact(
    sha256: str,
    service: AnalysisService = Depends(get_service),
    _auth=Depends(require_scope("read")),
):
    artifact = await service.get_artifact(sha256)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return artifact


@app.get("/verdicts/{sha256}")
async def get_verdict(
    sha256: str,
    service: AnalysisService = Depends(get_service),
    _auth=Depends(require_scope("read")),
):
    verdict = await service.get_verdict(sha256)
    if verdict is None:
        raise HTTPException(status_code=404, detail="Verdict not found.")
    return verdict


@app.post("/baselines")
async def create_baseline(
    file: Annotated[UploadFile, File(...)],
    product: Annotated[str, Form(...)],
    version: Annotated[str | None, Form()] = None,
    signer: Annotated[str | None, Form()] = None,
    service: AnalysisService = Depends(get_service),
    _auth=Depends(require_scope("submit")),
):
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    baseline = await service.register_baseline(
        filename=file.filename or Path(product).name,
        data=payload,
        product=product,
        version=version,
        signer=signer,
    )
    return baseline
