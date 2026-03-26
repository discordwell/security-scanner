from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile

from .models import ExecutionPolicy, ProvenanceBundle
from .service import AnalysisService


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not hasattr(app.state, "service"):
        app.state.service = AnalysisService()
    yield


app = FastAPI(title="Security Scanner", version="0.1.0", lifespan=lifespan)


def get_service() -> AnalysisService:
    service = getattr(app.state, "service", None)
    if service is None:
        service = AnalysisService()
        app.state.service = service
    return service


@app.get("/")
def root() -> dict[str, str]:
    return {"name": "security-scanner", "status": "ok"}


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
    result = service.submit(
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
def get_submission(submission_id: str, service: AnalysisService = Depends(get_service)):
    submission = service.get_submission(submission_id)
    if submission is None:
        raise HTTPException(status_code=404, detail="Submission not found.")
    return submission


@app.get("/artifacts/{sha256}")
def get_artifact(sha256: str, service: AnalysisService = Depends(get_service)):
    artifact = service.get_artifact(sha256)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return artifact


@app.get("/verdicts/{sha256}")
def get_verdict(sha256: str, service: AnalysisService = Depends(get_service)):
    verdict = service.get_verdict(sha256)
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
):
    payload = await file.read()
    if not payload:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")
    baseline = service.register_baseline(
        filename=file.filename or Path(product).name,
        data=payload,
        product=product,
        version=version,
        signer=signer,
    )
    return baseline
