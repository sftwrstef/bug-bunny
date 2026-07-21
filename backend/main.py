from __future__ import annotations

import json
import os
import ipaddress
import hashlib
import hmac
import re
import shutil
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr, StrictBool, field_validator

from proofs.idor_proof import write_proof
from backend.replay_engine import (
    ReplayHostBusyError,
    ReplayValidationError,
    build_capture_plan,
    build_sanitized_artifact,
    execute_capture_plan,
    validate_sanitized_artifact,
)


ROOT_DIR = Path(__file__).resolve().parents[1]
DB_PATH = ROOT_DIR / "audit_console.sqlite3"
RUNS_DIR = ROOT_DIR / "runs"
ARTIFACTS_DIR = ROOT_DIR / "artifacts"
WEB_ENGINE_URL = os.environ.get("BUG_BUNNY_WEB_ENGINE_URL", "http://127.0.0.1:8787")
WEB_AUDIT_TIMEOUT_SECONDS = 90
AI_MODEL = os.environ.get("BUG_BUNNY_AI_MODEL", "opencode-go/kimi-k3")
AI_AGENT = os.environ.get("BUG_BUNNY_AI_AGENT", "bug-bunny")
AI_TIMEOUT_SECONDS = int(os.environ.get("BUG_BUNNY_AI_TIMEOUT_SECONDS", "180"))
AI_ARTIFACT_NAME = "ai-analysis.json"
INTIGRITI_PWN_PROFILE_ID = "intigriti-pwn"
INTIGRITI_PWN_PROOF_PROFILE_ID = "intigriti-pwn-proof"
AUTHENTICATED_REPLAY_PROFILE_ID = "authenticated-replay"
INTIGRITI_PWN_POLICY_URL = "https://app.intigriti.com/programs/intigriti/intigriti/detail"
INTIGRITI_PWN_HOST_SUFFIX = ".pwn.intigriti.rocks"
INTIGRITI_PWN_REQUESTS_PER_SECOND = 2
INTIGRITI_PWN_REQUEST_BUDGET = 24
INTIGRITI_PWN_PROOF_REQUEST_BUDGET = 4
CONTROLLED_PROOF_ARTIFACT_NAME = "controlled-proof.json"
AUTHENTICATED_REPLAY_ARTIFACT_NAME = "authenticated-replay.json"
AUTHENTICATED_REPLAY_INTENT = "authenticated-replay-v1"
AUTHENTICATED_REPLAY_BODY_LIMIT = 64 * 1024


class AuditCreateRequest(BaseModel):
    target: str = Field(min_length=1)
    scope_notes: str = ""
    authorized: bool = False
    mode: Literal["local_lab", "external_program"] = "local_lab"
    program_profile: "ExternalProgramProfile | None" = None


class ExternalProgramProfile(BaseModel):
    platform: Literal["HackerOne", "Bugcrowd", "Intigriti"]
    profile_id: Literal["custom-passive", "intigriti-pwn", "intigriti-pwn-proof", "authenticated-replay"] = "custom-passive"
    program_name: str = ""
    policy_url: str = ""
    researcher_username: str = ""
    allowed_hosts: list[str] = Field(default_factory=list, max_length=4)
    proof_hypothesis: str = Field(default="", max_length=1000)
    controlled_accounts_acknowledged: bool = False
    minimum_proof_acknowledged: bool = False
    automation_acknowledged: bool = False
    human_review_acknowledged: bool = False


class ControlledProofResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_actor: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    peer_actor: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9_.-]+$")
    object_kind: Literal["submission_draft"] = "submission_draft"
    target_host: str = Field(min_length=1, max_length=253, pattern=r"^[a-z0-9.-]+$")
    object_locator_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_marker_observed: StrictBool
    peer_outcomes: list[Literal["forbidden"]] = Field(min_length=2, max_length=2)
    peer_marker_observed: StrictBool
    sessions_isolated: StrictBool
    third_party_data_observed: StrictBool

    @field_validator("owner_marker_observed", "sessions_isolated")
    @classmethod
    def require_true_attestation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("must be true")
        return value

    @field_validator("peer_marker_observed", "third_party_data_observed")
    @classmethod
    def require_false_attestation(cls, value: bool) -> bool:
        if value is not False:
            raise ValueError("must be false")
        return value


class AuthenticatedReplayPreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    owner_curl: SecretStr
    peer_curl: SecretStr

    @field_validator("owner_curl", "peer_curl")
    @classmethod
    def require_capture(cls, value: SecretStr) -> SecretStr:
        if not value.get_secret_value().strip():
            raise ValueError("must contain a cURL capture")
        return value


class AuthenticatedReplayExecuteRequest(AuthenticatedReplayPreviewRequest):
    object_kind: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9 _.-]+$")
    owner_marker: SecretStr
    peer_marker: SecretStr
    preview_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    sessions_isolated: StrictBool
    controlled_objects_acknowledged: StrictBool
    third_party_data_expected: StrictBool

    @field_validator("owner_marker", "peer_marker")
    @classmethod
    def require_marker(cls, value: SecretStr) -> SecretStr:
        length = len(value.get_secret_value().encode("utf-8"))
        if length < 1 or length > 512:
            raise ValueError("must contain 1-512 UTF-8 bytes")
        return value

    @field_validator("sessions_isolated", "controlled_objects_acknowledged")
    @classmethod
    def require_true_replay_attestation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("must be true")
        return value

    @field_validator("third_party_data_expected")
    @classmethod
    def require_no_third_party_data(cls, value: bool) -> bool:
        if value is not False:
            raise ValueError("must be false")
        return value


class AuditRunModel(BaseModel):
    run_id: str
    target: str
    target_type: str
    scope_notes: str
    authorized: bool
    mode: str
    policy_receipt: dict[str, Any]
    status: str
    run_dir: str
    raw_dir: str
    reports_dir: str
    report_path: str | None = None
    created_at: str
    updated_at: str


class FindingModel(BaseModel):
    finding_id: str
    run_id: str
    severity: str
    title: str
    location: str
    hypothesis: str
    confidence: int
    evidence: dict[str, Any]
    remediation: str
    poc: str
    status: str
    created_at: str


class AIAnalysisModel(BaseModel):
    verdict: Literal["OBSERVATION", "NEEDS_MANUAL_VALIDATION", "VERIFIED", "OVERSTATED", "INVALID"]
    summary: str = Field(min_length=1, max_length=4000)
    observed_facts: list[str]
    unsupported_claims: list[str]
    likely_dismissal: str | bool
    attacker: str | None
    victim: str | None
    asset_or_authority_at_risk: str | None
    safest_next_manual_step: str
    proof_requirements: list[str]
    submission_ready: bool


app = FastAPI(title="Bug Bunny.ai Local Audit Console", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5173", "http://localhost:5173"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(_request: Request, error: RequestValidationError) -> JSONResponse:
    """Never echo a rejected SecretStr capture in FastAPI's validation response."""
    safe_errors = []
    for item in error.errors():
        safe_errors.append(
            {
                "type": item.get("type", "value_error"),
                "loc": list(item.get("loc") or []),
                "msg": item.get("msg", "Invalid request"),
            }
        )
    return JSONResponse(status_code=422, content={"detail": safe_errors}, headers={"Cache-Control": "no-store"})


@app.middleware("http")
async def authenticated_replay_guard(request: Request, call_next: Any) -> Any:
    replay_request = request.method == "POST" and "/authenticated-replay/" in request.url.path
    if replay_request:
        if request.headers.get("transfer-encoding"):
            return JSONResponse(
                status_code=413,
                content={"detail": "Chunked authenticated-replay bodies are not accepted."},
                headers={"Cache-Control": "no-store"},
            )
        raw_length = request.headers.get("content-length")
        try:
            content_length = int(raw_length or "0")
        except ValueError:
            content_length = AUTHENTICATED_REPLAY_BODY_LIMIT + 1
        if content_length > AUTHENTICATED_REPLAY_BODY_LIMIT:
            return JSONResponse(
                status_code=413,
                content={"detail": "Authenticated-replay input exceeds the 64 KiB limit."},
                headers={"Cache-Control": "no-store"},
            )
    response = await call_next(request)
    if replay_request:
        response.headers["Cache-Control"] = "no-store"
    return response


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    RUNS_DIR.mkdir(exist_ok=True)
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_runs (
                run_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                scope_notes TEXT NOT NULL,
                authorized INTEGER NOT NULL,
                status TEXT NOT NULL,
                run_dir TEXT NOT NULL,
                raw_dir TEXT NOT NULL,
                reports_dir TEXT NOT NULL,
                report_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                location TEXT NOT NULL,
                hypothesis TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence_json TEXT NOT NULL,
                remediation TEXT NOT NULL,
                poc TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY(run_id) REFERENCES audit_runs(run_id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_run_id ON findings(run_id)")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_runs)").fetchall()}
        if "mode" not in columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN mode TEXT NOT NULL DEFAULT 'local_lab'")
        if "policy_receipt_json" not in columns:
            conn.execute("ALTER TABLE audit_runs ADD COLUMN policy_receipt_json TEXT NOT NULL DEFAULT '{}'")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


def classify_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"
    return "repo_path"


def row_to_run(row: sqlite3.Row) -> AuditRunModel:
    raw_receipt = row["policy_receipt_json"] if "policy_receipt_json" in row.keys() else "{}"
    try:
        policy_receipt = json.loads(raw_receipt or "{}")
    except json.JSONDecodeError:
        policy_receipt = {}
    return AuditRunModel(
        run_id=row["run_id"],
        target=row["target"],
        target_type=row["target_type"],
        scope_notes=row["scope_notes"],
        authorized=bool(row["authorized"]),
        mode=row["mode"] if "mode" in row.keys() else "local_lab",
        policy_receipt=policy_receipt,
        status=row["status"],
        run_dir=row["run_dir"],
        raw_dir=row["raw_dir"],
        reports_dir=row["reports_dir"],
        report_path=row["report_path"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def row_to_finding(row: sqlite3.Row) -> FindingModel:
    return FindingModel(
        finding_id=row["finding_id"],
        run_id=row["run_id"],
        severity=row["severity"],
        title=row["title"],
        location=row["location"],
        hypothesis=row["hypothesis"],
        confidence=row["confidence"],
        evidence=json.loads(row["evidence_json"]),
        remediation=row["remediation"],
        poc=row["poc"],
        status=row["status"],
        created_at=row["created_at"],
    )


def get_run_or_404(run_id: str) -> AuditRunModel:
    with connect() as conn:
        row = conn.execute("SELECT * FROM audit_runs WHERE run_id = ?", (run_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Audit run not found")
    return row_to_run(row)


def get_findings_for_run(run_id: str) -> list[FindingModel]:
    with connect() as conn:
        rows = conn.execute(
            "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at ASC, severity DESC",
            (run_id,),
        ).fetchall()
    return [row_to_finding(row) for row in rows]


def update_run_status(run_id: str, status: str, report_path: str | None = None) -> None:
    now = utc_now()
    with connect() as conn:
        if report_path is None:
            conn.execute(
                "UPDATE audit_runs SET status = ?, updated_at = ? WHERE run_id = ?",
                (status, now, run_id),
            )
        else:
            conn.execute(
                "UPDATE audit_runs SET status = ?, report_path = ?, updated_at = ? WHERE run_id = ?",
                (status, report_path, now, run_id),
            )


def build_external_policy_receipt(payload: AuditCreateRequest, target: str) -> dict[str, Any]:
    profile = payload.program_profile
    if profile is None:
        raise HTTPException(status_code=400, detail="External Program mode requires a current program policy receipt.")

    parsed_target = urlparse(target)
    parsed_policy = urlparse(profile.policy_url.strip())
    if parsed_target.scheme != "https" or not parsed_target.netloc:
        raise HTTPException(status_code=400, detail="External Program mode requires one exact public HTTPS target URL.")
    hostname = parsed_target.hostname or ""
    try:
        ipaddress.ip_address(hostname)
        target_is_ip = True
    except ValueError:
        target_is_ip = False
    if hostname == "localhost" or hostname.endswith(".localhost") or target_is_ip:
        raise HTTPException(status_code=400, detail="External Program mode cannot target localhost or an IP address.")
    if not profile.program_name.strip():
        raise HTTPException(status_code=400, detail="Record the program name in the policy receipt.")
    if not parsed_policy.scheme == "https" or not parsed_policy.netloc:
        raise HTTPException(status_code=400, detail="Policy URL must be a current HTTPS URL.")
    if not profile.automation_acknowledged:
        detail = (
            "Confirm that the current policy permits this tightly scoped controlled validation."
            if profile.profile_id == INTIGRITI_PWN_PROOF_PROFILE_ID
            else "Confirm that the current policy permits a low-rate read-only check."
        )
        raise HTTPException(status_code=400, detail=detail)
    if not profile.human_review_acknowledged:
        raise HTTPException(status_code=400, detail="Confirm that you will manually validate observations before reporting them.")

    if profile.profile_id == AUTHENTICATED_REPLAY_PROFILE_ID:
        try:
            target_port = parsed_target.port
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Authenticated-replay target port is invalid.") from error
        if parsed_target.username or parsed_target.password or target_port not in {None, 443}:
            raise HTTPException(
                status_code=400,
                detail="Authenticated-replay targets must use HTTPS on port 443 with no URL credentials.",
            )
        allowed_hosts: list[str] = []
        for raw_host in profile.allowed_hosts:
            allowed_host = raw_host.strip().lower().rstrip(".")
            try:
                ipaddress.ip_address(allowed_host)
                host_is_ip = True
            except ValueError:
                host_is_ip = False
            if (
                not allowed_host
                or host_is_ip
                or allowed_host == "localhost"
                or allowed_host.endswith(".localhost")
                or "*" in allowed_host
                or "/" in allowed_host
                or ":" in allowed_host
                or not re.fullmatch(r"[a-z0-9.-]+", allowed_host)
            ):
                raise HTTPException(
                    status_code=400,
                    detail="Each authenticated-replay host must be one explicit public hostname; wildcards, IPs, ports, and URLs are forbidden.",
                )
            if allowed_host not in allowed_hosts:
                allowed_hosts.append(allowed_host)
        if not allowed_hosts:
            raise HTTPException(status_code=400, detail="List every hostname required for authenticated replay.")
        if hostname.lower().rstrip(".") not in allowed_hosts:
            raise HTTPException(status_code=400, detail="The exact target hostname must appear in the authenticated-replay host list.")
        if not profile.proof_hypothesis.strip():
            raise HTTPException(status_code=400, detail="Record exactly one victim-centered proof hypothesis.")
        if not profile.controlled_accounts_acknowledged:
            raise HTTPException(status_code=400, detail="Confirm that both accounts and both harmless objects are controlled by you.")
        if not profile.minimum_proof_acknowledged:
            raise HTTPException(status_code=400, detail="Confirm the four-request maximum and stop-on-exposure condition.")
        return {
            "profileId": AUTHENTICATED_REPLAY_PROFILE_ID,
            "platform": profile.platform,
            "programName": profile.program_name.strip(),
            "policyUrl": profile.policy_url.strip(),
            "policySnapshotDate": datetime.now(timezone.utc).date().isoformat(),
            "exactScopeUrl": target,
            "allowedHosts": allowed_hosts,
            "executionMode": "authenticated-capture-replay",
            "authenticatedReplayEnabled": True,
            "automatedCollection": "user-initiated ephemeral credentials only",
            "requestRatePerSecond": 1,
            "requestBudget": 4,
            "allowedReplayMethods": ["GET"],
            "redirectPolicy": "do-not-follow",
            "responseBytesPerAttemptMax": 262144,
            "proofHypothesis": profile.proof_hypothesis.strip(),
            "controlledActors": {
                "owner": "Account A — self-created and controlled by researcher",
                "peer": "Account B — self-created and controlled by researcher",
            },
            "requiredEvidence": [
                "one Account A and one Account B same-account marker control",
                "one B-to-A replay, repeated only after no exposure",
                "write-once secret-free response hashes and marker booleans",
            ],
            "prohibitedActions": [
                "third-party accounts or data",
                "identifier enumeration",
                "credential attacks or brute force",
                "cross-scope traffic or redirects",
                "state-changing methods",
                "destructive actions, persistence, or denial of service",
                "storing raw cURL, URLs, object identifiers, header values, credentials, markers, or bodies",
            ],
            "stopCondition": "Stop immediately on exposure; otherwise stop after the second stable denied replay.",
            "output": "write-once sanitized authenticated-replay receipt; never automatically submission ready",
            "automationAcknowledged": True,
            "humanReviewAcknowledged": True,
            "controlledAccountsAcknowledged": True,
            "minimumProofAcknowledged": True,
            "recordedAt": utc_now(),
        }

    if profile.profile_id in {INTIGRITI_PWN_PROFILE_ID, INTIGRITI_PWN_PROOF_PROFILE_ID}:
        researcher_username = profile.researcher_username.strip()
        if profile.platform != "Intigriti":
            raise HTTPException(status_code=400, detail="The Intigriti PWN profile must use the Intigriti platform.")
        if hostname != "pwn.intigriti.rocks" and not hostname.endswith(INTIGRITI_PWN_HOST_SUFFIX):
            raise HTTPException(
                status_code=400,
                detail="The Intigriti PWN profile only permits an exact host under *.pwn.intigriti.rocks.",
            )
        if profile.policy_url.rstrip("/") != INTIGRITI_PWN_POLICY_URL.rstrip("/"):
            raise HTTPException(status_code=400, detail="The Intigriti PWN profile must use its pinned official policy URL.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{2,64}", researcher_username):
            raise HTTPException(
                status_code=400,
                detail="Enter your real Intigriti username so every request carries the required attribution header.",
            )

        if profile.profile_id == INTIGRITI_PWN_PROOF_PROFILE_ID:
            try:
                target_port = parsed_target.port
            except ValueError as error:
                raise HTTPException(status_code=400, detail="Controlled-proof target port is invalid.") from error
            if parsed_target.username or parsed_target.password or target_port not in {None, 443}:
                raise HTTPException(
                    status_code=400,
                    detail="Controlled-proof targets must use HTTPS on port 443 with no URL credentials.",
                )
            allowed_hosts: list[str] = []
            for raw_host in profile.allowed_hosts:
                allowed_host = raw_host.strip().lower().rstrip(".")
                if (
                    not allowed_host
                    or "*" in allowed_host
                    or "/" in allowed_host
                    or ":" in allowed_host
                    or not re.fullmatch(r"[a-z0-9.-]+", allowed_host)
                    or not allowed_host.endswith(INTIGRITI_PWN_HOST_SUFFIX)
                ):
                    raise HTTPException(
                        status_code=400,
                        detail="Each controlled-proof host must be one explicit hostname under *.pwn.intigriti.rocks; wildcards and URLs are forbidden.",
                    )
                if allowed_host not in allowed_hosts:
                    allowed_hosts.append(allowed_host)

            if not allowed_hosts:
                raise HTTPException(status_code=400, detail="List every PWN hostname required for the controlled proof.")
            if hostname.lower().rstrip(".") not in allowed_hosts:
                raise HTTPException(status_code=400, detail="The exact target hostname must appear in the controlled-proof host list.")
            if not profile.proof_hypothesis.strip():
                raise HTTPException(status_code=400, detail="Record exactly one victim-centered proof hypothesis.")
            if not profile.controlled_accounts_acknowledged:
                raise HTTPException(status_code=400, detail="Confirm that both attacker and victim accounts are self-created and controlled by you.")
            if not profile.minimum_proof_acknowledged:
                raise HTTPException(status_code=400, detail="Confirm the known-ID, minimum-proof stop condition.")

            return {
                "profileId": INTIGRITI_PWN_PROOF_PROFILE_ID,
                "platform": "Intigriti",
                "programName": "Intigriti",
                "policyUrl": INTIGRITI_PWN_POLICY_URL,
                "policySnapshotDate": "2026-07-21",
                "exactScopeUrl": target,
                "allowedHosts": allowed_hosts,
                "researcherUsername": researcher_username,
                "attributionHeaders": ["X-Intigriti-Username", "User-Agent"],
                "executionMode": "authenticated-capture-replay",
                "authenticatedReplayEnabled": True,
                "automatedCollection": "user-initiated ephemeral credentials only",
                "requestRatePerSecond": INTIGRITI_PWN_REQUESTS_PER_SECOND,
                "publishedRequestRatePerSecond": 10,
                "requestBudget": INTIGRITI_PWN_PROOF_REQUEST_BUDGET,
                "allowedReplayMethods": ["GET"],
                "redirectPolicy": "do-not-follow",
                "responseBytesPerAttemptMax": 262144,
                "proofHypothesis": profile.proof_hypothesis.strip(),
                "controlledActors": {
                    "attacker": "Account B — self-created and controlled by researcher",
                    "victim": "Account A — self-created and controlled by researcher",
                },
                "manualFixtureActions": [
                    "create two controlled PWN accounts",
                    "create one harmless Account A-owned object with a unique benign marker",
                    "create one harmless marked object under each controlled account",
                    "capture each account's legitimate GET with DevTools Copy as cURL",
                    "preview Bug Bunny's secret-free request shape before execution",
                    "run B-to-B and A-to-A controls, then replay A's known object with only B's session headers",
                    "repeat only a denied replay; stop immediately if A's marker is exposed",
                ],
                "requiredEvidence": [
                    "Account A and Account B same-account control outcomes",
                    "one or two bounded B-to-A replay outcomes and marker-present booleans",
                    "server timestamp, DNS pin, request budget, response SHA-256 values, and session-isolation attestation",
                    "capture, template, and response hashes only; never raw credentials, bodies, markers, object identifiers, or URLs",
                ],
                "prohibitedActions": [
                    "third-party accounts or data",
                    "identifier enumeration",
                    "credential attacks or brute force",
                    "cross-scope traffic",
                    "destructive actions or persistence",
                    "denial of service",
                    "storing raw cURL, request or response bodies, header values, raw object URLs or identifiers, credentials, cookies, session tokens, markers, email addresses, or unrelated personal data in the run",
                ],
                "stopCondition": "Stop after the minimum controlled deterministic proof is captured, whether allowed or denied.",
                "output": "write-once sanitized authenticated-replay receipt; live results remain non-submission-ready pending human review",
                "automationAcknowledged": True,
                "humanReviewAcknowledged": True,
                "controlledAccountsAcknowledged": True,
                "minimumProofAcknowledged": True,
                "recordedAt": utc_now(),
            }

        return {
            "profileId": INTIGRITI_PWN_PROFILE_ID,
            "platform": "Intigriti",
            "programName": "Intigriti",
            "policyUrl": INTIGRITI_PWN_POLICY_URL,
            "policySnapshotDate": "2026-07-21",
            "exactScopeUrl": target,
            "allowedHostSuffix": INTIGRITI_PWN_HOST_SUFFIX,
            "researcherUsername": researcher_username,
            "attributionHeaders": ["X-Intigriti-Username", "User-Agent"],
            "requestRatePerSecond": INTIGRITI_PWN_REQUESTS_PER_SECOND,
            "publishedRequestRatePerSecond": 10,
            "requestBudget": INTIGRITI_PWN_REQUEST_BUDGET,
            "allowedMethods": ["GET", "HEAD"],
            "redirectPolicy": "same-origin-only; maximum 2",
            "discoveryPolicy": "root, standard policy files, and same-origin links/assets found in retrieved pages",
            "prohibitedActions": [
                "cross-origin discovery",
                "subdomain enumeration",
                "credential attacks",
                "form submission",
                "state-changing requests",
                "payload mutation",
                "denial of service",
                "access to other users' data",
            ],
            "output": "evidence-and-hypotheses; deterministic proof still required",
            "automationAcknowledged": True,
            "humanReviewAcknowledged": True,
            "recordedAt": utc_now(),
        }

    return {
        "profileId": "custom-passive",
        "platform": profile.platform,
        "programName": profile.program_name.strip(),
        "policyUrl": profile.policy_url.strip(),
        "exactScopeUrl": target,
        "requestRatePerSecond": 1,
        "requestBudget": 1,
        "allowedMethods": ["GET"],
        "redirectPolicy": "do-not-follow",
        "prohibitedActions": [
            "path discovery",
            "route guessing",
            "CORS origin manipulation",
            "authentication",
            "payload mutation",
            "active exploitation",
            "reproduction traffic",
        ],
        "output": "observations-only",
        "automationAcknowledged": True,
        "humanReviewAcknowledged": True,
        "recordedAt": utc_now(),
    }


def mock_scan_payload(run: AuditRunModel) -> dict[str, Any]:
    target_label = run.target
    if run.target_type == "url":
        findings = [
            {
                "severity": "Medium",
                "title": "Missing Content-Security-Policy header",
                "location": target_label,
                "hypothesis": "The application does not advertise a CSP in mock scanner mode, increasing XSS blast radius if injection exists.",
                "confidence": 82,
                "evidence": {
                    "scanner": "mock-web-baseline",
                    "observed": "content-security-policy header absent in simulated response profile",
                    "mode": "mock",
                },
                "remediation": "Define a restrictive Content-Security-Policy and tune script/style sources.",
                "poc": f"curl -I {json.dumps(target_label)}",
            },
            {
                "severity": "Low",
                "title": "No clickjacking frame control detected",
                "location": target_label,
                "hypothesis": "The page may be embeddable unless runtime controls prevent framing.",
                "confidence": 70,
                "evidence": {
                    "scanner": "mock-web-baseline",
                    "observed": "x-frame-options and CSP frame-ancestors absent in simulated response profile",
                    "mode": "mock",
                },
                "remediation": "Add CSP frame-ancestors or X-Frame-Options according to product requirements.",
                "poc": f"curl -I {json.dumps(target_label)}",
            },
            {
                "severity": "Info",
                "title": "Security contact metadata not configured",
                "location": f"{target_label.rstrip('/')}/.well-known/security.txt",
                "hypothesis": "Researchers may not have a standard disclosure contact path.",
                "confidence": 55,
                "evidence": {
                    "scanner": "mock-route-baseline",
                    "observed": "security.txt absent in mock route profile",
                    "mode": "mock",
                },
                "remediation": "Publish /.well-known/security.txt with contact and policy details.",
                "poc": f"curl -sS {json.dumps(target_label.rstrip('/') + '/.well-known/security.txt')}",
            },
        ]
    else:
        findings = [
            {
                "severity": "Medium",
                "title": "Repository dependency review required",
                "location": target_label,
                "hypothesis": "Mock repo scan identified dependency metadata that should be checked with a real SCA tool next.",
                "confidence": 60,
                "evidence": {
                    "scanner": "mock-repo-baseline",
                    "observed": "repo path accepted and queued for dependency review",
                    "mode": "mock",
                },
                "remediation": "Run the repo through an SCA scanner and pin/patch vulnerable packages.",
                "poc": f"ls -la {json.dumps(target_label)}",
            }
        ]

    return {
        "run_id": run.run_id,
        "target": run.target,
        "target_type": run.target_type,
        "scope_notes": run.scope_notes,
        "scanner_mode": "mock",
        "generated_at": utc_now(),
        "findings": findings,
    }


def web_engine_request(path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    body = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        f"{WEB_ENGINE_URL}{path}",
        data=body,
        method="POST" if payload is not None else "GET",
        headers={"content-type": "application/json"},
    )
    try:
        with urlopen(request, timeout=10) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise HTTPException(status_code=502, detail=f"Web audit engine rejected the request: {detail}") from error
    except (URLError, TimeoutError) as error:
        raise HTTPException(
            status_code=503,
            detail="Safe Web engine is unavailable. Start Bug Bunny with `npm run dev`.",
        ) from error


def load_engine_audit(run: AuditRunModel) -> dict[str, Any] | None:
    raw_path = Path(run.raw_dir) / "web_audit.json"
    if not raw_path.exists():
        return None
    return json.loads(raw_path.read_text(encoding="utf-8"))


def load_controlled_proof_artifact(run: AuditRunModel) -> dict[str, Any] | None:
    artifact_path = Path(run.raw_dir) / CONTROLLED_PROOF_ARTIFACT_NAME
    if not artifact_path.exists():
        return None
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
        result = artifact["result"]
        target = result["target"]
        actors = result["actors"]
        control = result["truthfulControl"]
        branch = result["authorizationBranch"]
        redaction = result["redaction"]
        recorded_at = datetime.fromisoformat(artifact["recorded_at"])
        expected_reason = (
            "No IDOR observed in the tested draft flow. Owner access succeeded; "
            "Account B was denied on both controlled replays. Hypothesis closed."
        )
        valid = all(
            [
                set(artifact) == {"schema_version", "proof_type", "evidence_origin", "run_id", "recorded_at", "result"},
                artifact["schema_version"] == 1,
                artifact["proof_type"] == "controlled_external_known_id",
                artifact["evidence_origin"] == "manual_redacted_import",
                artifact["run_id"] == run.run_id,
                recorded_at.tzinfo is not None,
                set(result) == {
                    "schemaVersion", "verdict", "classification", "testedScope", "submissionReady",
                    "hypothesis", "recordedAt", "target", "actors", "truthfulControl",
                    "authorizationBranch", "redaction", "reason",
                },
                result["schemaVersion"] == 1,
                result["verdict"] == "INVALID",
                result["classification"] == "NO_IDOR",
                result["testedScope"] == "tested_draft_only",
                result["submissionReady"] is False,
                result["hypothesis"] == run.policy_receipt.get("proofHypothesis"),
                result["recordedAt"] == artifact["recorded_at"],
                set(target) == {"host", "objectKind", "objectLocatorSha256"},
                target["host"] in (run.policy_receipt.get("allowedHosts") or []),
                target["objectKind"] == "submission_draft",
                re.fullmatch(r"[a-f0-9]{64}", target["objectLocatorSha256"]) is not None,
                set(actors) == {"owner", "peer", "bothResearcherControlled", "sessionsIsolated"},
                re.fullmatch(r"[A-Za-z0-9_.-]{2,80}", actors["owner"]) is not None,
                re.fullmatch(r"[A-Za-z0-9_.-]{2,80}", actors["peer"]) is not None,
                actors["owner"] != actors["peer"],
                actors["bothResearcherControlled"] is True,
                actors["sessionsIsolated"] is True,
                control == {"outcome": "owner_access_succeeded", "markerObserved": True},
                set(branch) == {"attempts", "outcomes", "markerObserved", "thirdPartyDataObserved"},
                branch["attempts"] == 2,
                branch["outcomes"] == ["forbidden", "forbidden"],
                branch["markerObserved"] is False,
                branch["thirdPartyDataObserved"] is False,
                redaction == {
                    "rawBodiesAbsent": True,
                    "headersAbsent": True,
                    "credentialsAbsent": True,
                    "cookiesAndTokensAbsent": True,
                    "emailAddressesAbsent": True,
                    "rawObjectLocatorAbsent": True,
                },
                result["reason"] == expected_reason,
            ]
        )
        return artifact if valid else None
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def replay_allowed_hosts(run: AuditRunModel) -> list[str]:
    if run.mode == "external_program":
        return [str(host).lower().rstrip(".") for host in (run.policy_receipt.get("allowedHosts") or [])]
    hostname = (urlparse(run.target).hostname or "").lower().rstrip(".")
    return [hostname] if hostname else []


def load_authenticated_replay_artifact(run: AuditRunModel) -> dict[str, Any] | None:
    artifact_path = Path(run.raw_dir) / AUTHENTICATED_REPLAY_ARTIFACT_NAME
    if not artifact_path.exists():
        return None
    try:
        artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return artifact if validate_sanitized_artifact(
        artifact,
        run_id=run.run_id,
        allowed_hosts=replay_allowed_hosts(run),
    ) else None


def write_json_once(path: Path, payload: dict[str, Any]) -> None:
    """Publish one immutable JSON receipt without ever overwriting prior evidence."""
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        descriptor = os.open(temp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temp_path, path)
        except FileExistsError as error:
            raise HTTPException(
                status_code=409,
                detail="A controlled-proof receipt already exists for this run; create a new run for new evidence.",
            ) from error
    finally:
        temp_path.unlink(missing_ok=True)


def build_controlled_proof_artifact(
    run: AuditRunModel,
    payload: ControlledProofResultRequest,
) -> dict[str, Any]:
    if run.policy_receipt.get("profileId") != INTIGRITI_PWN_PROOF_PROFILE_ID:
        raise HTTPException(status_code=400, detail="This run is not a controlled PWN proof run.")
    if payload.owner_actor == payload.peer_actor:
        raise HTTPException(status_code=400, detail="The owner and peer must be two distinct controlled accounts.")
    if payload.target_host not in (run.policy_receipt.get("allowedHosts") or []):
        raise HTTPException(status_code=400, detail="The proof host is not listed in the run's explicit host allowlist.")
    if not payload.owner_marker_observed:
        raise HTTPException(status_code=400, detail="The owner control must succeed before the denial branch can close.")
    if payload.peer_marker_observed:
        raise HTTPException(status_code=400, detail="A positive peer marker cannot be imported through the denial endpoint.")
    if not payload.sessions_isolated:
        raise HTTPException(status_code=400, detail="The owner and peer sessions must be isolated.")
    if payload.third_party_data_observed:
        raise HTTPException(status_code=400, detail="Stop: third-party data cannot be imported into this controlled proof run.")
    recorded_at = utc_now()
    result = {
        "schemaVersion": 1,
        "verdict": "INVALID",
        "classification": "NO_IDOR",
        "testedScope": "tested_draft_only",
        "submissionReady": False,
        "hypothesis": run.policy_receipt.get("proofHypothesis"),
        "recordedAt": recorded_at,
        "target": {
            "host": payload.target_host,
            "objectKind": payload.object_kind,
            "objectLocatorSha256": payload.object_locator_sha256,
        },
        "actors": {
            "owner": payload.owner_actor,
            "peer": payload.peer_actor,
            "bothResearcherControlled": True,
            "sessionsIsolated": True,
        },
        "truthfulControl": {
            "outcome": "owner_access_succeeded",
            "markerObserved": True,
        },
        "authorizationBranch": {
            "attempts": len(payload.peer_outcomes),
            "outcomes": list(payload.peer_outcomes),
            "markerObserved": False,
            "thirdPartyDataObserved": False,
        },
        "redaction": {
            "rawBodiesAbsent": True,
            "headersAbsent": True,
            "credentialsAbsent": True,
            "cookiesAndTokensAbsent": True,
            "emailAddressesAbsent": True,
            "rawObjectLocatorAbsent": True,
        },
        "reason": "No IDOR observed in the tested draft flow. Owner access succeeded; Account B was denied on both controlled replays. Hypothesis closed.",
    }
    return {
        "schema_version": 1,
        "proof_type": "controlled_external_known_id",
        "evidence_origin": "manual_redacted_import",
        "run_id": run.run_id,
        "recorded_at": recorded_at,
        "result": result,
    }


def prepare_authenticated_replay(
    run: AuditRunModel,
    owner_curl: str,
    peer_curl: str,
) -> tuple[Any, dict[str, Any]]:
    if load_engine_audit(run) is not None:
        raise HTTPException(status_code=409, detail="Authenticated replay requires a fresh run with no Web-engine evidence.")
    if load_controlled_proof_artifact(run) is not None or load_authenticated_replay_artifact(run) is not None:
        raise HTTPException(status_code=409, detail="This run already contains immutable proof evidence; create a new run.")
    if run.mode == "external_program":
        if run.policy_receipt.get("authenticatedReplayEnabled") is not True:
            raise HTTPException(status_code=400, detail="This program receipt does not authorize authenticated replay.")
        if run.policy_receipt.get("allowedReplayMethods") != ["GET"]:
            raise HTTPException(status_code=400, detail="This program receipt does not contain the required GET-only replay boundary.")
        if int(run.policy_receipt.get("requestBudget") or 0) < 4:
            raise HTTPException(status_code=400, detail="This program receipt does not reserve the four-request control budget.")
    try:
        return build_capture_plan(
            owner_curl,
            peer_curl,
            target_url=run.target,
            allowed_hosts=replay_allowed_hosts(run),
            external=run.mode == "external_program",
        )
    except ReplayValidationError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


def load_ai_analysis(run: AuditRunModel) -> dict[str, Any] | None:
    artifact_path = Path(run.raw_dir) / AI_ARTIFACT_NAME
    if not artifact_path.exists():
        return None
    try:
        return json.loads(artifact_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return parsed._replace(query="", fragment="").geturl()
    return value


SENSITIVE_TEXT_PATTERNS = [
    re.compile(r"(?i)(bearer\s+)[a-z0-9._~+/=-]+"),
    re.compile(r"(?i)((?:api[_-]?key|authorization|cookie|token|secret|password)\s*[:=]\s*)[^\s,;]+"),
]


def redact_text(value: Any, limit: int = 2000) -> str:
    text = str(value or "")
    for pattern in SENSITIVE_TEXT_PATTERNS:
        text = pattern.sub(r"\1[redacted]", text)
    return text[:limit]


def build_ai_input(run: AuditRunModel, findings: list[FindingModel]) -> dict[str, Any]:
    engine = load_engine_audit(run) or {}
    evidence = engine.get("evidence") or {}
    controlled_artifact = load_controlled_proof_artifact(run) or {}
    controlled_proof = controlled_artifact.get("result")
    replay_artifact = load_authenticated_replay_artifact(run) or {}
    authenticated_replay = replay_artifact.get("result")
    http = evidence.get("http") or {}
    headers = http.get("headers") or {}
    cookie = str(headers.get("set-cookie") or "").lower()
    policy = run.policy_receipt or {}
    request_log = []
    for request in (evidence.get("requestLog") or [])[:20]:
        request_log.append(
            {
                "method": request.get("method"),
                "url": redact_url(str(request.get("url") or "")),
                "status": request.get("status"),
                "time": request.get("time"),
            }
        )

    return {
        "run_id": run.run_id,
        "target": redact_url(run.target),
        "mode": run.mode,
        "scope_boundary": redact_text(run.scope_notes),
        "policy_receipt": {
            "platform": policy.get("platform"),
            "program": policy.get("programName"),
            "policy_url": redact_url(str(policy.get("policyUrl") or "")),
            "exact_scope_url": redact_url(str(policy.get("exactScopeUrl") or run.target)),
            "request_rate_per_second": policy.get("requestRatePerSecond"),
            "request_budget": policy.get("requestBudget"),
            "allowed_methods": policy.get("allowedMethods") or policy.get("allowedReplayMethods"),
            "prohibited_actions": policy.get("prohibitedActions"),
            "policy_text_supplied": False,
        }
        if run.mode == "external_program"
        else {"authorization_recorded": run.authorized, "target_class": run.target_type},
        "request_log": request_log,
        "response": {
            "status": http.get("status"),
            "final_url": redact_url(str(http.get("finalUrl") or "")),
            "title": redact_text(http.get("title"), 500),
            "forms": http.get("forms", 0),
            "same_origin_links_collected": len(http.get("links") or []),
            "header_names": sorted(str(name).lower() for name in headers.keys()),
            "cookie_attributes": {
                "secure": "secure" in cookie,
                "http_only": "httponly" in cookie,
                "same_site_lax": "samesite=lax" in cookie,
                "same_site_strict": "samesite=strict" in cookie,
                "same_site_none": "samesite=none" in cookie,
            }
            if cookie
            else None,
        },
        "observations": [
            {
                "severity": finding.severity,
                "title": redact_text(finding.title, 500),
                "location": redact_url(finding.location),
                "hypothesis": redact_text(finding.hypothesis),
                "confidence": finding.confidence,
                "status": finding.status,
                "evidence": [redact_text(item, 1000) for item in (finding.evidence.get("observations") or [])[:20]],
            }
            for finding in findings[:30]
        ],
        "controlled_proof": controlled_proof,
        "controlled_proof_supplied": bool(controlled_proof),
        "authenticated_replay": authenticated_replay,
        "authenticated_replay_supplied": bool(authenticated_replay),
        "deterministic_proof_supplied": bool(
            authenticated_replay and authenticated_replay.get("verdict") == "VERIFIED"
        ),
    }


def ai_prompt(ai_input: dict[str, Any]) -> str:
    return """You are the bounded reasoning stage of Bug Bunny, an authorized Web security evidence tool.
Analyze only the JSON evidence below. Do not use tools, inspect files, make network requests, or infer facts not explicitly supplied.
Separate facts from hypotheses. Never call a missing header, exposed route, or scanner signal a vulnerability without victim-centered reproducible impact.
The policy URL is only a receipt reference; it is not policy text. Do not claim that this program, or programs generally, include or exclude a finding class unless exact policy text is supplied.
A zero count means only that the collector stored zero items. It does not prove that no such item exists on the page or elsewhere.
VERIFIED is forbidden unless deterministic_proof_supplied is true and the supplied proof establishes the attacker, victim, control, exploit branch, and incremental harm.
Return exactly one valid JSON object with these top-level keys:
verdict, summary, observed_facts, unsupported_claims, likely_dismissal, attacker, victim, asset_or_authority_at_risk, safest_next_manual_step, proof_requirements, submission_ready.
verdict must be one of OBSERVATION, NEEDS_MANUAL_VALIDATION, VERIFIED, OVERSTATED, INVALID. submission_ready must be boolean.
likely_dismissal, attacker, victim, and asset_or_authority_at_risk must always be strings; use "None identified" rather than null. The two claims fields and proof_requirements must be arrays of strings.
The safest next step must remain within the recorded policy and must not create traffic unless separately human-approved.
A controlled_proof is a manual redacted receipt. It may close only its explicitly tested hypothesis as INVALID; it can never establish VERIFIED or submission-ready impact.
An authenticated_replay is a server-validated, secret-free deterministic receipt. Treat its tested branch verdict as authoritative, but never mark a live-program result submission-ready without separate human scope, impact, and duplicate review.

EVIDENCE_JSON:
""" + json.dumps(ai_input, separators=(",", ":"), sort_keys=True)


def parse_opencode_events(stdout: str) -> tuple[str, dict[str, Any]]:
    text_parts: list[str] = []
    metadata: dict[str, Any] = {}
    for line in stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("sessionID"):
            metadata["session_id"] = event["sessionID"]
        if event.get("type") == "text":
            text_parts.append(str((event.get("part") or {}).get("text") or ""))
        if event.get("type") == "step_finish":
            part = event.get("part") or {}
            metadata["cost"] = part.get("cost")
            metadata["tokens"] = part.get("tokens")
    return "".join(text_parts).strip(), metadata


def parse_analysis_json(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        payload = json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end <= start:
            raise ValueError("OpenCode did not return a JSON object.")
        payload = json.loads(candidate[start : end + 1])
    analysis = AIAnalysisModel.model_validate(payload).model_dump()
    if isinstance(analysis["likely_dismissal"], bool):
        analysis["likely_dismissal"] = (
            "Likely dismissal: no victim-centered impact is demonstrated."
            if analysis["likely_dismissal"]
            else "No dismissal assessment was returned."
        )
    for identity_field in ("attacker", "victim", "asset_or_authority_at_risk"):
        if not analysis[identity_field]:
            analysis[identity_field] = "None identified."
    return analysis


def opencode_executable() -> str | None:
    return shutil.which("opencode")


def opencode_status() -> dict[str, Any]:
    executable = opencode_executable()
    if not executable:
        return {"ready": False, "provider": "opencode-go", "model": AI_MODEL, "detail": "OpenCode CLI is not installed."}
    try:
        models = subprocess.run([executable, "models"], cwd=ROOT_DIR, capture_output=True, text=True, timeout=20, check=False)
        auth = subprocess.run([executable, "auth", "list"], cwd=ROOT_DIR, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {"ready": False, "provider": "opencode-go", "model": AI_MODEL, "detail": "OpenCode model catalog is unavailable."}
    provider_name = "OpenCode Go" if AI_MODEL.startswith("opencode-go/") else "OpenCode Zen"
    model_available = models.returncode == 0 and AI_MODEL in models.stdout.splitlines()
    credential_available = auth.returncode == 0 and provider_name in auth.stdout
    ready = model_available and credential_available
    return {
        "ready": ready,
        "provider": AI_MODEL.split("/", 1)[0],
        "model": AI_MODEL,
        "agent": AI_AGENT,
        "detail": "Credential and model catalog are available." if ready else "Configured model or provider credential is unavailable.",
    }


def apply_analysis_server_gate(
    run: AuditRunModel,
    ai_input: dict[str, Any],
    analysis: dict[str, Any],
    controlled_artifact: dict[str, Any] | None,
    authenticated_replay_artifact: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    model_analysis = dict(analysis)
    gated_analysis = dict(analysis)
    if controlled_artifact is not None:
        gated_analysis["verdict"] = "INVALID"
        gated_analysis["submission_ready"] = False
    elif authenticated_replay_artifact is not None:
        replay_verdict = authenticated_replay_artifact["result"]["verdict"]
        gated_analysis["verdict"] = {
            "VERIFIED": "VERIFIED",
            "INVALID": "INVALID",
            "INCONCLUSIVE": "NEEDS_MANUAL_VALIDATION",
        }[replay_verdict]
        gated_analysis["submission_ready"] = False
    elif run.mode == "external_program" or not ai_input["deterministic_proof_supplied"]:
        if gated_analysis["verdict"] == "VERIFIED":
            gated_analysis["verdict"] = "OVERSTATED"
        gated_analysis["submission_ready"] = False
    return gated_analysis, model_analysis


def run_opencode_analysis(run: AuditRunModel, findings: list[FindingModel]) -> dict[str, Any]:
    executable = opencode_executable()
    if not executable:
        raise HTTPException(status_code=503, detail="OpenCode CLI is not installed or not on PATH.")
    controlled_artifact = load_controlled_proof_artifact(run)
    authenticated_replay_artifact = load_authenticated_replay_artifact(run)
    artifact_path = Path(run.raw_dir) / AI_ARTIFACT_NAME
    if (controlled_artifact is not None or authenticated_replay_artifact is not None) and artifact_path.exists():
        raise HTTPException(
            status_code=409,
            detail="Kimi analysis is already preserved for this controlled-proof run; create a new run for new evidence.",
        )
    ai_input = build_ai_input(run, findings)
    prompt = ai_prompt(ai_input)
    environment = os.environ.copy()
    for ambient_provider_key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY"):
        environment.pop(ambient_provider_key, None)
    started = time.monotonic()
    try:
        completed = subprocess.run(
            [
                executable,
                "run",
                "--pure",
                "--format",
                "json",
                "--model",
                AI_MODEL,
                "--agent",
                AI_AGENT,
                "--dir",
                str(ROOT_DIR),
                "--title",
                f"Bug Bunny evidence triage {run.run_id}",
                prompt,
            ],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=AI_TIMEOUT_SECONDS,
            env=environment,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise HTTPException(status_code=504, detail=f"Kimi analysis exceeded its {AI_TIMEOUT_SECONDS}-second limit.") from error
    latency_ms = round((time.monotonic() - started) * 1000)
    response_text, metadata = parse_opencode_events(completed.stdout)
    if completed.returncode != 0:
        safe_error = "OpenCode analysis failed. Check the configured provider, authentication, and balance."
        if "Insufficient balance" in completed.stdout or "Insufficient balance" in completed.stderr:
            safe_error = "The configured OpenCode provider has insufficient balance."
        raise HTTPException(status_code=502, detail=safe_error)
    try:
        analysis = parse_analysis_json(response_text)
    except (json.JSONDecodeError, ValueError) as error:
        raise HTTPException(status_code=502, detail=f"Kimi returned an invalid structured analysis: {error}") from error

    analysis, model_analysis = apply_analysis_server_gate(
        run,
        ai_input,
        analysis,
        controlled_artifact,
        authenticated_replay_artifact,
    )

    artifact = {
        "schema_version": 1,
        "provider": metadata.get("provider_id") or AI_MODEL.split("/", 1)[0],
        "model": AI_MODEL.split("/", 1)[-1],
        "model_ref": AI_MODEL,
        "agent": AI_AGENT,
        "session_id": metadata.get("session_id"),
        "cost_usd": metadata.get("cost"),
        "tokens": metadata.get("tokens"),
        "latency_ms": latency_ms,
        "analyzed_at": utc_now(),
        "input_sha256": hashlib.sha256(json.dumps(ai_input, sort_keys=True).encode("utf-8")).hexdigest(),
        "redacted_input": ai_input,
        "model_analysis": model_analysis,
        "analysis": analysis,
        "server_gate": (
            "The validated controlled receipt is authoritative: the tested branch is INVALID and not submission ready."
            if controlled_artifact is not None
            else "The validated authenticated-replay receipt controls the tested branch verdict; live results still require human scope, impact, and duplicate review."
            if authenticated_replay_artifact is not None
            else "Model output is advisory. VERIFIED requires a separate deterministic proof artifact."
        ),
    }
    if controlled_artifact is not None or authenticated_replay_artifact is not None:
        write_json_once(artifact_path, artifact)
    else:
        artifact_path.write_text(json.dumps(artifact, indent=2), encoding="utf-8")
    return artifact


def response_for_run(run: AuditRunModel, findings: list[FindingModel], markdown: str = "") -> dict[str, Any]:
    engine_audit = load_engine_audit(run)
    controlled_proof_result = (load_controlled_proof_artifact(run) or {}).get("result")
    authenticated_replay_result = (load_authenticated_replay_artifact(run) or {}).get("result")
    return {
        "audit": run.model_dump(),
        "findings": [finding.model_dump() for finding in findings],
        "markdown": markdown,
        "engine_audit": engine_audit,
        "ai_analysis": load_ai_analysis(run),
        "controlled_proof_result": controlled_proof_result,
        "authenticated_replay_result": authenticated_replay_result,
        "authenticated_replay_receipt_sha256": (
            (load_authenticated_replay_artifact(run) or {}).get("integrity_sha256")
        ),
    }


@app.get("/api/health")
def health() -> dict[str, Any]:
    return {"ok": True, "service": "bug-bunny-fastapi", "db_path": str(DB_PATH)}


@app.get("/api/ai/status")
def ai_status() -> dict[str, Any]:
    return opencode_status()


@app.post("/api/proofs/idor/run")
def run_idor_verified_proof() -> dict[str, Any]:
    artifact_path = ARTIFACTS_DIR / "idor-before.json"
    proof = write_proof(artifact_path)
    if proof["verdict"] != "confirmed":
        raise HTTPException(status_code=500, detail="IDOR proof assertions did not hold.")
    return {"proof": proof, "artifact_path": str(artifact_path)}


@app.post("/api/audits/create")
def create_audit(payload: AuditCreateRequest) -> dict[str, Any]:
    target = payload.target.strip()
    scope_notes = payload.scope_notes.strip()
    if not payload.authorized:
        raise HTTPException(status_code=400, detail="Authorization checkbox must be true.")
    if not target:
        raise HTTPException(status_code=400, detail="Target URL or repo path is required.")
    if not scope_notes:
        raise HTTPException(status_code=400, detail="Scope notes are required.")

    target_type = classify_target(target)
    if target_type != "url":
        raise HTTPException(status_code=400, detail="Bug Bunny currently accepts HTTP(S) target URLs only.")
    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=400, detail="Target URL must include http:// or https://.")

    policy_receipt = build_external_policy_receipt(payload, target) if payload.mode == "external_program" else {}

    run_id = str(uuid.uuid4())
    run_dir = RUNS_DIR / run_id
    raw_dir = run_dir / "raw"
    reports_dir = run_dir / "reports"
    raw_dir.mkdir(parents=True, exist_ok=False)
    reports_dir.mkdir(parents=True, exist_ok=False)
    now = utc_now()

    initial_status = (
        "proof_scope_recorded"
        if policy_receipt.get("authenticatedReplayEnabled") is True
        else "created"
    )

    with connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_runs (
                run_id, target, target_type, scope_notes, authorized, mode, policy_receipt_json, status,
                run_dir, raw_dir, reports_dir, report_path, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                target,
                target_type,
                scope_notes,
                1,
                payload.mode,
                json.dumps(policy_receipt),
                initial_status,
                str(run_dir),
                str(raw_dir),
                str(reports_dir),
                None,
                now,
                now,
            ),
        )

    run = get_run_or_404(run_id)
    return {"audit": run.model_dump(), "findings": []}


@app.get("/api/audits")
def list_audits() -> dict[str, Any]:
    with connect() as conn:
        rows = conn.execute("SELECT * FROM audit_runs ORDER BY created_at DESC").fetchall()
    return {"audits": [row_to_run(row).model_dump() for row in rows]}


@app.get("/api/audits/{run_id}")
def get_audit(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    markdown = ""
    if run.report_path and Path(run.report_path).exists():
        markdown = Path(run.report_path).read_text(encoding="utf-8")
    return response_for_run(run, findings, markdown)


@app.post("/api/audits/{run_id}/run-web-audit")
def run_web_audit(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    if run.target_type != "url":
        raise HTTPException(status_code=400, detail="The live Web engine currently accepts HTTP(S) targets only.")
    if run.policy_receipt.get("authenticatedReplayEnabled") is True:
        raise HTTPException(
            status_code=400,
            detail="Authenticated-replay runs never enter the general Web engine. Preview two controlled captures in Proof Lab, then run the bounded secret-free replay.",
        )

    bounded_external = (
        run.mode == "external_program"
        and run.policy_receipt.get("profileId") == INTIGRITI_PWN_PROFILE_ID
    )
    engine_mode = (
        "external-program-bounded"
        if bounded_external
        else "external-program-passive" if run.mode == "external_program" else "authorized-safe-web"
    )
    evidence_mode = (
        "external-program-bounded"
        if bounded_external
        else "external-program-passive" if run.mode == "external_program" else "authorized-read-only"
    )

    update_run_status(run_id, "scanning")
    started = web_engine_request(
        "/api/audits",
        {
            "target": run.target,
            "scopeRules": run.scope_notes,
            "authorized": run.authorized,
            "mode": engine_mode,
            "programProfile": run.policy_receipt if run.mode == "external_program" else None,
        },
    )
    engine_id = started["audit"]["id"]
    deadline = time.monotonic() + WEB_AUDIT_TIMEOUT_SECONDS
    engine_audit = started["audit"]

    while engine_audit.get("status") not in {"complete", "failed"}:
        if time.monotonic() >= deadline:
            update_run_status(run_id, "failed")
            raise HTTPException(status_code=504, detail="Safe Web audit exceeded its 90-second limit.")
        time.sleep(0.2)
        engine_audit = web_engine_request(f"/api/audits/{engine_id}")["audit"]

    if engine_audit.get("status") == "failed":
        update_run_status(run_id, "failed")
        raise HTTPException(status_code=502, detail=engine_audit.get("error") or "Safe Web audit failed.")

    raw_path = Path(run.raw_dir) / "web_audit.json"
    raw_path.write_text(json.dumps(engine_audit, indent=2), encoding="utf-8")

    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        now = utc_now()
        for item in engine_audit.get("findings", []):
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, severity, title, location, hypothesis,
                    confidence, evidence_json, remediation, poc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.get("id") or str(uuid.uuid4()),
                    run_id,
                    item.get("severity", "Info"),
                    item.get("title", "Untitled finding"),
                    item.get("path", run.target),
                    item.get("hypothesis", "Review the captured evidence."),
                    int(item.get("confidence", 0)),
                    json.dumps({
                        "mode": evidence_mode,
                        "observations": item.get("evidence", []),
                        "validation": item.get("validation"),
                        "policy_receipt": run.policy_receipt if run.mode == "external_program" else None,
                    }),
                    item.get("remediation", "Review and remediate the observed condition."),
                    item.get("poc", ""),
                    item.get("status", "Observed"),
                    now,
                ),
            )

    update_run_status(run_id, "web_audit_complete")
    run = get_run_or_404(run_id)
    return response_for_run(run, get_findings_for_run(run_id))


@app.post("/api/audits/{run_id}/authenticated-replay/preview")
def preview_authenticated_replay(
    run_id: str,
    payload: AuthenticatedReplayPreviewRequest,
    x_bug_bunny_intent: str | None = Header(default=None),
) -> dict[str, Any]:
    if x_bug_bunny_intent != AUTHENTICATED_REPLAY_INTENT:
        raise HTTPException(status_code=400, detail="Authenticated replay requires the explicit intent header.")
    run = get_run_or_404(run_id)
    _plan, preview = prepare_authenticated_replay(
        run,
        payload.owner_curl.get_secret_value(),
        payload.peer_curl.get_secret_value(),
    )
    return {"preview": preview}


@app.post("/api/audits/{run_id}/authenticated-replay/execute")
def run_authenticated_replay(
    run_id: str,
    payload: AuthenticatedReplayExecuteRequest,
    x_bug_bunny_intent: str | None = Header(default=None),
) -> dict[str, Any]:
    if x_bug_bunny_intent != AUTHENTICATED_REPLAY_INTENT:
        raise HTTPException(status_code=400, detail="Authenticated replay requires the explicit intent header.")
    run = get_run_or_404(run_id)
    plan, preview = prepare_authenticated_replay(
        run,
        payload.owner_curl.get_secret_value(),
        payload.peer_curl.get_secret_value(),
    )
    if not hmac.compare_digest(preview["captureSha256"], payload.preview_sha256):
        raise HTTPException(status_code=409, detail="The captures changed after redaction preview. Preview them again.")

    previous_status = run.status
    with connect() as conn:
        cursor = conn.execute(
            """
            UPDATE audit_runs
            SET status = ?, updated_at = ?
            WHERE run_id = ? AND status IN ('created', 'proof_scope_recorded')
            """,
            ("authenticated_replay_running", utc_now(), run_id),
        )
        if cursor.rowcount != 1:
            raise HTTPException(status_code=409, detail="This run is not available for a new authenticated replay.")

    try:
        execution = execute_capture_plan(
            plan,
            owner_marker=payload.owner_marker.get_secret_value(),
            peer_marker=payload.peer_marker.get_secret_value(),
            requests_per_second=int(run.policy_receipt.get("requestRatePerSecond") or 1),
        )
    except ReplayHostBusyError as error:
        with connect() as conn:
            conn.execute(
                "UPDATE audit_runs SET status = ?, updated_at = ? WHERE run_id = ? AND status = ?",
                (previous_status, utc_now(), run_id, "authenticated_replay_running"),
            )
        raise HTTPException(status_code=409, detail=str(error)) from error
    except ReplayValidationError as error:
        with connect() as conn:
            conn.execute(
                "UPDATE audit_runs SET status = ?, updated_at = ? WHERE run_id = ? AND status = ?",
                (previous_status, utc_now(), run_id, "authenticated_replay_running"),
            )
        raise HTTPException(status_code=400, detail=str(error)) from error

    recorded_at = utc_now()
    artifact = build_sanitized_artifact(
        run_id=run.run_id,
        plan=plan,
        execution=execution,
        recorded_at=recorded_at,
        object_kind=payload.object_kind.strip(),
    )
    artifact_path = Path(run.raw_dir) / AUTHENTICATED_REPLAY_ARTIFACT_NAME
    try:
        write_json_once(artifact_path, artifact)
    except Exception:
        update_run_status(run_id, "authenticated_replay_failed")
        raise

    status = {
        "VERIFIED": "authenticated_replay_verified",
        "INVALID": "authenticated_replay_closed_invalid",
        "INCONCLUSIVE": "authenticated_replay_inconclusive",
    }[execution["verdict"]]
    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        if execution["verdict"] == "VERIFIED":
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, severity, title, location, hypothesis,
                    confidence, evidence_json, remediation, poc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    run_id,
                    "Unrated",
                    "Controlled peer retrieved owner-only marker",
                    f"{plan.endpoint_shape['scheme']}://{plan.endpoint_shape['hostname']}/[redacted-controlled-object]",
                    run.policy_receipt.get("proofHypothesis") or "A distinct controlled account can read the owner's known object.",
                    100,
                    json.dumps({
                        "mode": "authenticated-capture-replay",
                        "verdict": execution["verdict"],
                        "classification": execution["classification"],
                        "capture_sha256": plan.capture_sha256,
                        "request_budget_used": execution["requestBudgetUsed"],
                        "attempts": execution["attempts"],
                        "redaction": artifact["result"]["redaction"],
                    }),
                    "Enforce object ownership or an explicit per-object authorization policy on the server.",
                    "Re-run only in a new authorized run with two controlled accounts; the raw replay command is intentionally not retained.",
                    "verified-replay",
                    recorded_at,
                ),
            )
    update_run_status(run_id, status)
    run = get_run_or_404(run_id)
    return response_for_run(run, get_findings_for_run(run_id))


@app.post("/api/audits/{run_id}/record-controlled-proof-denial")
def record_controlled_proof_denial(
    run_id: str,
    payload: ControlledProofResultRequest,
) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    artifact = build_controlled_proof_artifact(run, payload)
    raw_path = Path(run.raw_dir) / CONTROLLED_PROOF_ARTIFACT_NAME
    write_json_once(raw_path, artifact)
    update_run_status(run_id, "proof_closed_invalid")
    run = get_run_or_404(run_id)
    return response_for_run(run, get_findings_for_run(run_id))


def ensure_mock_scan_allowed(run: AuditRunModel) -> None:
    if (
        run.policy_receipt.get("authenticatedReplayEnabled") is True
        or run.policy_receipt.get("profileId") == INTIGRITI_PWN_PROOF_PROFILE_ID
        or load_controlled_proof_artifact(run) is not None
        or load_authenticated_replay_artifact(run) is not None
    ):
        raise HTTPException(
            status_code=400,
            detail="Mock findings cannot be mixed into a controlled-proof run.",
        )


@app.post("/api/audits/{run_id}/run-mock-scan")
def run_mock_scan(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    ensure_mock_scan_allowed(run)
    update_run_status(run_id, "scanning")
    run = get_run_or_404(run_id)
    payload = mock_scan_payload(run)
    raw_path = Path(run.raw_dir) / "mock_scan.json"
    raw_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    with connect() as conn:
        conn.execute("DELETE FROM findings WHERE run_id = ?", (run_id,))
        now = utc_now()
        for item in payload["findings"]:
            conn.execute(
                """
                INSERT INTO findings (
                    finding_id, run_id, severity, title, location, hypothesis,
                    confidence, evidence_json, remediation, poc, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    run_id,
                    item["severity"],
                    item["title"],
                    item["location"],
                    item["hypothesis"],
                    item["confidence"],
                    json.dumps(item["evidence"]),
                    item["remediation"],
                    item["poc"],
                    "mock-verified",
                    now,
                ),
            )

    update_run_status(run_id, "mock_scan_complete")
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    return {
        "audit": run.model_dump(),
        "raw_path": str(raw_path),
        "findings": [finding.model_dump() for finding in findings],
    }


@app.post("/api/audits/{run_id}/analyze")
def analyze_audit(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    if (
        load_engine_audit(run) is None
        and load_controlled_proof_artifact(run) is None
        and load_authenticated_replay_artifact(run) is None
    ):
        raise HTTPException(status_code=400, detail="Collect Web evidence before running Kimi analysis.")
    run_opencode_analysis(run, findings)
    return response_for_run(get_run_or_404(run_id), findings)


@app.get("/api/audits/{run_id}/findings")
def list_findings(run_id: str) -> dict[str, Any]:
    get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    return {"findings": [finding.model_dump() for finding in findings]}


@app.post("/api/audits/{run_id}/generate-report")
def generate_report(run_id: str) -> dict[str, Any]:
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    authenticated_replay_artifact = load_authenticated_replay_artifact(run)
    if not findings and run.mode != "external_program" and authenticated_replay_artifact is None:
        raise HTTPException(status_code=400, detail="Run a safe Web audit before generating a report.")
    controlled_profile = (
        run.mode == "external_program"
        and (
            run.policy_receipt.get("profileId") == INTIGRITI_PWN_PROOF_PROFILE_ID
            or run.policy_receipt.get("authenticatedReplayEnabled") is True
        )
    )
    controlled_artifact = load_controlled_proof_artifact(run) if controlled_profile else None
    if controlled_profile and controlled_artifact is None and authenticated_replay_artifact is None:
        raise HTTPException(
            status_code=400,
            detail="A valid controlled-proof receipt is required before generating this ledger.",
        )
    ai_artifact = load_ai_analysis(run)
    if ai_artifact is None:
        raise HTTPException(status_code=400, detail="Run Kimi evidence analysis before generating the report.")
    analysis = ai_artifact["analysis"]

    report_path = Path(run.reports_dir) / ("observation-ledger.md" if run.mode == "external_program" else "report.md")
    engine_audit = load_engine_audit(run)
    bounded_external = (
        run.mode == "external_program"
        and run.policy_receipt.get("profileId") == INTIGRITI_PWN_PROFILE_ID
    )
    controlled_external = controlled_profile and (
        controlled_artifact is not None or authenticated_replay_artifact is not None
    )
    authenticated_replay = authenticated_replay_artifact["result"] if authenticated_replay_artifact else None
    scanner_mode = (
        "authenticated-capture-replay" if authenticated_replay else "manual-controlled-proof" if controlled_external else "external-program-bounded" if bounded_external else "external-program-passive"
        if run.mode == "external_program"
        else "authenticated-capture-replay" if authenticated_replay else "authorized-read-only" if engine_audit else "mock"
    )
    lines = [
        "# Bug Bunny External Program Observation Ledger" if run.mode == "external_program" else "# Bug Bunny.ai Local Audit Report",
        "",
        f"- Run ID: `{run.run_id}`",
        f"- Target: `{run.target}`",
        f"- Target type: `{run.target_type}`",
        f"- Scanner mode: `{scanner_mode}`",
        f"- Generated: `{utc_now()}`",
        "",
        "## Scope Notes",
        run.scope_notes,
        "",
        "## Observations — Not Submission Ready" if run.mode == "external_program" else "## Findings",
    ]
    if run.mode == "external_program":
        lines.extend(
            [
                "",
                "## Policy Receipt",
                f"- Platform: `{run.policy_receipt.get('platform', 'n/a')}`",
                f"- Program: `{run.policy_receipt.get('programName', 'n/a')}`",
                f"- Policy URL: `{run.policy_receipt.get('policyUrl', 'n/a')}`",
                f"- Exact in-scope URL: `{run.policy_receipt.get('exactScopeUrl', run.target)}`",
                f"- HTTP request ceiling: `{run.policy_receipt.get('requestRatePerSecond', 1)} request(s)/second`; "
                f"`{run.policy_receipt.get('requestBudget', 1)}` total request(s).",
                f"- Allowed methods: `{', '.join(run.policy_receipt.get('allowedMethods') or run.policy_receipt.get('allowedReplayMethods') or ['GET'])}`.",
                f"- Redirect policy: `{run.policy_receipt.get('redirectPolicy', 'do-not-follow')}`.",
                f"- Discovery policy: `{run.policy_receipt.get('discoveryPolicy', 'disabled')}`.",
                "- Deterministic proof and human duplicate/impact validation remain required.",
            ]
        )
    if authenticated_replay:
        lines.extend(
            [
                "",
                "## Authenticated Replay Control Matrix",
                f"- Receipt SHA-256: `{authenticated_replay_artifact.get('integrity_sha256')}`",
                f"- Capture SHA-256: `{authenticated_replay.get('captureSha256')}`",
                f"- Verdict: `{authenticated_replay.get('verdict')} · {authenticated_replay.get('classification')}`",
                f"- Request budget: `{authenticated_replay.get('requestBudgetUsed')} / {authenticated_replay.get('requestBudgetMax')}`",
                "- Network boundary: DNS pinned; fresh connection per attempt; redirects never followed.",
                "- Secret boundary: no raw cURL, URL, object locator, header value, credential, marker, or body was persisted.",
                "",
                "| # | Branch | HTTP | Marker observed | Outcome | Response SHA-256 |",
                "|---:|---|---:|:---:|---|---|",
                *[
                    f"| {attempt.get('sequence')} | `{attempt.get('branch')}` | "
                    f"`{attempt.get('status') if attempt.get('status') is not None else 'n/a'}` | "
                    f"`{str(bool(attempt.get('markerObserved'))).lower()}` | `{attempt.get('outcome')}` | "
                    f"`{attempt.get('responseSha256') or 'not available'}` |"
                    for attempt in authenticated_replay.get("attempts", [])
                ],
            ]
        )
    lines.extend(
        [
            "",
            "## Kimi Evidence Triage",
            f"- Provider: `{ai_artifact.get('provider', 'n/a')}`",
            f"- Model: `{ai_artifact.get('model_ref', 'n/a')}`",
            f"- OpenCode session: `{ai_artifact.get('session_id') or 'not recorded'}`",
            f"- Verdict: `{analysis.get('verdict', 'n/a')}`",
            f"- Submission ready: `{str(bool(analysis.get('submission_ready'))).lower()}`",
            f"- Input SHA-256: `{ai_artifact.get('input_sha256', 'n/a')}`",
            "",
            analysis.get("summary", "No summary returned."),
            "",
            "### Unsupported Claims",
            *[f"- {item}" for item in analysis.get("unsupported_claims", [])],
            "",
            "### Proof Requirements",
            *[f"- {item}" for item in analysis.get("proof_requirements", [])],
            "",
            f"**Likely dismissal:** {analysis.get('likely_dismissal', 'Not assessed.')} ",
            "",
            f"**Safest next manual step:** {analysis.get('safest_next_manual_step', 'Stop and review scope.')} ",
        ]
    )
    for finding in findings:
        lines.extend(
            [
                "",
                f"### {finding.severity}: {finding.title}",
                f"- Location: `{finding.location}`",
                f"- Confidence: {finding.confidence}%",
                f"- Status: {finding.status}",
                f"- Hypothesis: {finding.hypothesis}",
                f"- Evidence: `{json.dumps(finding.evidence)}`",
                f"- PoC: `{finding.poc}`",
                f"- Remediation: {finding.remediation}",
            ]
        )
    lines.extend(
        [
            "",
            "## Submission Gate" if run.mode == "external_program" else "## Notes",
            (
                "The bounded A/B controls verified cross-account exposure of Account A's unique marker. This is deterministic evidence for the tested object flow, not automatic permission to submit. "
                "A human must still confirm current program scope, impact, duplicate status, and disclosure requirements."
                if authenticated_replay and authenticated_replay.get("verdict") == "VERIFIED"
                else "The bounded A/B controls held twice for the tested object flow. The hypothesis is invalidated for this exact flow and must not be submitted."
                if authenticated_replay and authenticated_replay.get("verdict") == "INVALID"
                else "The authenticated replay was inconclusive because a control or network boundary failed. Do not report it; create a fresh scoped run only after resolving the control."
                if authenticated_replay
                else
                "This ledger is not a vulnerability report. The controlled owner path succeeded and the distinct controlled peer was denied twice. "
                "The tested IDOR hypothesis is invalidated and must not be submitted."
                if controlled_external
                else "This ledger is not a vulnerability report. It records a single passive response and must not be submitted. "
                "Manually establish current scope, impact, duplicate status, and a victim-centered proof before creating a report."
                if run.mode == "external_program"
                else "This report was generated from bounded live DNS and HTTP observations. "
                "Only GET and HEAD requests were used; no active exploitation was performed."
                if engine_audit
                else "This report was generated in mock scanner mode. No active exploitation was performed."
            ),
        ]
    )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    report_status = "authenticated_replay_report_generated" if authenticated_replay else "proof_closed_invalid" if controlled_external else "report_generated"
    update_run_status(run_id, report_status, str(report_path))
    run = get_run_or_404(run_id)
    findings = get_findings_for_run(run_id)
    response = response_for_run(run, findings, report_path.read_text(encoding="utf-8"))
    response["report_path"] = str(report_path)
    return response


@app.get("/api/audits/{run_id}/report", response_class=PlainTextResponse)
def get_report(run_id: str) -> str:
    run = get_run_or_404(run_id)
    if not run.report_path:
        raise HTTPException(status_code=404, detail="Report not generated yet.")
    report_path = Path(run.report_path)
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report file is missing.")
    return report_path.read_text(encoding="utf-8")
