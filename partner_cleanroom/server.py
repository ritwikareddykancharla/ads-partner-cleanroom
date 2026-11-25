"""Local HTTP Server & AWS CloudFront `/api/*` Lambda Handler for PartnerCleanRoom."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from .cleanroom_sql import CleanRoomSQLGateway, K_ANONYMITY_FLOOR
from .model_drift import PartnerModelDriftGuard
from .partner_diagnostics import PartnerDiagnosticsAdvisor
from .vending_ledger import PartnerVendingLedger

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCH_FILE = ROOT_DIR / "benchmarks" / "latest_results.json"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


class PartnerCleanRoomControlPlane:
    """Unified stateful runtime wiring Clean-Room SQL, Model Drift Guard, Partner Diagnostics & Audit Ledger."""

    def __init__(self, db_dir: Path | None = None) -> None:
        base = db_dir or Path("/tmp/partner-cleanroom")
        base.mkdir(parents=True, exist_ok=True)
        self.ledger = PartnerVendingLedger(db_path=base / "partner_vending_audit.db")
        self.cleanroom = CleanRoomSQLGateway(
            ledger=self.ledger,
            db_path=base / "partner_vending_cleanroom.db",
            k_floor=K_ANONYMITY_FLOOR,
        )
        self.drift_guard = PartnerModelDriftGuard(ledger=self.ledger)
        self.diagnostics = PartnerDiagnosticsAdvisor(cleanroom=self.cleanroom, ledger=self.ledger)

    def load_benchmarks(self) -> Dict[str, Any]:
        if BENCH_FILE.is_file():
            try:
                return json.loads(BENCH_FILE.read_text(encoding="utf-8"))
            except Exception:
                return {}
        return {}

    def get_state_snapshot(self) -> Dict[str, Any]:
        chain = self.ledger.verify_chain_integrity()
        return {
            "service": "ads-partner-cleanroom",
            "k_anonymity_floor": self.cleanroom.k_floor,
            "grants": self.cleanroom.list_grants(),
            "models": self.drift_guard.list_models(),
            "diagnostic_presets": self.diagnostics.list_presets(),
            "audit_chain": chain,
            "audit_events": self.ledger.list_recent_events(limit=25),
            "privacy_budgets": self.ledger.get_privacy_budget_summary(),
            "benchmarks": self.load_benchmarks(),
        }

    def reset_all(self) -> Dict[str, Any]:
        self.ledger.reset()
        grants = self.cleanroom.reset_grants()
        self.drift_guard.reset()
        return {
            "status": "reset_complete",
            "grants_count": len(grants),
            "models_count": len(self.drift_guard.list_models()),
            "audit_chain": self.ledger.verify_chain_integrity(),
        }


CONTROL_PLANE = PartnerCleanRoomControlPlane()


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Pure HTTP router shared by local dev server and AWS Lambda `/api/*` origin."""
    try:
        if method == "GET" and path == "/api/health":
            chain = CONTROL_PLANE.ledger.verify_chain_integrity()
            return 200, {
                "status": "ok",
                "service": "ads-partner-cleanroom",
                "delivery": os.environ.get("PARTNER_CLEANROOM_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-west-2",
                "bedrock_model": os.environ.get("PARTNER_CLEANROOM_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
                "python_version": platform.python_version(),
                "k_anonymity_floor": CONTROL_PLANE.cleanroom.k_floor,
                "grants_active": sum(1 for g in CONTROL_PLANE.cleanroom.list_grants() if g["status"] == "ACTIVE"),
                "models_registered": len(CONTROL_PLANE.drift_guard.list_models()),
                "sqlite_audit_chain_valid": chain["valid"],
                "sqlite_audit_rows": chain["checked_rows"],
                "request_id": request_id,
            }

        if method == "GET" and path == "/api/state":
            snap = CONTROL_PLANE.get_state_snapshot()
            snap["request_id"] = request_id
            return 200, snap

        if method == "GET" and path == "/api/benchmarks":
            bench = CONTROL_PLANE.load_benchmarks()
            return 200, bench if bench else {"status": "empty", "request_id": request_id}

        if method == "POST" and path == "/api/cleanroom/query":
            # Support optional delegation grant toggle in the same cleanroom control endpoint or direct query
            grant_action = str(body.get("grant_action") or "").strip().upper()
            agency_id = str(body.get("agency_id") or "agency-northstar-media").strip()
            advertiser_id = str(body.get("advertiser_id") or "adv-summit-gear").strip()
            if grant_action in ("ACTIVE", "REVOKED"):
                res = CONTROL_PLANE.cleanroom.update_grant_status(
                    agency_id=agency_id,
                    advertiser_id=advertiser_id,
                    new_status=grant_action,
                )
                res["request_id"] = request_id
                return 200, res

            sql = str(body.get("sql") or "").strip()
            if not sql:
                return 400, {"error": "sql is required"}
            out = CONTROL_PLANE.cleanroom.execute_cleanroom_query(
                agency_id=agency_id,
                advertiser_id=advertiser_id,
                sql=sql,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/cleanroom/grants":
            agency_id = str(body.get("agency_id") or "agency-northstar-media").strip()
            advertiser_id = str(body.get("advertiser_id") or "adv-summit-gear").strip()
            status = str(body.get("status") or "REVOKED").strip().upper()
            out = CONTROL_PLANE.cleanroom.update_grant_status(
                agency_id=agency_id,
                advertiser_id=advertiser_id,
                new_status=status,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/models/evaluate":
            model_id = str(body.get("model_id") or "mdl-kestrel-promo-v3").strip()
            scenario = body.get("scenario")
            sample_size = int(body.get("sample_size") or 5000)
            out = CONTROL_PLANE.drift_guard.evaluate_partner_model(
                model_id=model_id,
                scenario=str(scenario).strip() if scenario else None,
                sample_size=sample_size,
            )
            out["request_id"] = request_id
            return 200, out

        if method == "POST" and path == "/api/partner/diagnose":
            issue_type = str(body.get("issue_type") or "bid_micros_schema_422").strip()
            agency_id = body.get("agency_id")
            advertiser_id = body.get("advertiser_id")
            custom_payload = body.get("error_payload") if isinstance(body.get("error_payload"), dict) else None
            partner_note = str(body.get("partner_note") or "").strip()
            use_bedrock = bool(body.get("use_bedrock", True))
            out = CONTROL_PLANE.diagnostics.diagnose_and_advise(
                issue_type=issue_type,
                agency_id=str(agency_id).strip() if agency_id else None,
                advertiser_id=str(advertiser_id).strip() if advertiser_id else None,
                custom_payload=custom_payload,
                partner_note=partner_note,
                use_bedrock=use_bedrock,
            )
            out["request_id"] = request_id
            return 200, out

        if path == "/api/audit/verify" and method in ("GET", "POST"):
            chain = CONTROL_PLANE.ledger.verify_chain_integrity()
            events = CONTROL_PLANE.ledger.list_recent_events(limit=25)
            budgets = CONTROL_PLANE.ledger.get_privacy_budget_summary()
            return 200, {
                "audit_chain": chain,
                "audit_events": events,
                "privacy_budgets": budgets,
                "request_id": request_id,
            }

        if method == "POST" and path == "/api/reset":
            out = CONTROL_PLANE.reset_all()
            out["request_id"] = request_id
            return 200, out

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except KeyError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {
        k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None
    }
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalPartnerCleanRoomHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3099) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalPartnerCleanRoomHandler)
    print(f"PartnerCleanRoom running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3099"))
    run_local_server(port=port_num)
