"""MCP Partner API & Webhook Integration Debugger + Bedrock Campaign Advisor."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from .cleanroom_sql import CleanRoomSQLGateway
from .vending_ledger import PartnerVendingLedger

DEFAULT_BEDROCK_MODEL = "us.amazon.nova-lite-v1:0"

BANNED_RETAIL_CLAIM_RE = re.compile(
    r"(#1\b|\bnumber\s+one\b|\bbest\s+seller\b|\b100%\s+guaranteed\b|\bmiracle\b|\bunbeatable\b)",
    re.IGNORECASE,
)

PARTNER_KB_DOCS: List[Dict[str, str]] = [
    {
        "doc_id": "KB-LWA-OAUTH-01",
        "title": "Login with Amazon (LWA) OAuth Token Lifecycle & Refresh Rotation",
        "tags": "401 unauthorized expired access token refresh_token oauth lwa bearer",
        "content": (
            "Amazon Ads API access tokens expire strictly at 3,600 seconds. Partner workers must cache bearer tokens "
            "with a 300-second pre-expiry refresh buffer via POST https://api.amazon.com/auth/o2/token and persist rotated "
            "refresh tokens atomically so concurrent workers do not replay invalidated tokens."
        ),
    },
    {
        "doc_id": "KB-GRANT-SCOPE-02",
        "title": "Multi-Tenant Advertiser Delegation Grants & Profile Scope Headers",
        "tags": "403 forbidden missing advertiser grant scope profile delegation agency",
        "content": (
            "Every Partner API call must pass Amazon-Advertising-API-Scope matching an advertiser profile with an ACTIVE "
            "OAuth delegation grant and required scopes (campaign:read, cohort:aggregate, bid:recommend). Revoked or unlinked "
            "advertiser grants immediately return 403 ACCESS_DENIED."
        ),
    },
    {
        "doc_id": "KB-SPV3-SCHEMA-03",
        "title": "Sponsored Products v3 Bid Micros & Enum Schema Contract",
        "tags": "422 unprocessable schema bid bid_micros float micros matchType exact",
        "content": (
            "Sponsored Products v3 endpoints reject floating-point dollar bids (for example bid: 1.85). Partners must submit "
            "integer bid_micros (1 USD = 1,000,000 micros, minimum 20,000 micros) and uppercase matchType enums "
            "(EXACT, PHRASE, BROAD)."
        ),
    },
    {
        "doc_id": "KB-RATELIMIT-429-04",
        "title": "Token-Bucket Rate Quotas, Retry-After Headers & Async Snapshots",
        "tags": "429 too many requests rate limit retry-after throttling backoff polling",
        "content": (
            "Synchronous campaign list and bid mutation routes enforce per-profile token buckets. On HTTP 429, partners must "
            "honor the Retry-After response header plus full-jitter exponential backoff, and replace tight reporting loops "
            "with asynchronous v3 Reporting Snapshots."
        ),
    },
    {
        "doc_id": "KB-WEBHOOK-HMAC-05",
        "title": "Partner Webhook HMAC-SHA256 Canonical Signature & Replay Guard",
        "tags": "hmac webhook signature x-amz-ads-signature drift timestamp raw bytes",
        "content": (
            "Webhook receivers must compute HMAC-SHA256(webhook_secret, X-Amz-Ads-Timestamp + '.' + raw_utf8_body) before JSON "
            "parsing. Re-serializing parsed dictionaries alters whitespace or key order and invalidates signatures; timestamps "
            "older than 300 seconds must be rejected."
        ),
    },
    {
        "doc_id": "KB-CAMPAIGN-ROAS-06",
        "title": "Sponsored Products & Brands Keyword Harvesting & Retail Ad Policy",
        "tags": "campaign roas acos exact negative keyword bid optimization headline moderation",
        "content": (
            "Promote high-ROAS search cohorts (k >= 25 shoppers) to EXACT match with +10% to +15% top-of-search bid micros, "
            "add negative exact keywords on zero-conversion BROAD terms, and ensure Sponsored Brands headlines contain zero "
            "unverified superlatives (#1, best seller, 100% guaranteed)."
        ),
    },
]

DIAGNOSTIC_PRESETS: Dict[str, Dict[str, Any]] = {
    "expired_refresh_token_401": {
        "issue_type": "expired_refresh_token_401",
        "title": "401 Expired Refresh Token",
        "http_status": 401,
        "agency_id": "agency-northstar-media",
        "advertiser_id": "adv-summit-gear",
        "error_payload": {
            "status": 401,
            "code": "UNAUTHORIZED_TOKEN_EXPIRED",
            "header_token_age_sec": 5412,
            "lwa_ttl_sec": 3600,
            "concurrent_refresh_race": True,
            "endpoint": "POST /sp/targets/bid/recommendations",
        },
    },
    "missing_advertiser_grant_403": {
        "issue_type": "missing_advertiser_grant_403",
        "title": "403 Missing Advertiser Grant",
        "http_status": 403,
        "agency_id": "agency-northstar-media",
        "advertiser_id": "adv-veloce-audio",
        "error_payload": {
            "status": 403,
            "code": "MISSING_ADVERTISER_DELEGATION_GRANT",
            "requested_scope": "campaign:read",
            "profile_advertiser_id": "adv-veloce-audio",
            "endpoint": "POST /cleanroom/v3/cohorts/query",
        },
    },
    "bid_micros_schema_422": {
        "issue_type": "bid_micros_schema_422",
        "title": "422 Bid Micros Schema Mismatch",
        "http_status": 422,
        "agency_id": "agency-northstar-media",
        "advertiser_id": "adv-summit-gear",
        "error_payload": {
            "status": 422,
            "code": "SCHEMA_VALIDATION_FAILED",
            "endpoint": "PUT /sp/keywords",
            "submitted_body": {
                "campaignId": "cmp-sp-trailpacks",
                "keywordText": "ultralight hiking backpack 45l",
                "matchType": "exact",
                "bid": 1.85,
            },
        },
    },
    "retry_after_429": {
        "issue_type": "retry_after_429",
        "title": "429 Retry-After Backoff Violation",
        "http_status": 429,
        "agency_id": "agency-northstar-media",
        "advertiser_id": "adv-lumina-home",
        "error_payload": {
            "status": 429,
            "code": "TOO_MANY_REQUESTS",
            "observed_rps": 48.0,
            "quota_rps": 10.0,
            "retry_after_header_sec": 4,
            "partner_retry_delay_ms": 45,
            "endpoint": "POST /sp/campaigns/list",
        },
    },
    "hmac_webhook_drift": {
        "issue_type": "hmac_webhook_drift",
        "title": "HMAC Webhook Signature Drift",
        "http_status": 401,
        "agency_id": "agency-kestrel-growth",
        "advertiser_id": "adv-veloce-audio",
        "error_payload": {
            "status": 401,
            "code": "WEBHOOK_SIGNATURE_MISMATCH",
            "timestamp_header": "1764109200",
            "clock_skew_sec": 42,
            "raw_body": '{"campaignId":"cmp-sp-anc-buds","budgetExhaustedPct":92.5,"event":"BUDGET_ALERT"}',
            "partner_reserialized_body": '{"budgetExhaustedPct": 92.5, "campaignId": "cmp-sp-anc-buds", "event": "BUDGET_ALERT"}',
            "endpoint": "POST /partner/webhooks/budget-alerts",
        },
    },
}


def retrieve_partner_kb(query_text: str, top_k: int = 2) -> List[Dict[str, str]]:
    """Lexical keyword overlap retriever over the Partner API & Campaign Optimization KB."""
    tokens = set(re.findall(r"[a-z0-9_]+", query_text.lower()))
    scored: List[tuple[int, Dict[str, str]]] = []
    for doc in PARTNER_KB_DOCS:
        hay = set(re.findall(r"[a-z0-9_]+", (doc["title"] + " " + doc["tags"] + " " + doc["content"]).lower()))
        overlap = len(tokens & hay)
        scored.append((overlap, doc))
    scored.sort(key=lambda x: x[0], reverse=True)
    selected = [d for sc, d in scored[:top_k] if sc > 0]
    return selected if selected else PARTNER_KB_DOCS[:top_k]


def verify_retail_ad_policy(headline_or_text: str) -> Dict[str, Any]:
    """Blocks unverified superlative claims in Sponsored Brands creative copy."""
    hit = BANNED_RETAIL_CLAIM_RE.search(headline_or_text or "")
    if hit:
        sanitized = BANNED_RETAIL_CLAIM_RE.sub("trusted", headline_or_text)
        return {
            "compliant": False,
            "flagged_term": hit.group(0),
            "sanitized_text": sanitized,
        }
    return {
        "compliant": True,
        "flagged_term": None,
        "sanitized_text": headline_or_text,
    }


class PartnerDiagnosticsAdvisor:
    """Diagnoses Partner API & webhook faults and generates Bedrock-grounded campaign recommendations."""

    def __init__(self, cleanroom: CleanRoomSQLGateway, ledger: PartnerVendingLedger) -> None:
        self.cleanroom = cleanroom
        self.ledger = ledger
        self.bedrock_model = os.environ.get("PARTNER_CLEANROOM_BEDROCK_MODEL", DEFAULT_BEDROCK_MODEL)
        self.aws_region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or "us-west-2"

    def list_presets(self) -> List[Dict[str, Any]]:
        return [
            {
                "issue_type": k,
                "title": v["title"],
                "http_status": v["http_status"],
                "agency_id": v["agency_id"],
                "advertiser_id": v["advertiser_id"],
            }
            for k, v in DIAGNOSTIC_PRESETS.items()
        ]

    def _run_deterministic_diagnosis(
        self,
        issue_type: str,
        agency_id: str,
        advertiser_id: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        if issue_type == "expired_refresh_token_401":
            age = int(payload.get("header_token_age_sec", 5412))
            return {
                "diagnostic_code": "ERR-LWA-401-EXPIRED",
                "root_cause": (
                    f"Bearer access token age ({age}s) exceeded the 3,600s Login with Amazon TTL, and concurrent worker "
                    "threads raced on single-use refresh_token rotation."
                ),
                "remediation_patch": {
                    "token_endpoint": "POST https://api.amazon.com/auth/o2/token",
                    "pre_expiry_refresh_window_sec": 300,
                    "distributed_token_lock": "acquire single-flight mutex per agency_id before rotating refresh_token",
                },
            }

        if issue_type == "missing_advertiser_grant_403":
            grant_state = self.cleanroom.check_delegation(agency_id=agency_id, advertiser_id=advertiser_id)
            return {
                "diagnostic_code": "ERR-GRANT-403-SCOPE",
                "root_cause": grant_state["reason"],
                "remediation_patch": {
                    "required_header": "Amazon-Advertising-API-Scope",
                    "grant_verification": grant_state["policy_rule"],
                    "action": f"Request advertiser '{advertiser_id}' to approve OAuth delegation scopes ['campaign:read', 'cohort:aggregate'] or switch to an active granted advertiser.",
                },
            }

        if issue_type == "bid_micros_schema_422":
            submitted = payload.get("submitted_body") or {
                "campaignId": "cmp-sp-trailpacks",
                "keywordText": "ultralight hiking backpack 45l",
                "matchType": "exact",
                "bid": 1.85,
            }
            raw_bid = float(submitted.get("bid", 1.85))
            bid_micros = max(20000, int(round(raw_bid * 1_000_000)))
            fixed_body = {
                "campaignId": submitted.get("campaignId", "cmp-sp-trailpacks"),
                "keywordText": submitted.get("keywordText", "ultralight hiking backpack 45l"),
                "matchType": str(submitted.get("matchType", "EXACT")).upper(),
                "bid_micros": bid_micros,
            }
            return {
                "diagnostic_code": "ERR-SCHEMA-422-MICROS",
                "root_cause": (
                    f"Partner submitted float dollar field 'bid': {raw_bid} and lowercase 'matchType' instead of "
                    f"Sponsored Products v3 integer 'bid_micros': {bid_micros} and uppercase enum '{fixed_body['matchType']}'."
                ),
                "remediation_patch": {
                    "invalid_v2_payload": submitted,
                    "corrected_v3_payload": fixed_body,
                },
            }

        if issue_type == "retry_after_429":
            retry_sec = int(payload.get("retry_after_header_sec", 4))
            schedule_ms = [retry_sec * 1000, retry_sec * 2000 + 310, retry_sec * 4000 + 620]
            return {
                "diagnostic_code": "ERR-RATE-429-BACKOFF",
                "root_cause": (
                    f"Partner burst {payload.get('observed_rps', 48.0)} req/s against a {payload.get('quota_rps', 10.0)} req/s "
                    f"profile bucket and retried after {payload.get('partner_retry_delay_ms', 45)} ms, violating Retry-After: {retry_sec}s."
                ),
                "remediation_patch": {
                    "honor_retry_after_sec": retry_sec,
                    "full_jitter_backoff_ms": schedule_ms,
                    "bulk_migration_endpoint": "POST /reporting/reports (v3 Async GZIP Snapshot)",
                },
            }

        # Default / hmac_webhook_drift
        secret = b"amz_partner_webhook_signing_secret_v1"
        ts = str(payload.get("timestamp_header", "1764109200"))
        raw_body = str(
            payload.get(
                "raw_body",
                '{"campaignId":"cmp-sp-anc-buds","budgetExhaustedPct":92.5,"event":"BUDGET_ALERT"}',
            )
        )
        mutated_body = str(
            payload.get(
                "partner_reserialized_body",
                json.dumps(json.loads(raw_body), sort_keys=True),
            )
        )
        expected_sig = hmac.new(secret, f"{ts}.{raw_body}".encode("utf-8"), hashlib.sha256).hexdigest()
        partner_sig = hmac.new(secret, f"{ts}.{mutated_body}".encode("utf-8"), hashlib.sha256).hexdigest()
        return {
            "diagnostic_code": "ERR-HMAC-SIG-DRIFT",
            "root_cause": (
                "Partner parsed the JSON webhook body before verifying X-Amz-Ads-Signature; key sorting and whitespace "
                "changes altered the SHA-256 HMAC digest."
            ),
            "remediation_patch": {
                "canonical_signing_input": f"{ts}.<raw_request_bytes>",
                "expected_hmac_sha256": expected_sig[:32] + "...",
                "partner_mutated_hmac": partner_sig[:32] + "...",
                "replay_window_max_sec": 300,
            },
        }

    def _build_campaign_recommendations(
        self,
        agency_id: str,
        advertiser_id: str,
    ) -> Dict[str, Any]:
        cohorts = self.cleanroom.get_authorized_campaign_insights(
            agency_id=agency_id,
            advertiser_id=advertiser_id,
        )
        # If target advertiser is unauthorized (e.g. 403 test), inspect agency's primary authorized advertiser if available
        recommendation_adv = advertiser_id
        if not cohorts:
            for g in self.cleanroom.list_grants():
                if g["agency_id"] == agency_id and g["status"] == "ACTIVE":
                    recommendation_adv = g["advertiser_id"]
                    cohorts = self.cleanroom.get_authorized_campaign_insights(agency_id, recommendation_adv)
                    if cohorts:
                        break

        actions: List[Dict[str, Any]] = []
        for c in cohorts:
            spend = float(c.get("spend_usd", 0.0) or 0.0)
            sales = float(c.get("sales_usd", 0.0) or 0.0)
            convs = int(c.get("conversions", 0) or 0)
            roas = round(sales / spend, 2) if spend > 0 else 0.0
            kw = str(c.get("keyword_term", ""))
            mtype = str(c.get("match_type", ""))
            if convs == 0 or (mtype == "BROAD" and roas < 2.2):
                actions.append(
                    {
                        "action": "ADD_NEGATIVE_EXACT_KEYWORD",
                        "campaign_id": c["campaign_id"],
                        "keyword_term": kw,
                        "observed_roas": roas,
                        "distinct_shoppers": c["distinct_shoppers"],
                        "rationale": f"Broad term spent ${spend:.2f} at {roas:.2f}x ROAS; exclude to stop wasted clicks.",
                    }
                )
            elif roas >= 3.8:
                actions.append(
                    {
                        "action": "RAISE_EXACT_BID_MICROS_12PCT",
                        "campaign_id": c["campaign_id"],
                        "keyword_term": kw,
                        "observed_roas": roas,
                        "distinct_shoppers": c["distinct_shoppers"],
                        "rationale": f"High-converting cohort ({c['distinct_shoppers']} shoppers, {roas:.2f}x ROAS); boost Top-of-Search share.",
                    }
                )

        headline_draft = f"Shop Durable Gear Built for Every Trail ({recommendation_adv})"
        moderation = verify_retail_ad_policy(headline_draft)
        return {
            "grounded_advertiser_id": recommendation_adv,
            "vended_cohorts_analyzed": len(cohorts),
            "recommended_actions": actions[:4],
            "sponsored_brands_headline": moderation["sanitized_text"],
            "retail_policy_compliant": moderation["compliant"],
        }

    def _invoke_bedrock(
        self,
        issue_title: str,
        diag: Dict[str, Any],
        kb_docs: List[Dict[str, str]],
        campaign_plan: Dict[str, Any],
        partner_note: str,
    ) -> Dict[str, Any]:
        kb_refs = ", ".join(f"{d['doc_id']} ({d['title']})" for d in kb_docs)
        prompt_text = (
            "You are an Amazon Ads Partner Tech Solutions Engineer and Campaign Optimization Advisor.\n"
            f"Issue Diagnosed: {issue_title} ({diag['diagnostic_code']})\n"
            f"Deterministic Root Cause: {diag['root_cause']}\n"
            f"Remediation Patch: {json.dumps(diag['remediation_patch'])}\n"
            f"Knowledge Base Citations: {kb_refs}\n"
            f"Clean-Room Campaign Recommendations (k>=25 verified): {json.dumps(campaign_plan['recommended_actions'][:3])}\n"
            f"Partner Context Note: {partner_note or 'Provide concise remediation and campaign actions.'}\n\n"
            "Write a clear, concise 2-part engineering response (under 140 words total, plain text, no markdown tables, "
            "no em-dashes):\n"
            "1) API Fix: exact technical steps referencing the Knowledge Base ID.\n"
            "2) Campaign Optimization: concrete keyword and bid_micros actions grounded in the k>=25 clean-room cohorts."
        )

        t0 = time.perf_counter()
        try:
            import boto3
            import shutil
            import subprocess

            try:
                client = boto3.client("bedrock-runtime", region_name=self.aws_region)
                resp = client.converse(
                    modelId=self.bedrock_model,
                    messages=[{"role": "user", "content": [{"text": prompt_text}]}],
                    inferenceConfig={"maxTokens": 320, "temperature": 0.2},
                )
            except Exception as inner_exc:
                if "botocore[crt]" in str(inner_exc) or "NoCredentialsError" in type(inner_exc).__name__:
                    aws_bin = shutil.which("aws")
                    if not aws_bin:
                        raise
                    cred_env = dict(os.environ)
                    cred_env.pop("AWS_ACCESS_KEY_ID", None)
                    cred_env.pop("AWS_SECRET_ACCESS_KEY", None)
                    cred_env.pop("AWS_SESSION_TOKEN", None)
                    cred_env["AWS_PROFILE"] = os.environ.get("AWS_PROFILE", "portfolio")
                    proc = subprocess.run(
                        [aws_bin, "configure", "export-credentials", "--profile", cred_env["AWS_PROFILE"], "--format", "process"],
                        env=cred_env,
                        capture_output=True,
                        text=True,
                        timeout=8.0,
                        check=True,
                    )
                    exported = json.loads(proc.stdout)
                    t0 = time.perf_counter()
                    client = boto3.client(
                        "bedrock-runtime",
                        region_name=self.aws_region,
                        aws_access_key_id=exported["AccessKeyId"],
                        aws_secret_access_key=exported["SecretAccessKey"],
                        aws_session_token=exported.get("SessionToken"),
                    )
                    resp = client.converse(
                        modelId=self.bedrock_model,
                        messages=[{"role": "user", "content": [{"text": prompt_text}]}],
                        inferenceConfig={"maxTokens": 320, "temperature": 0.2},
                    )
                else:
                    raise

            round_trip_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            latency_ms = round(float(resp.get("metrics", {}).get("latencyMs") or round_trip_ms), 2)
            blocks = resp.get("output", {}).get("message", {}).get("content", [])
            raw_text = "\n".join(b.get("text", "") for b in blocks if "text" in b).strip()
            # Ensure zero em-dashes in model output as well
            clean_text = raw_text.replace("\u2014", "-").replace("\u2013", "-")
            usage = resp.get("usage") or {}
            total_tokens = int(usage.get("totalTokens") or (int(usage.get("inputTokens", 0)) + int(usage.get("outputTokens", 0))))
            mod_check = verify_retail_ad_policy(clean_text)
            return {
                "invoked_live": True,
                "model_id": self.bedrock_model,
                "bedrock_latency_ms": latency_ms,
                "round_trip_ms": round_trip_ms,
                "bedrock_tokens": total_tokens,
                "advisor_guidance": mod_check["sanitized_text"],
                "retail_policy_compliant": mod_check["compliant"],
            }
        except Exception as exc:
            latency_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            doc_id = kb_docs[0]["doc_id"] if kb_docs else "KB-SPV3-SCHEMA-03"
            top_act = (
                campaign_plan["recommended_actions"][0]["rationale"]
                if campaign_plan["recommended_actions"]
                else "Maintain current exact-match bid_micros allocations."
            )
            fallback_text = (
                f"1) API Fix ({doc_id}): {diag['root_cause']} Apply the verified remediation patch parameters.\n"
                f"2) Campaign Optimization: {top_act}"
            )
            return {
                "invoked_live": False,
                "model_id": self.bedrock_model,
                "bedrock_latency_ms": latency_ms,
                "bedrock_tokens": 0,
                "advisor_guidance": fallback_text,
                "retail_policy_compliant": True,
                "fallback_reason": str(exc),
            }

    def diagnose_and_advise(
        self,
        issue_type: str = "bid_micros_schema_422",
        agency_id: Optional[str] = None,
        advertiser_id: Optional[str] = None,
        custom_payload: Optional[Dict[str, Any]] = None,
        partner_note: str = "",
        use_bedrock: bool = True,
    ) -> Dict[str, Any]:
        t_start = time.perf_counter()
        preset = DIAGNOSTIC_PRESETS.get(issue_type, DIAGNOSTIC_PRESETS["bid_micros_schema_422"])
        resolved_issue = preset["issue_type"] if issue_type in DIAGNOSTIC_PRESETS else issue_type
        resolved_agency = (agency_id or preset["agency_id"]).strip()
        resolved_adv = (advertiser_id or preset["advertiser_id"]).strip()
        payload = custom_payload if isinstance(custom_payload, dict) and custom_payload else preset["error_payload"]

        diag = self._run_deterministic_diagnosis(
            issue_type=resolved_issue,
            agency_id=resolved_agency,
            advertiser_id=resolved_adv,
            payload=payload,
        )
        kb_query = f"{preset['title']} {diag['diagnostic_code']} {diag['root_cause']} campaign roas"
        kb_docs = retrieve_partner_kb(kb_query, top_k=2)
        campaign_plan = self._build_campaign_recommendations(
            agency_id=resolved_agency,
            advertiser_id=resolved_adv,
        )

        if use_bedrock:
            ai_res = self._invoke_bedrock(
                issue_title=preset["title"],
                diag=diag,
                kb_docs=kb_docs,
                campaign_plan=campaign_plan,
                partner_note=partner_note,
            )
        else:
            ai_res = {
                "invoked_live": False,
                "model_id": self.bedrock_model,
                "bedrock_latency_ms": 0.0,
                "bedrock_tokens": 0,
                "advisor_guidance": (
                    f"1) API Fix ({kb_docs[0]['doc_id']}): {diag['root_cause']}\n"
                    f"2) Campaign Optimization: Analyzed {campaign_plan['vended_cohorts_analyzed']} clean-room cohorts."
                ),
                "retail_policy_compliant": True,
            }

        total_ms = round((time.perf_counter() - t_start) * 1000.0, 2)
        receipt = self.ledger.append_event(
            agency_id=resolved_agency,
            advertiser_id=resolved_adv,
            action_type="PARTNER_API_DIAGNOSE",
            decision="DIAGNOSED_REMEDIATED",
            policy_rule=diag["diagnostic_code"],
            summary=f"Diagnosed {preset['title']} and generated {len(campaign_plan['recommended_actions'])} k>=25 campaign actions",
            k_redacted_count=0,
            privacy_units=1,
            duration_ms=total_ms,
        )

        return {
            "issue_type": resolved_issue,
            "issue_title": preset["title"],
            "http_status": preset["http_status"],
            "agency_id": resolved_agency,
            "advertiser_id": resolved_adv,
            "diagnostic_code": diag["diagnostic_code"],
            "root_cause": diag["root_cause"],
            "remediation_patch": diag["remediation_patch"],
            "kb_citations": [{"doc_id": d["doc_id"], "title": d["title"]} for d in kb_docs],
            "campaign_recommendations": campaign_plan,
            "bedrock": ai_res,
            "total_ms": total_ms,
            "audit_receipt": receipt,
        }
