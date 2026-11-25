"""Real end-to-end benchmark runner for PartnerCleanRoom (SQLite + Drift Math + Live Amazon Bedrock)."""
from __future__ import annotations

import json
import math
import os
import platform
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from partner_cleanroom.cleanroom_sql import CleanRoomSQLGateway
from partner_cleanroom.model_drift import PartnerModelDriftGuard
from partner_cleanroom.partner_diagnostics import PartnerDiagnosticsAdvisor
from partner_cleanroom.vending_ledger import PartnerVendingLedger


def pct(vals: List[float], p: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    idx = (len(s) - 1) * (p / 100.0)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return round(s[lo], 3)
    frac = idx - lo
    return round(s[lo] * (1.0 - frac) + s[hi] * frac, 3)


def main() -> None:
    out_path = ROOT_DIR / "benchmarks" / "latest_results.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        ledger = PartnerVendingLedger(db_path=base / "bench_audit.db")
        cleanroom = CleanRoomSQLGateway(ledger=ledger, db_path=base / "bench_cleanroom.db", k_floor=25)
        drift_guard = PartnerModelDriftGuard(ledger=ledger)
        diagnostics = PartnerDiagnosticsAdvisor(cleanroom=cleanroom, ledger=ledger)

        # =====================================================================
        # 1. Authorized Multi-Tenant Clean-Room Queries (16 executions)
        # =====================================================================
        authorized_queries = [
            (
                "agency-northstar-media",
                "adv-summit-gear",
                "SELECT shopper_segment, COUNT(DISTINCT user_id) AS distinct_shoppers, ROUND(SUM(spend_usd),2) AS spend_usd, ROUND(SUM(attributed_sales_usd),2) AS sales_usd FROM ad_events GROUP BY shopper_segment ORDER BY spend_usd DESC",
            ),
            (
                "agency-northstar-media",
                "adv-summit-gear",
                "SELECT campaign_id, placement, COUNT(DISTINCT user_id) AS distinct_shoppers, SUM(impressions) AS impressions, SUM(clicks) AS clicks FROM ad_events GROUP BY campaign_id, placement",
            ),
            (
                "agency-northstar-media",
                "adv-lumina-home",
                "SELECT shopper_segment, COUNT(DISTINCT user_id) AS distinct_shoppers, ROUND(SUM(spend_usd),2) AS spend_usd, SUM(conversions) AS conversions FROM ad_events GROUP BY shopper_segment",
            ),
            (
                "agency-kestrel-growth",
                "adv-veloce-audio",
                "SELECT shopper_segment, COUNT(DISTINCT user_id) AS distinct_shoppers, ROUND(SUM(spend_usd),2) AS spend_usd, ROUND(SUM(attributed_sales_usd),2) AS sales_usd FROM ad_events GROUP BY shopper_segment",
            ),
        ]

        policy_eval_latencies: List[float] = []
        cleanroom_query_latencies: List[float] = []
        total_safe_cohorts = 0
        total_redacted_cohorts = 0
        total_protected_shoppers = 0

        for _ in range(4):
            for ag_id, adv_id, sql in authorized_queries:
                res = cleanroom.execute_cleanroom_query(agency_id=ag_id, advertiser_id=adv_id, sql=sql)
                assert res["allowed"], f"Authorized query unexpectedly failed: {res}"
                for row in res["rows"]:
                    assert row["distinct_shoppers"] >= 25, f"Sub-k leak detected: {row}"
                policy_eval_latencies.append(float(res["policy_eval_ms"]))
                cleanroom_query_latencies.append(float(res["total_ms"]))
                total_safe_cohorts += int(res["returned_cohorts_count"])
                total_redacted_cohorts += int(res["redacted_cohorts_count"])
                total_protected_shoppers += int(res["redacted_shoppers_protected"])

        # =====================================================================
        # 2. 24 Red-Team User-Reconstruction & Cross-Advertiser Leakage Probes
        # =====================================================================
        redteam_probes = [
            # Direct PII & Wildcard
            ("RT-01", "Wildcard SELECT * on ad_events", "agency-northstar-media", "adv-summit-gear", "SELECT * FROM ad_events WHERE advertiser_id = 'adv-summit-gear'"),
            ("RT-02", "Raw user_id and device_id projection", "agency-northstar-media", "adv-summit-gear", "SELECT user_id, device_id, SUM(spend_usd) FROM ad_events GROUP BY user_id, device_id"),
            ("RT-03", "SUBSTR(user_id, 1, 8) prefix slicing", "agency-northstar-media", "adv-summit-gear", "SELECT SUBSTR(user_id, 1, 8), COUNT(*) FROM ad_events GROUP BY 1"),
            ("RT-04", "HEX(device_id) fingerprint extraction", "agency-northstar-media", "adv-summit-gear", "SELECT HEX(device_id), SUM(clicks) FROM ad_events GROUP BY 1"),
            ("RT-05", "MAX(user_id) singleton extraction", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, MAX(user_id) FROM ad_events GROUP BY campaign_id"),
            ("RT-06", "Table-qualified ad_events.* wildcard", "agency-northstar-media", "adv-summit-gear", "SELECT ad_events.* FROM ad_events GROUP BY campaign_id"),
            # Differencing & Micro-Cohort Probes
            ("RT-07", "HAVING COUNT(DISTINCT user_id) < 25 probe", "agency-northstar-media", "adv-summit-gear", "SELECT shopper_segment, COUNT(DISTINCT user_id) FROM ad_events GROUP BY shopper_segment HAVING COUNT(DISTINCT user_id) < 25"),
            ("RT-08", "HAVING COUNT(*) = 1 singleton probe", "agency-northstar-media", "adv-summit-gear", "SELECT shopper_segment, COUNT(*) FROM ad_events GROUP BY shopper_segment HAVING COUNT(*) = 1"),
            ("RT-09", "WHERE user_id = '...' targeted lookup", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, SUM(spend_usd) FROM ad_events WHERE user_id = 'usr_summit_0001' GROUP BY campaign_id"),
            ("RT-10", "EXCEPT set-differencing reconstruction", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id EXCEPT SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id"),
            ("RT-11", "UNION ALL raw user_id injection", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, SUM(spend_usd) FROM ad_events GROUP BY campaign_id UNION ALL SELECT campaign_id, 0 FROM campaigns"),
            ("RT-12", "OVER() window function row leak", "agency-northstar-media", "adv-summit-gear", "SELECT shopper_segment, SUM(spend_usd) OVER (ORDER BY campaign_id) FROM ad_events"),
            # Cross-Advertiser & Revoked Grant Attacks
            ("RT-13", "Northstar querying ungranted adv-veloce-audio", "agency-northstar-media", "adv-veloce-audio", "SELECT shopper_segment, SUM(spend_usd) FROM ad_events GROUP BY shopper_segment"),
            ("RT-14", "Kestrel querying ungranted adv-summit-gear", "agency-kestrel-growth", "adv-summit-gear", "SELECT shopper_segment, SUM(spend_usd) FROM ad_events GROUP BY shopper_segment"),
            ("RT-15", "Revoked agency querying adv-summit-gear", "agency-revoked-bidops", "adv-summit-gear", "SELECT shopper_segment, SUM(spend_usd) FROM ad_events GROUP BY shopper_segment"),
            ("RT-16", "SQL OR cross-advertiser literal injection", "agency-northstar-media", "adv-summit-gear", "SELECT advertiser_id, SUM(spend_usd) FROM ad_events WHERE advertiser_id = 'adv-summit-gear' OR advertiser_id = 'adv-veloce-audio' GROUP BY advertiser_id"),
            ("RT-17", "Kestrel querying ungranted adv-lumina-home", "agency-kestrel-growth", "adv-lumina-home", "SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id"),
            ("RT-18", "Forged agency token querying adv-summit-gear", "agency-unregistered-bot", "adv-summit-gear", "SELECT campaign_id, SUM(spend_usd) FROM ad_events GROUP BY campaign_id"),
            # DDL, Catalog, Unaggregated & Sub-k Micro-Cohort Suppression
            ("RT-19", "Multi-statement semicolon DROP TABLE chain", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id; DROP TABLE ad_events"),
            ("RT-20", "sqlite_master schema catalog enumeration", "agency-northstar-media", "adv-summit-gear", "SELECT COUNT(*) FROM sqlite_master"),
            ("RT-21", "PRAGMA table_info metadata probe", "agency-northstar-media", "adv-summit-gear", "PRAGMA table_info(ad_events)"),
            ("RT-22", "Unaggregated raw event row dump (LIMIT 5)", "agency-northstar-media", "adv-summit-gear", "SELECT campaign_id, spend_usd FROM ad_events LIMIT 5"),
            ("RT-23", "Single-household retarget cohort (n=1 < 25)", "agency-northstar-media", "adv-summit-gear", "SELECT shopper_segment, SUM(spend_usd) AS spend FROM ad_events WHERE shopper_segment = 'single_household_retarget' GROUP BY shopper_segment"),
            ("RT-24", "Narrow zip & VIP trek micro-cohorts (n=4, n=9 < 25)", "agency-northstar-media", "adv-summit-gear", "SELECT shopper_segment, SUM(attributed_sales_usd) AS sales FROM ad_events WHERE shopper_segment IN ('vip_repeat_trek_buyers', 'ultra_narrow_zip_98101') GROUP BY shopper_segment"),
        ]

        redteam_results: List[Dict[str, Any]] = []
        cross_tenant_leaks = 0
        sub_k_leaks = 0

        for probe_id, vector, ag_id, adv_id, sql in redteam_probes:
            out = cleanroom.execute_cleanroom_query(agency_id=ag_id, advertiser_id=adv_id, sql=sql)
            policy_eval_latencies.append(float(out["policy_eval_ms"]))
            leaked_rows = len(out["rows"])
            assert leaked_rows == 0, f"Red-team probe {probe_id} leaked rows: {out}"
            cross_tenant_leaks += int(out["cross_tenant_leak_rows"])
            sub_k_leaks += int(out["sub_k_leak_rows"])
            redteam_results.append(
                {
                    "probe_id": probe_id,
                    "vector": vector,
                    "agency_id": ag_id,
                    "target_advertiser": adv_id,
                    "verdict": out["verdict"],
                    "policy_rule": out["policy_rule"],
                    "eval_ms": out["total_ms"],
                    "rows_exposed": leaked_rows,
                    "protected": True,
                }
            )

        # =====================================================================
        # 3. Partner Custom Bidding Model Drift & Circuit-Breaker (5,000 impr/scenario)
        # =====================================================================
        drift_scenarios = [
            ("mdl-northstar-roas-v2", "healthy_shadow", False),
            ("mdl-kestrel-promo-v3", "feature_drift_spike", True),
            ("mdl-kestrel-promo-v3", "calibration_collapse", True),
            ("mdl-acorn-neural-v1", "latency_sla_breach", True),
        ]
        drift_matrix: List[Dict[str, Any]] = []
        drift_correct = 0
        for mid, scen, expected_trip in drift_scenarios:
            d_res = drift_guard.evaluate_partner_model(model_id=mid, scenario=scen, sample_size=5000)
            matched = bool(d_res["circuit_tripped"]) == expected_trip
            assert matched, f"Drift circuit breaker mismatch on {mid}/{scen}: {d_res}"
            drift_correct += 1
            m = d_res["metrics"]
            drift_matrix.append(
                {
                    "model_id": mid,
                    "scenario": scen,
                    "impressions": d_res["impressions_evaluated"],
                    "max_psi": m["max_psi"],
                    "partner_ece": m["partner_ece"],
                    "slate_p50_ms": m["slate_p50_ms"],
                    "slate_p99_ms": m["slate_p99_ms"],
                    "verdict": d_res["verdict"],
                    "active_ranker": d_res["active_ranker"],
                    "eval_duration_ms": d_res["eval_duration_ms"],
                    "expected_verdict_matched": matched,
                }
            )

        # =====================================================================
        # 4. Partner API Debugger & Live Amazon Bedrock Advisor (10 live runs)
        # =====================================================================
        diag_runs_spec = [
            ("DIAG-01", "expired_refresh_token_401", "ERR-LWA-401-EXPIRED", "Worker pool hitting 401 after 60m uptime."),
            ("DIAG-02", "missing_advertiser_grant_403", "ERR-GRANT-403-SCOPE", "Agency trying to pull Veloce cohort report."),
            ("DIAG-03", "bid_micros_schema_422", "ERR-SCHEMA-422-MICROS", "Migrating v2 float bid payload to SP v3."),
            ("DIAG-04", "retry_after_429", "ERR-RATE-429-BACKOFF", "Sync campaign list poller throttled at 48 rps."),
            ("DIAG-05", "hmac_webhook_drift", "ERR-HMAC-SIG-DRIFT", "Express JSON middleware broke webhook HMAC."),
            ("DIAG-06", "bid_micros_schema_422", "ERR-SCHEMA-422-MICROS", "Optimize Summit Trail backpack exact keywords."),
            ("DIAG-07", "retry_after_429", "ERR-RATE-429-BACKOFF", "Optimize Lumina smart bulb keyword spend."),
            ("DIAG-08", "hmac_webhook_drift", "ERR-HMAC-SIG-DRIFT", "Optimize Veloce studio headphone bids."),
            ("DIAG-09", "expired_refresh_token_401", "ERR-LWA-401-EXPIRED", "Single-flight LWA token refresh guidance."),
            ("DIAG-10", "missing_advertiser_grant_403", "ERR-GRANT-403-SCOPE", "Verify OAuth scope header requirements."),
        ]

        bedrock_latencies: List[float] = []
        bedrock_tokens_list: List[int] = []
        diagnostic_results: List[Dict[str, Any]] = []
        diag_passed = 0

        for run_id, issue_type, expected_code, note in diag_runs_spec:
            diag_out = diagnostics.diagnose_and_advise(
                issue_type=issue_type,
                partner_note=note,
                use_bedrock=True,
            )
            b_info = diag_out["bedrock"]
            assert b_info["invoked_live"], f"Bedrock live call failed during benchmark: {b_info}"
            assert diag_out["diagnostic_code"] == expected_code
            assert b_info["retail_policy_compliant"]
            diag_passed += 1
            bedrock_latencies.append(float(b_info["bedrock_latency_ms"]))
            bedrock_tokens_list.append(int(b_info["bedrock_tokens"]))
            diagnostic_results.append(
                {
                    "run_id": run_id,
                    "issue_type": issue_type,
                    "issue_title": diag_out["issue_title"],
                    "diagnostic_code": diag_out["diagnostic_code"],
                    "kb_doc": diag_out["kb_citations"][0]["doc_id"],
                    "campaign_actions_count": len(diag_out["campaign_recommendations"]["recommended_actions"]),
                    "bedrock_latency_ms": b_info["bedrock_latency_ms"],
                    "bedrock_tokens": b_info["bedrock_tokens"],
                    "passed": True,
                }
            )

        # =====================================================================
        # 5. SQLite WAL Hash-Chain Verification
        # =====================================================================
        chain_check = ledger.verify_chain_integrity()
        assert chain_check["valid"], f"Ledger verification failed: {chain_check}"

        payload: Dict[str, Any] = {
            "service": "ads-partner-cleanroom",
            "benchmark_timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "environment": {
                "python_version": platform.python_version(),
                "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
                "aws_region": os.environ.get("AWS_DEFAULT_REGION", "us-west-2"),
                "bedrock_model": diagnostics.bedrock_model,
                "cleanroom_store": "SQLite WAL + Tenant CTE + k>=25 Cohort Floor",
                "audit_store": "SQLite WAL + SHA-256 Hash Chain",
            },
            "headline_kpis": {
                "k_anonymity_floor": 25,
                "redteam_queries_total": len(redteam_results),
                "redteam_queries_blocked_or_suppressed": len(redteam_results),
                "redteam_protection_pct": 100.0,
                "cross_advertiser_leak_pct": 0.0,
                "sub_k25_user_leaks": sub_k_leaks,
                "authorized_queries_executed": 16,
                "safe_cohorts_vended": total_safe_cohorts,
                "micro_cohorts_redacted": total_redacted_cohorts,
                "shoppers_protected_by_k_floor": total_protected_shoppers,
                "sql_policy_p50_ms": pct(policy_eval_latencies, 50.0),
                "sql_policy_p95_ms": pct(policy_eval_latencies, 95.0),
                "cleanroom_query_p50_ms": pct(cleanroom_query_latencies, 50.0),
                "cleanroom_query_p95_ms": pct(cleanroom_query_latencies, 95.0),
                "impressions_per_drift_eval": 5000,
                "drift_scenarios_total": len(drift_matrix),
                "drift_scenarios_verified": drift_correct,
                "drift_detection_accuracy_pct": 100.0,
                "healthy_slate_p99_ms": drift_matrix[0]["slate_p99_ms"],
                "drifted_feature_max_psi": drift_matrix[1]["max_psi"],
                "diagnostic_runs_total": len(diagnostic_results),
                "diagnostic_runs_passed": diag_passed,
                "diagnostic_accuracy_pct": 100.0,
                "bedrock_calls_measured": len(bedrock_latencies),
                "bedrock_latency_p50_ms": pct(bedrock_latencies, 50.0),
                "bedrock_latency_p95_ms": pct(bedrock_latencies, 95.0),
                "bedrock_mean_tokens": round(sum(bedrock_tokens_list) / max(1, len(bedrock_tokens_list)), 1),
                "bedrock_total_tokens": sum(bedrock_tokens_list),
                "audit_rows_verified": chain_check["checked_rows"],
                "audit_verify_ms": chain_check["verify_ms"],
            },
            "drift_evaluation_matrix": drift_matrix,
            "redteam_results": redteam_results,
            "diagnostic_bedrock_results": diagnostic_results,
        }

        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(payload["headline_kpis"], indent=2))


if __name__ == "__main__":
    main()
