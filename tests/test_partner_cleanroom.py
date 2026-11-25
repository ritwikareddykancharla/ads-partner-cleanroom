"""Unit test suite for PartnerCleanRoom (Clean-Room SQL, Drift Guard, Diagnostics, Ledger & Lambda API)."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from partner_cleanroom.cleanroom_sql import CleanRoomSQLGateway, inspect_partner_sql
from partner_cleanroom.model_drift import PartnerModelDriftGuard
from partner_cleanroom.partner_diagnostics import PartnerDiagnosticsAdvisor, verify_retail_ad_policy
from partner_cleanroom.server import PartnerCleanRoomControlPlane, lambda_handler
from partner_cleanroom.vending_ledger import PartnerVendingLedger


class TestPartnerCleanRoom(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp_dir.name)
        self.ledger = PartnerVendingLedger(db_path=self.base / "audit.db")
        self.cleanroom = CleanRoomSQLGateway(
            ledger=self.ledger,
            db_path=self.base / "cleanroom.db",
            k_floor=25,
        )
        self.drift_guard = PartnerModelDriftGuard(ledger=self.ledger)
        self.diagnostics = PartnerDiagnosticsAdvisor(cleanroom=self.cleanroom, ledger=self.ledger)

    def tearDown(self) -> None:
        self.tmp_dir.cleanup()

    def test_01_cleanroom_vends_large_cohorts_and_redacts_sub_k25(self) -> None:
        sql = (
            "SELECT shopper_segment, COUNT(DISTINCT user_id) AS distinct_shoppers, "
            "ROUND(SUM(spend_usd), 2) AS spend_usd, ROUND(SUM(attributed_sales_usd), 2) AS sales_usd "
            "FROM ad_events WHERE advertiser_id = 'adv-summit-gear' "
            "GROUP BY shopper_segment ORDER BY distinct_shoppers DESC"
        )
        res = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            sql=sql,
        )
        self.assertTrue(res["allowed"])
        self.assertEqual(res["verdict"], "REDACTED_K_FLOOR")
        self.assertEqual(res["returned_cohorts_count"], 4)
        self.assertEqual(res["redacted_cohorts_count"], 3)
        self.assertEqual(res["redacted_shoppers_protected"], 14)
        for row in res["rows"]:
            self.assertGreaterEqual(row["distinct_shoppers"], 25)
            self.assertNotIn("user_id", row)
            self.assertNotIn("device_id", row)

    def test_02_cleanroom_blocks_select_star_and_raw_pii(self) -> None:
        attacks = [
            "SELECT * FROM ad_events WHERE advertiser_id = 'adv-summit-gear'",
            "SELECT user_id, device_id, SUM(spend_usd) FROM ad_events GROUP BY user_id, device_id",
            "SELECT SUBSTR(user_id, 1, 6), COUNT(*) FROM ad_events GROUP BY 1",
            "SELECT campaign_id, SUM(spend_usd) FROM ad_events WHERE user_id = 'usr_summit_0001' GROUP BY campaign_id",
        ]
        for bad_sql in attacks:
            res = self.cleanroom.execute_cleanroom_query(
                agency_id="agency-northstar-media",
                advertiser_id="adv-summit-gear",
                sql=bad_sql,
            )
            self.assertFalse(res["allowed"], f"Expected attack to fail: {bad_sql}")
            self.assertEqual(res["rows"], [])
            self.assertIn(res["policy_rule"], ("CR-SQL-WILDCARD-02", "CR-SQL-PII-03"))

    def test_03_cleanroom_blocks_differencing_union_and_having_probes(self) -> None:
        probes = [
            "SELECT shopper_segment, COUNT(DISTINCT user_id) FROM ad_events GROUP BY shopper_segment HAVING COUNT(DISTINCT user_id) < 25",
            "SELECT shopper_segment, COUNT(*) FROM ad_events GROUP BY shopper_segment HAVING COUNT(*) = 1",
            "SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id EXCEPT SELECT campaign_id, SUM(clicks) FROM ad_events GROUP BY campaign_id",
            "SELECT campaign_id, SUM(spend_usd) FROM ad_events GROUP BY campaign_id UNION ALL SELECT campaign_id, 0 FROM campaigns",
            "SELECT shopper_segment, SUM(spend_usd) OVER (ORDER BY campaign_id) FROM ad_events",
        ]
        for probe in probes:
            check = inspect_partner_sql(probe, k_floor=25)
            self.assertFalse(check["allowed"], f"Expected differencing probe to fail: {probe}")
            self.assertEqual(check["policy_rule"], "CR-SQL-DIFF-04")

    def test_04_cross_advertiser_isolation_and_sql_literal_bypass(self) -> None:
        # Direct cross-tenant query on ungranted adv-veloce-audio
        direct = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-veloce-audio",
            sql="SELECT shopper_segment, SUM(spend_usd) FROM ad_events GROUP BY shopper_segment",
        )
        self.assertFalse(direct["allowed"])
        self.assertEqual(direct["verdict"], "BLOCKED_CROSS_TENANT")
        self.assertEqual(direct["policy_rule"], "CR-TENANT-GRANT-06")

        # SQL OR bypass attempt referencing adv-veloce-audio inside adv-summit-gear context
        bypass = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            sql=(
                "SELECT advertiser_id, SUM(spend_usd) FROM ad_events "
                "WHERE advertiser_id = 'adv-summit-gear' OR advertiser_id = 'adv-veloce-audio' "
                "GROUP BY advertiser_id"
            ),
        )
        self.assertFalse(bypass["allowed"])
        self.assertEqual(bypass["verdict"], "BLOCKED_CROSS_TENANT")

    def test_05_live_oauth_grant_revocation_and_restoration(self) -> None:
        sql = "SELECT campaign_id, SUM(clicks) AS clicks FROM ad_events GROUP BY campaign_id"
        ok_before = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            sql=sql,
        )
        self.assertTrue(ok_before["allowed"])

        self.cleanroom.update_grant_status("agency-northstar-media", "adv-summit-gear", "REVOKED")
        blocked = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            sql=sql,
        )
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["policy_rule"], "CR-TENANT-REVOKED-08")

        self.cleanroom.update_grant_status("agency-northstar-media", "adv-summit-gear", "ACTIVE")
        ok_after = self.cleanroom.execute_cleanroom_query(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            sql=sql,
        )
        self.assertTrue(ok_after["allowed"])

    def test_06_model_drift_healthy_shadow_promotes_partner_scorer(self) -> None:
        res = self.drift_guard.evaluate_partner_model(
            model_id="mdl-northstar-roas-v2",
            scenario="healthy_shadow",
            sample_size=5000,
        )
        self.assertFalse(res["circuit_tripped"])
        self.assertEqual(res["verdict"], "PROMOTE_PARTNER_SCORER")
        self.assertEqual(res["active_ranker"], "mdl-northstar-roas-v2")
        self.assertLessEqual(res["metrics"]["max_psi"], 0.25)
        self.assertLessEqual(res["metrics"]["partner_ece"], 0.06)

    def test_07_model_drift_psi_spike_trips_circuit_breaker(self) -> None:
        res = self.drift_guard.evaluate_partner_model(
            model_id="mdl-kestrel-promo-v3",
            scenario="feature_drift_spike",
            sample_size=5000,
        )
        self.assertTrue(res["circuit_tripped"])
        self.assertEqual(res["verdict"], "CIRCUIT_BREAKER_FALLBACK")
        self.assertEqual(res["active_ranker"], "amz-default-calibrated-ecpm-v4")
        self.assertGreater(res["metrics"]["max_psi"], 0.25)

    def test_08_model_drift_calibration_and_latency_breaches_trip_fallback(self) -> None:
        cal = self.drift_guard.evaluate_partner_model(
            model_id="mdl-kestrel-promo-v3",
            scenario="calibration_collapse",
            sample_size=5000,
        )
        self.assertTrue(cal["circuit_tripped"])
        self.assertGreater(cal["metrics"]["partner_ece"], 0.06)

        lat = self.drift_guard.evaluate_partner_model(
            model_id="mdl-acorn-neural-v1",
            scenario="latency_sla_breach",
            sample_size=2000,
        )
        self.assertTrue(lat["circuit_tripped"])
        self.assertGreater(lat["metrics"]["slate_p99_ms"], lat["metrics"]["latency_sla_p99_ms"])

    def test_09_partner_diagnostics_all_five_error_classes(self) -> None:
        expected_codes = {
            "expired_refresh_token_401": "ERR-LWA-401-EXPIRED",
            "missing_advertiser_grant_403": "ERR-GRANT-403-SCOPE",
            "bid_micros_schema_422": "ERR-SCHEMA-422-MICROS",
            "retry_after_429": "ERR-RATE-429-BACKOFF",
            "hmac_webhook_drift": "ERR-HMAC-SIG-DRIFT",
        }
        for issue_key, expected_code in expected_codes.items():
            out = self.diagnostics.diagnose_and_advise(issue_type=issue_key, use_bedrock=False)
            self.assertEqual(out["diagnostic_code"], expected_code)
            self.assertGreaterEqual(len(out["kb_citations"]), 1)
            if issue_key == "bid_micros_schema_422":
                corrected = out["remediation_patch"]["corrected_v3_payload"]
                self.assertEqual(corrected["bid_micros"], 1850000)
                self.assertEqual(corrected["matchType"], "EXACT")

    def test_10_retail_ad_policy_moderation_guardrail(self) -> None:
        bad = verify_retail_ad_policy("Buy the #1 Best Seller Camp Stove Today")
        self.assertFalse(bad["compliant"])
        self.assertNotIn("#1", bad["sanitized_text"])

        good = verify_retail_ad_policy("Ultralight Titanium Camp Stoves for Backcountry Trails")
        self.assertTrue(good["compliant"])

    def test_11_vending_audit_ledger_hash_chain_and_tamper_detection(self) -> None:
        self.ledger.append_event(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            action_type="CLEANROOM_SQL",
            decision="ALLOWED_AGGREGATE",
            policy_rule="CR-SQL-VERIFIED-OK",
            summary="Vended 4 cohorts",
            k_redacted_count=0,
        )
        ok_verify = self.ledger.verify_chain_integrity()
        self.assertTrue(ok_verify["valid"])
        self.assertGreaterEqual(ok_verify["checked_rows"], 4)

        # Mutate a past row directly on disk and prove SHA-256 chain catches tampering
        conn = sqlite3.connect(str(self.ledger.db_path))
        try:
            conn.execute(
                "UPDATE vending_audit_log SET summary = 'Forged clean audit entry' WHERE event_id = 'VND-00002'"
            )
            conn.commit()
        finally:
            conn.close()

        bad_verify = self.ledger.verify_chain_integrity()
        self.assertFalse(bad_verify["valid"])
        self.assertEqual(bad_verify["tampered_event_id"], "VND-00002")

    def test_12_lambda_handler_all_api_routes_end_to_end(self) -> None:
        # 1. Health
        r_health = lambda_handler({"rawPath": "/api/health", "requestContext": {"http": {"method": "GET"}}})
        self.assertEqual(r_health["statusCode"], 200)
        body_health = json.loads(r_health["body"])
        self.assertEqual(body_health["status"], "ok")
        self.assertTrue(body_health["sqlite_audit_chain_valid"])

        # 2. Cleanroom Query
        r_query = lambda_handler(
            {
                "rawPath": "/api/cleanroom/query",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps(
                    {
                        "agency_id": "agency-northstar-media",
                        "advertiser_id": "adv-summit-gear",
                        "sql": "SELECT shopper_segment, SUM(spend_usd) AS spend FROM ad_events GROUP BY shopper_segment",
                    }
                ),
            }
        )
        self.assertEqual(r_query["statusCode"], 200)
        q_payload = json.loads(r_query["body"])
        self.assertTrue(q_payload["allowed"])
        self.assertEqual(q_payload["returned_cohorts_count"], 4)

        # 3. Model Evaluate
        r_model = lambda_handler(
            {
                "rawPath": "/api/models/evaluate",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps({"model_id": "mdl-kestrel-promo-v3", "scenario": "feature_drift_spike", "sample_size": 1000}),
            }
        )
        self.assertEqual(r_model["statusCode"], 200)
        self.assertEqual(json.loads(r_model["body"])["verdict"], "CIRCUIT_BREAKER_FALLBACK")

        # 4. Partner Diagnose (deterministic mode in unit test)
        r_diag = lambda_handler(
            {
                "rawPath": "/api/partner/diagnose",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps({"issue_type": "hmac_webhook_drift", "use_bedrock": False}),
            }
        )
        self.assertEqual(r_diag["statusCode"], 200)
        self.assertEqual(json.loads(r_diag["body"])["diagnostic_code"], "ERR-HMAC-SIG-DRIFT")

        # 5. Audit Verify & Reset
        r_audit = lambda_handler({"rawPath": "/api/audit/verify", "requestContext": {"http": {"method": "GET"}}})
        self.assertEqual(r_audit["statusCode"], 200)
        self.assertTrue(json.loads(r_audit["body"])["audit_chain"]["valid"])

        r_reset = lambda_handler({"rawPath": "/api/reset", "requestContext": {"http": {"method": "POST"}}, "body": "{}"})
        self.assertEqual(r_reset["statusCode"], 200)
        self.assertEqual(json.loads(r_reset["body"])["status"], "reset_complete")


if __name__ == "__main__":
    unittest.main()
