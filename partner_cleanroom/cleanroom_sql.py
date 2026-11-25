"""Multi-Tenant Ads Partner Data Vending & k >= 25 Clean-Room SQL Gateway."""
from __future__ import annotations

import hashlib
import random
import re
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .vending_ledger import PartnerVendingLedger

K_ANONYMITY_FLOOR = 25

FORBIDDEN_DDL_RE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|REPLACE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|ANALYZE|SQLITE_MASTER|SQLITE_SCHEMA|SQLITE_TEMP_MASTER)\b",
    re.IGNORECASE,
)
COMMENT_OR_CHAIN_RE = re.compile(r"(;|--|/\*|\*/)")
WILDCARD_SELECT_RE = re.compile(r"(\bSELECT\s+(?:DISTINCT\s+)?\*|\b[a-zA-Z_][a-zA-Z0-9_]*\s*\.\s*\*)", re.IGNORECASE)
SAFE_DISTINCT_PII_RE = re.compile(
    r"\bCOUNT\s*\(\s*DISTINCT\s+(?:[a-zA-Z_][a-zA-Z0-9_]*\.)?(?:user_id|device_id)\s*\)",
    re.IGNORECASE,
)
RAW_PII_COL_RE = re.compile(
    r"\b(user_id|device_id|ip_hash|household_id|session_token|email_hash)\b",
    re.IGNORECASE,
)
SET_OR_WINDOW_DIFF_RE = re.compile(
    r"\b(UNION|EXCEPT|INTERSECT|OVER)\b",
    re.IGNORECASE,
)
AGGREGATE_FN_RE = re.compile(
    r"\b(SUM|AVG|COUNT|MIN|MAX)\s*\(",
    re.IGNORECASE,
)
ADVERTISER_ID_LITERAL_RE = re.compile(r"adv-[a-z0-9-]+", re.IGNORECASE)
ALLOWED_TABLES = {"ad_events", "campaigns"}


def inspect_partner_sql(sql: str, k_floor: int = K_ANONYMITY_FLOOR) -> Dict[str, Any]:
    """Deterministically inspect partner SQL before execution to prevent raw PII leaks and differencing."""
    t0 = time.perf_counter()
    cleaned = (sql or "").strip()
    if not cleaned:
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-EMPTY-00",
            "reason": "SQL query cannot be empty.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # Allow a single trailing semicolon only if nothing follows, block comments and multi-statement chains
    if cleaned.endswith(";"):
        cleaned = cleaned[:-1].strip()
    if COMMENT_OR_CHAIN_RE.search(cleaned):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DDL-01",
            "reason": "Multi-statement chaining (;) and SQL comment obfuscation (-- or /* */) are blocked.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if not re.match(r"^SELECT\b", cleaned, flags=re.IGNORECASE):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DDL-01",
            "reason": "Only single read-only SELECT queries are permitted in the clean room.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if FORBIDDEN_DDL_RE.search(cleaned):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DDL-01",
            "reason": "DDL, mutation, PRAGMA, and SQLite catalog introspection keywords are blocked.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if WILDCARD_SELECT_RE.search(cleaned):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-WILDCARD-02",
            "reason": "SELECT * wildcard projections are blocked; partners must name explicit aggregate metrics.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # Strip approved COUNT(DISTINCT user_id | device_id) expressions, then scan for any remaining raw PII column usage
    scrubbed_pii = SAFE_DISTINCT_PII_RE.sub("COUNT_DISTINCT_SHOPPERS_OK", cleaned)
    pii_hit = RAW_PII_COL_RE.search(scrubbed_pii)
    if pii_hit:
        col = pii_hit.group(1)
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-PII-03",
            "reason": f"Identifier column '{col}' is blocked outside COUNT(DISTINCT {col}); raw projection, filtering, and slicing are prohibited.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    if SET_OR_WINDOW_DIFF_RE.search(cleaned):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DIFF-04",
            "reason": "Set differencing operators (UNION, EXCEPT, INTERSECT) and window functions (OVER) are blocked to prevent shopper reconstruction.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # Block nested subqueries (a second SELECT token inside FROM/WHERE/HAVING)
    select_tokens = re.findall(r"\bSELECT\b", cleaned, flags=re.IGNORECASE)
    if len(select_tokens) > 1:
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DIFF-04",
            "reason": "Nested subqueries are blocked in clean-room SQL to prevent correlated differencing probes.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # Block HAVING micro-cohort differencing attacks such as HAVING COUNT(DISTINCT user_id) < 25 or HAVING COUNT(*) = 1
    having_match = re.search(r"\bHAVING\b(.+?)(?:\bORDER\s+BY\b|\bLIMIT\b|$)", cleaned, flags=re.IGNORECASE | re.DOTALL)
    if having_match:
        having_expr = having_match.group(1)
        if re.search(r"(<|<=|!=|<>|\bBETWEEN\b|=\s*\d+)", having_expr, flags=re.IGNORECASE):
            # Check if any comparison targets a value below k_floor or uses upper-bound / exact-count isolation
            upper_bound = re.search(r"(<|<=|=)\s*(\d+)", having_expr)
            if upper_bound:
                op, threshold_str = upper_bound.group(1), upper_bound.group(2)
                threshold_val = int(threshold_str)
                if op in ("<", "<=", "=") and threshold_val <= k_floor:
                    return {
                        "allowed": False,
                        "policy_rule": "CR-SQL-DIFF-04",
                        "reason": f"Differencing attack blocked: HAVING clause attempts to isolate micro-cohorts ({op} {threshold_val}) below the k >= {k_floor} floor.",
                        "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                    }
            if re.search(r"\bBETWEEN\b", having_expr, flags=re.IGNORECASE):
                return {
                    "allowed": False,
                    "policy_rule": "CR-SQL-DIFF-04",
                    "reason": "HAVING BETWEEN range probes are blocked to prevent bounded cohort differencing.",
                    "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
                }

    # Require aggregate functions so raw event rows cannot be enumerated
    if not AGGREGATE_FN_RE.search(cleaned):
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-AGG-05",
            "reason": "Clean-room queries must compute aggregate metrics (SUM, AVG, COUNT) rather than enumerating event rows.",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }

    # Verify referenced tables after FROM / JOIN
    table_refs = re.findall(r"\b(?:FROM|JOIN)\s+([a-zA-Z_][a-zA-Z0-9_]*)", cleaned, flags=re.IGNORECASE)
    if not table_refs:
        return {
            "allowed": False,
            "policy_rule": "CR-SQL-DDL-01",
            "reason": " Clean-room SELECT must query an approved table (ad_events or campaigns).",
            "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
        }
    for tbl in table_refs:
        if tbl.lower() not in ALLOWED_TABLES:
            return {
                "allowed": False,
                "policy_rule": "CR-SQL-DDL-01",
                "reason": f"Table '{tbl}' is not an approved clean-room dataset.",
                "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
            }

    referenced_advertisers = sorted({m.lower() for m in ADVERTISER_ID_LITERAL_RE.findall(cleaned)})
    return {
        "allowed": True,
        "policy_rule": "CR-SQL-VERIFIED-OK",
        "normalized_sql": cleaned,
        "referenced_advertisers": referenced_advertisers,
        "eval_ms": round((time.perf_counter() - t0) * 1000.0, 3),
    }


def _inject_k_counter_and_tenant_views(normalized_sql: str) -> str:
    """Injects __cr_k_users = COUNT(DISTINCT user_id) and rewrites table refs to tenant-isolated CTEs."""
    # Find first top-level FROM keyword
    from_match = re.search(r"\bFROM\b", normalized_sql, flags=re.IGNORECASE)
    if not from_match:
        raise ValueError("Missing FROM clause in clean-room query")
    select_part = normalized_sql[: from_match.start()].rstrip()
    rest_part = normalized_sql[from_match.start() :]

    # Rewrite table identifiers ad_events -> tenant_ad_events, campaigns -> tenant_campaigns
    rewritten_rest = re.sub(r"\bad_events\b", "tenant_ad_events", rest_part, flags=re.IGNORECASE)
    rewritten_rest = re.sub(r"\bcampaigns\b", "tenant_campaigns", rewritten_rest, flags=re.IGNORECASE)
    rewritten_select = re.sub(r"\bad_events\.", "tenant_ad_events.", select_part, flags=re.IGNORECASE)
    rewritten_select = re.sub(r"\bcampaigns\.", "tenant_campaigns.", rewritten_select, flags=re.IGNORECASE)

    # Determine whether tenant_ad_events is present so we can count distinct user_id accurately
    uses_ad_events = bool(re.search(r"\btenant_ad_events\b", rewritten_rest, flags=re.IGNORECASE))
    if uses_ad_events:
        k_expr = ", COUNT(DISTINCT user_id) AS __cr_k_users "
    else:
        k_expr = ", 25 AS __cr_k_users "

    return f"{rewritten_select}{k_expr}{rewritten_rest}"


class CleanRoomSQLGateway:
    """Multi-tenant Ads Partner Data Vending & k >= 25 Clean-Room SQL Gateway backed by SQLite."""

    def __init__(
        self,
        ledger: PartnerVendingLedger,
        db_path: Optional[Path] = None,
        k_floor: int = K_ANONYMITY_FLOOR,
    ) -> None:
        base_dir = Path("/tmp/partner-cleanroom")
        base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else (base_dir / "partner_vending_cleanroom.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.ledger = ledger
        self.k_floor = k_floor
        self._lock = threading.Lock()
        self._seed_database()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _seed_database(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS advertisers (
                        advertiser_id TEXT PRIMARY KEY,
                        brand_name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        marketplace TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS agency_delegation_grants (
                        grant_id TEXT PRIMARY KEY,
                        agency_id TEXT NOT NULL,
                        agency_name TEXT NOT NULL,
                        advertiser_id TEXT NOT NULL,
                        scopes_json TEXT NOT NULL,
                        status TEXT NOT NULL,
                        expires_epoch INTEGER NOT NULL,
                        UNIQUE(agency_id, advertiser_id)
                    );

                    CREATE TABLE IF NOT EXISTS campaigns (
                        campaign_id TEXT PRIMARY KEY,
                        advertiser_id TEXT NOT NULL,
                        campaign_name TEXT NOT NULL,
                        campaign_type TEXT NOT NULL,
                        daily_budget_usd REAL NOT NULL,
                        target_roas REAL NOT NULL,
                        default_bid_micros INTEGER NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS ad_events (
                        event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        advertiser_id TEXT NOT NULL,
                        campaign_id TEXT NOT NULL,
                        campaign_type TEXT NOT NULL,
                        asin TEXT NOT NULL,
                        keyword_term TEXT NOT NULL,
                        match_type TEXT NOT NULL,
                        shopper_segment TEXT NOT NULL,
                        placement TEXT NOT NULL,
                        user_id TEXT NOT NULL,
                        device_id TEXT NOT NULL,
                        impressions INTEGER NOT NULL,
                        clicks INTEGER NOT NULL,
                        spend_usd REAL NOT NULL,
                        attributed_sales_usd REAL NOT NULL,
                        conversions INTEGER NOT NULL
                    );
                    """
                )
                existing = conn.execute("SELECT COUNT(*) AS c FROM ad_events").fetchone()["c"]
                if existing == 0:
                    self._populate_seed_rows(conn)
                conn.commit()
            finally:
                conn.close()

    def _populate_seed_rows(self, conn: sqlite3.Connection) -> None:
        advertisers = [
            ("adv-summit-gear", "Summit Trail Gear", "Outdoor & Camping", "US"),
            ("adv-lumina-home", "Lumina Smart Home", "Connected Lighting & Kitchen", "US"),
            ("adv-veloce-audio", "Veloce Acoustics", "Wireless Studio Audio", "US"),
        ]
        conn.executemany("INSERT OR REPLACE INTO advertisers VALUES (?, ?, ?, ?)", advertisers)

        self._reset_grants_in_conn(conn)

        campaigns = [
            ("cmp-sp-trailpacks", "adv-summit-gear", "SP Exact Ultralight Backpacks", "SPONSORED_PRODUCTS", 420.0, 4.2, 1650000),
            ("cmp-sb-campstove", "adv-summit-gear", "SB Video Titanium Camp Stoves", "SPONSORED_BRANDS", 310.0, 3.8, 2150000),
            ("cmp-sp-broad-gear", "adv-summit-gear", "SP Broad Outdoor Discovery", "SPONSORED_PRODUCTS", 260.0, 2.5, 1950000),
            ("cmp-sp-smartbulbs", "adv-lumina-home", "SP Matter Wi-Fi Dimmer Bulbs", "SPONSORED_PRODUCTS", 380.0, 4.5, 1450000),
            ("cmp-sb-kitchenhub", "adv-lumina-home", "SB Countertop Espresso & Lighting", "SPONSORED_BRANDS", 290.0, 3.6, 1850000),
            ("cmp-sp-anc-buds", "adv-veloce-audio", "SP Lossless ANC Earbuds", "SPONSORED_PRODUCTS", 510.0, 4.8, 2350000),
            ("cmp-sb-studiomon", "adv-veloce-audio", "SB Planar Studio Headphones", "SPONSORED_BRANDS", 340.0, 4.0, 2600000),
        ]
        conn.executemany("INSERT OR REPLACE INTO campaigns VALUES (?, ?, ?, ?, ?, ?, ?)", campaigns)

        rng = random.Random(20261125)
        rows: List[Tuple[Any, ...]] = []

        # Cohort definitions: (advertiser_id, shopper_segment, distinct_users, campaign_pool, keyword_pool, conv_rate, roas_mult)
        # Includes both safe cohorts (k >= 25) and niche micro-cohorts (k < 25) to prove real k-anonymity redaction!
        cohort_specs = [
            # adv-summit-gear: 4 safe cohorts (142, 96, 64, 52) + 3 sub-k micro-cohorts (9, 4, 1)
            ("adv-summit-gear", "outdoor_enthusiasts", 142, ["cmp-sp-trailpacks", "cmp-sb-campstove"], [("ultralight hiking backpack 45l", "EXACT", "B0SUMMIT01"), ("waterproof trekking pack", "EXACT", "B0SUMMIT02")], 0.145, 4.85),
            ("adv-summit-gear", "weekend_campers", 96, ["cmp-sb-campstove", "cmp-sp-trailpacks"], [("titanium pocket camp stove", "PHRASE", "B0SUMMIT03"), ("backcountry cookware set", "EXACT", "B0SUMMIT04")], 0.118, 4.12),
            ("adv-summit-gear", "trail_runners", 64, ["cmp-sp-trailpacks", "cmp-sp-broad-gear"], [("hydration running vest", "EXACT", "B0SUMMIT05"), ("free outdoor map pdf", "BROAD", "B0SUMMIT01")], 0.082, 2.74),
            ("adv-summit-gear", "seasonal_gift_shoppers", 52, ["cmp-sp-broad-gear"], [("camping gift ideas", "BROAD", "B0SUMMIT03"), ("cheap tent repair tape", "BROAD", "B0SUMMIT04")], 0.048, 1.58),
            ("adv-summit-gear", "vip_repeat_trek_buyers", 9, ["cmp-sp-trailpacks"], [("alpine expedition bivy", "EXACT", "B0SUMMIT02")], 0.28, 6.40),
            ("adv-summit-gear", "ultra_narrow_zip_98101", 4, ["cmp-sb-campstove"], [("cascade pass stove fuel", "EXACT", "B0SUMMIT03")], 0.25, 5.90),
            ("adv-summit-gear", "single_household_retarget", 1, ["cmp-sp-trailpacks"], [("custom serial pack replacement", "EXACT", "B0SUMMIT01")], 0.50, 8.20),

            # adv-lumina-home: 3 safe cohorts (118, 84, 46) + 2 sub-k micro-cohorts (11, 3)
            ("adv-lumina-home", "prime_home_upgraders", 118, ["cmp-sp-smartbulbs", "cmp-sb-kitchenhub"], [("matter smart led bulb 4-pack", "EXACT", "B0LUMINA01"), ("voice dimmer switch", "EXACT", "B0LUMINA02")], 0.152, 5.10),
            ("adv-lumina-home", "smart_kitchen_builders", 84, ["cmp-sb-kitchenhub"], [("under cabinet warm led strip", "PHRASE", "B0LUMINA03"), ("smart espresso timer plug", "EXACT", "B0LUMINA04")], 0.112, 3.95),
            ("adv-lumina-home", "apartment_renters", 46, ["cmp-sp-smartbulbs"], [("plug in sunset lamp", "BROAD", "B0LUMINA01"), ("diy wiring schematic", "BROAD", "B0LUMINA02")], 0.064, 2.15),
            ("adv-lumina-home", "beta_matter_testers", 11, ["cmp-sp-smartbulbs"], [("thread border router bulb", "EXACT", "B0LUMINA01")], 0.24, 5.80),
            ("adv-lumina-home", "penthouse_custom_install", 3, ["cmp-sb-kitchenhub"], [("architectural recessed kit", "EXACT", "B0LUMINA03")], 0.33, 6.90),

            # adv-veloce-audio (competitor tenant NOT granted to agency-northstar-media): 3 safe cohorts + 1 sub-k
            ("adv-veloce-audio", "audiophile_commuters", 128, ["cmp-sp-anc-buds"], [("aptx lossless anc earbuds", "EXACT", "B0VELOCE01"), ("multipoint bluetooth earbuds", "EXACT", "B0VELOCE02")], 0.162, 5.45),
            ("adv-veloce-audio", "home_studio_creators", 76, ["cmp-sb-studiomon"], [("planar magnetic studio headphones", "EXACT", "B0VELOCE03"), ("open back mixing headset", "PHRASE", "B0VELOCE04")], 0.129, 4.60),
            ("adv-veloce-audio", "podcast_editors", 39, ["cmp-sb-studiomon", "cmp-sp-anc-buds"], [("low latency monitoring headphones", "PHRASE", "B0VELOCE03")], 0.095, 3.55),
            ("adv-veloce-audio", "mastering_engineer_vip", 6, ["cmp-sb-studiomon"], [("reference mastering planar", "EXACT", "B0VELOCE04")], 0.30, 7.10),
        ]

        placements = ["TOP_OF_SEARCH", "PRODUCT_PAGE", "REST_OF_SEARCH"]
        cmp_type_map = {c[0]: c[3] for c in campaigns}

        for adv_id, segment, n_users, cmp_pool, kw_pool, conv_rate, roas_mult in cohort_specs:
            seg_slug = segment[:10]
            for u_idx in range(n_users):
                uid = f"usr_{adv_id.split('-')[1]}_{seg_slug}_{u_idx:04d}"
                did = f"dev_{hashlib.sha1(uid.encode('utf-8')).hexdigest()[:10]}"
                events_for_user = 2 if n_users >= 25 else 3
                for _ in range(events_for_user):
                    cmp_id = rng.choice(cmp_pool)
                    kw_term, match_type, asin = rng.choice(kw_pool)
                    placement = rng.choice(placements)
                    impr = rng.randint(14, 65)
                    clicks = max(1, int(round(impr * rng.uniform(0.025, 0.085))))
                    cpc = rng.uniform(1.15, 2.35) if match_type != "BROAD" else rng.uniform(1.45, 2.65)
                    spend = round(clicks * cpc, 2)
                    conv = 1 if rng.random() < min(0.85, conv_rate * clicks * 0.48) else 0
                    if match_type == "BROAD" and "free" in kw_term:
                        conv = 0
                    sales = round(spend * roas_mult * rng.uniform(0.82, 1.24), 2) if conv > 0 else 0.0
                    rows.append(
                        (
                            adv_id,
                            cmp_id,
                            cmp_type_map[cmp_id],
                            asin,
                            kw_term,
                            match_type,
                            segment,
                            placement,
                            uid,
                            did,
                            impr,
                            clicks,
                            spend,
                            sales,
                            conv,
                        )
                    )

        conn.executemany(
            """
            INSERT INTO ad_events (
                advertiser_id, campaign_id, campaign_type, asin, keyword_term,
                match_type, shopper_segment, placement, user_id, device_id,
                impressions, clicks, spend_usd, attributed_sales_usd, conversions
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )

    def _reset_grants_in_conn(self, conn: sqlite3.Connection) -> None:
        now_ts = int(time.time())
        grants = [
            (
                "grt-ns-summit-01",
                "agency-northstar-media",
                "Northstar Retail Media Agency",
                "adv-summit-gear",
                '["campaign:read","cohort:aggregate","attribution:read","bid:recommend"]',
                "ACTIVE",
                now_ts + 86400 * 30,
            ),
            (
                "grt-ns-lumina-02",
                "agency-northstar-media",
                "Northstar Retail Media Agency",
                "adv-lumina-home",
                '["campaign:read","cohort:aggregate","attribution:read"]',
                "ACTIVE",
                now_ts + 86400 * 30,
            ),
            (
                "grt-ks-veloce-03",
                "agency-kestrel-growth",
                "Kestrel Performance Partners",
                "adv-veloce-audio",
                '["campaign:read","cohort:aggregate","bid:recommend"]',
                "ACTIVE",
                now_ts + 86400 * 30,
            ),
            (
                "grt-rv-summit-04",
                "agency-revoked-bidops",
                "Legacy BidOps Integrator",
                "adv-summit-gear",
                '["campaign:read","cohort:aggregate"]',
                "REVOKED",
                now_ts - 7200,
            ),
        ]
        conn.execute("DELETE FROM agency_delegation_grants")
        conn.executemany(
            "INSERT INTO agency_delegation_grants VALUES (?, ?, ?, ?, ?, ?, ?)",
            grants,
        )

    def reset_grants(self) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                self._reset_grants_in_conn(conn)
                conn.commit()
            finally:
                conn.close()
        return self.list_grants()

    def list_grants(self) -> List[Dict[str, Any]]:
        import json

        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT g.*, a.brand_name, a.category
                    FROM agency_delegation_grants g
                    LEFT JOIN advertisers a ON a.advertiser_id = g.advertiser_id
                    ORDER BY g.grant_id ASC
                    """
                ).fetchall()
            finally:
                conn.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            item = dict(r)
            item["scopes"] = json.loads(item.pop("scopes_json", "[]"))
            out.append(item)
        return out

    def update_grant_status(self, agency_id: str, advertiser_id: str, new_status: str) -> Dict[str, Any]:
        t0 = time.perf_counter()
        normalized_status = new_status.upper().strip()
        if normalized_status not in ("ACTIVE", "REVOKED"):
            raise ValueError("new_status must be ACTIVE or REVOKED")

        now_ts = int(time.time())
        new_exp = (now_ts + 86400 * 30) if normalized_status == "ACTIVE" else (now_ts - 60)

        with self._lock:
            conn = self._connect()
            try:
                cur = conn.execute(
                    """
                    UPDATE agency_delegation_grants
                    SET status = ?, expires_epoch = ?
                    WHERE agency_id = ? AND advertiser_id = ?
                    """,
                    (normalized_status, new_exp, agency_id, advertiser_id),
                )
                conn.commit()
                updated = cur.rowcount
            finally:
                conn.close()

        if updated == 0:
            raise KeyError(f"No delegation grant found for {agency_id} -> {advertiser_id}")

        elapsed = round((time.perf_counter() - t0) * 1000.0, 3)
        action_type = "GRANT_REVOKED" if normalized_status == "REVOKED" else "GRANT_RESTORED"
        rule = "CR-TENANT-REVOKED-08" if normalized_status == "REVOKED" else "CR-TENANT-GRANT-06"
        receipt = self.ledger.append_event(
            agency_id=agency_id,
            advertiser_id=advertiser_id,
            action_type=action_type,
            decision=normalized_status,
            policy_rule=rule,
            summary=f"Advertiser {advertiser_id} set OAuth delegation grant for {agency_id} to {normalized_status}",
            k_redacted_count=0,
            privacy_units=0,
            duration_ms=elapsed,
        )
        return {
            "agency_id": agency_id,
            "advertiser_id": advertiser_id,
            "status": normalized_status,
            "duration_ms": elapsed,
            "audit_receipt": receipt,
            "grants": self.list_grants(),
        }

    def check_delegation(
        self,
        agency_id: str,
        advertiser_id: str,
        required_scope: str = "cohort:aggregate",
    ) -> Dict[str, Any]:
        import json

        now_ts = int(time.time())
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    """
                    SELECT * FROM agency_delegation_grants
                    WHERE agency_id = ? AND advertiser_id = ?
                    """,
                    (agency_id, advertiser_id),
                ).fetchone()
            finally:
                conn.close()

        if not row:
            return {
                "authorized": False,
                "policy_rule": "CR-TENANT-GRANT-06",
                "reason": f"Agency '{agency_id}' holds no delegation grant for advertiser '{advertiser_id}'.",
            }
        status = str(row["status"]).upper()
        exp = int(row["expires_epoch"])
        scopes = json.loads(str(row["scopes_json"]))
        if status != "ACTIVE" or exp <= now_ts:
            return {
                "authorized": False,
                "policy_rule": "CR-TENANT-REVOKED-08",
                "grant_id": str(row["grant_id"]),
                "grant_status": status,
                "reason": f"Delegation grant '{row['grant_id']}' for '{advertiser_id}' is {status} or expired.",
            }
        if required_scope and required_scope not in scopes:
            return {
                "authorized": False,
                "policy_rule": "CR-TENANT-GRANT-06",
                "grant_id": str(row["grant_id"]),
                "grant_status": status,
                "reason": f"Delegation grant '{row['grant_id']}' lacks required scope '{required_scope}'.",
            }
        return {
            "authorized": True,
            "policy_rule": "CR-TENANT-GRANT-OK",
            "grant_id": str(row["grant_id"]),
            "grant_status": status,
            "scopes": scopes,
        }

    def execute_cleanroom_query(
        self,
        agency_id: str,
        advertiser_id: str,
        sql: str,
    ) -> Dict[str, Any]:
        t0 = time.perf_counter()
        agency_clean = (agency_id or "").strip()
        adv_clean = (advertiser_id or "").strip()

        # 1. Verify OAuth Agency -> Advertiser Delegation Grant first
        grant_check = self.check_delegation(
            agency_id=agency_clean,
            advertiser_id=adv_clean,
            required_scope="cohort:aggregate",
        )
        if not grant_check["authorized"]:
            total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            receipt = self.ledger.append_event(
                agency_id=agency_clean or "unknown-agency",
                advertiser_id=adv_clean or "unknown-advertiser",
                action_type="CLEANROOM_SQL",
                decision="BLOCKED_CROSS_TENANT",
                policy_rule=grant_check["policy_rule"],
                summary=grant_check["reason"],
                k_redacted_count=0,
                privacy_units=1,
                duration_ms=total_ms,
            )
            return {
                "allowed": False,
                "verdict": "BLOCKED_CROSS_TENANT",
                "policy_rule": grant_check["policy_rule"],
                "reason": grant_check["reason"],
                "agency_id": agency_clean,
                "advertiser_id": adv_clean,
                "k_floor": self.k_floor,
                "rows": [],
                "returned_cohorts_count": 0,
                "redacted_cohorts_count": 0,
                "redacted_shoppers_protected": 0,
                "cross_tenant_leak_rows": 0,
                "sub_k_leak_rows": 0,
                "policy_eval_ms": total_ms,
                "total_ms": total_ms,
                "audit_receipt": receipt,
            }

        # 2. Inspect SQL AST / tokens before touching SQLite
        sql_check = inspect_partner_sql(sql, k_floor=self.k_floor)
        if not sql_check["allowed"]:
            total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            receipt = self.ledger.append_event(
                agency_id=agency_clean,
                advertiser_id=adv_clean,
                action_type="CLEANROOM_SQL",
                decision="BLOCKED_POLICY",
                policy_rule=sql_check["policy_rule"],
                summary=sql_check["reason"],
                k_redacted_count=0,
                privacy_units=1,
                duration_ms=total_ms,
            )
            return {
                "allowed": False,
                "verdict": "BLOCKED_POLICY",
                "policy_rule": sql_check["policy_rule"],
                "reason": sql_check["reason"],
                "agency_id": agency_clean,
                "advertiser_id": adv_clean,
                "k_floor": self.k_floor,
                "rows": [],
                "returned_cohorts_count": 0,
                "redacted_cohorts_count": 0,
                "redacted_shoppers_protected": 0,
                "cross_tenant_leak_rows": 0,
                "sub_k_leak_rows": 0,
                "policy_eval_ms": sql_check["eval_ms"],
                "total_ms": total_ms,
                "audit_receipt": receipt,
            }

        # 3. Verify SQL string does not reference any other advertiser literal outside the target grant
        for ref_adv in sql_check["referenced_advertisers"]:
            if ref_adv != adv_clean.lower():
                reason = (
                    f"Cross-advertiser SQL literal '{ref_adv}' blocked: query context is bound exclusively to '{adv_clean}'."
                )
                total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
                receipt = self.ledger.append_event(
                    agency_id=agency_clean,
                    advertiser_id=ref_adv,
                    action_type="CLEANROOM_SQL",
                    decision="BLOCKED_CROSS_TENANT",
                    policy_rule="CR-TENANT-GRANT-06",
                    summary=reason,
                    k_redacted_count=0,
                    privacy_units=1,
                    duration_ms=total_ms,
                )
                return {
                    "allowed": False,
                    "verdict": "BLOCKED_CROSS_TENANT",
                    "policy_rule": "CR-TENANT-GRANT-06",
                    "reason": reason,
                    "agency_id": agency_clean,
                    "advertiser_id": adv_clean,
                    "k_floor": self.k_floor,
                    "rows": [],
                    "returned_cohorts_count": 0,
                    "redacted_cohorts_count": 0,
                    "redacted_shoppers_protected": 0,
                    "cross_tenant_leak_rows": 0,
                    "sub_k_leak_rows": 0,
                    "policy_eval_ms": sql_check["eval_ms"],
                    "total_ms": total_ms,
                    "audit_receipt": receipt,
                }

        # 4. Execute inside tenant-bound CTEs and enforce k >= 25 cohort floor on every returned row
        rewritten_select = _inject_k_counter_and_tenant_views(sql_check["normalized_sql"])
        cte_sql = (
            "WITH tenant_ad_events AS ("
            "SELECT * FROM ad_events WHERE advertiser_id = ?"
            "), tenant_campaigns AS ("
            "SELECT * FROM campaigns WHERE advertiser_id = ?"
            ") "
            + rewritten_select
        )

        try:
            with self._lock:
                conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5.0)
                conn.row_factory = sqlite3.Row
                try:
                    raw_rows = conn.execute(cte_sql, (adv_clean, adv_clean)).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
            return {
                "allowed": False,
                "verdict": "BLOCKED_SQL_SYNTAX",
                "policy_rule": "CR-SQL-SYNTAX-09",
                "reason": f"SQLite clean-room execution rejected query syntax: {exc}",
                "agency_id": agency_clean,
                "advertiser_id": adv_clean,
                "k_floor": self.k_floor,
                "rows": [],
                "returned_cohorts_count": 0,
                "redacted_cohorts_count": 0,
                "redacted_shoppers_protected": 0,
                "cross_tenant_leak_rows": 0,
                "sub_k_leak_rows": 0,
                "policy_eval_ms": sql_check["eval_ms"],
                "total_ms": total_ms,
            }

        safe_rows: List[Dict[str, Any]] = []
        redacted_cohorts_count = 0
        redacted_shoppers_protected = 0

        for r in raw_rows:
            row_dict = dict(r)
            k_users = int(row_dict.pop("__cr_k_users", 0) or 0)
            if k_users < self.k_floor:
                redacted_cohorts_count += 1
                redacted_shoppers_protected += k_users
                continue
            if "distinct_shoppers" not in row_dict and "unique_users" not in row_dict:
                row_dict["distinct_shoppers"] = k_users
            for key, val in list(row_dict.items()):
                if isinstance(val, float):
                    row_dict[key] = round(val, 4)
            safe_rows.append(row_dict)

        total_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        verdict = "REDACTED_K_FLOOR" if redacted_cohorts_count > 0 else "ALLOWED_AGGREGATE"
        rule = "CR-K-ANON-FLOOR-07" if redacted_cohorts_count > 0 else "CR-SQL-VERIFIED-OK"
        summary = (
            f"Vended {len(safe_rows)} cohort(s) with k>={self.k_floor}; redacted {redacted_cohorts_count} cohort(s) ({redacted_shoppers_protected} shoppers protected)"
        )
        receipt = self.ledger.append_event(
            agency_id=agency_clean,
            advertiser_id=adv_clean,
            action_type="CLEANROOM_SQL",
            decision=verdict,
            policy_rule=rule,
            summary=summary,
            k_redacted_count=redacted_cohorts_count,
            privacy_units=2 if redacted_cohorts_count > 0 else 1,
            duration_ms=total_ms,
        )

        return {
            "allowed": True,
            "verdict": verdict,
            "policy_rule": rule,
            "reason": summary,
            "agency_id": agency_clean,
            "advertiser_id": adv_clean,
            "grant_id": grant_check["grant_id"],
            "k_floor": self.k_floor,
            "rows": safe_rows,
            "returned_cohorts_count": len(safe_rows),
            "redacted_cohorts_count": redacted_cohorts_count,
            "redacted_shoppers_protected": redacted_shoppers_protected,
            "cross_tenant_leak_rows": 0,
            "sub_k_leak_rows": 0,
            "policy_eval_ms": sql_check["eval_ms"],
            "total_ms": total_ms,
            "audit_receipt": receipt,
        }

    def get_authorized_campaign_insights(self, agency_id: str, advertiser_id: str) -> List[Dict[str, Any]]:
        """Helper used by Partner API & Campaign Advisor to pull k>=25 campaign cohorts safely."""
        sql = (
            "SELECT c.campaign_id, c.campaign_name, c.campaign_type, a.keyword_term, a.match_type, "
            "COUNT(DISTINCT a.user_id) AS distinct_shoppers, "
            "SUM(a.impressions) AS impressions, SUM(a.clicks) AS clicks, "
            "ROUND(SUM(a.spend_usd), 2) AS spend_usd, "
            "ROUND(SUM(a.attributed_sales_usd), 2) AS sales_usd, "
            "SUM(a.conversions) AS conversions "
            "FROM ad_events a JOIN campaigns c ON a.campaign_id = c.campaign_id "
            "GROUP BY c.campaign_id, c.campaign_name, c.campaign_type, a.keyword_term, a.match_type "
            "ORDER BY spend_usd DESC"
        )
        res = self.execute_cleanroom_query(agency_id=agency_id, advertiser_id=advertiser_id, sql=sql)
        return res.get("rows", [])
