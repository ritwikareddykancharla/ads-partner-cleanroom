"""Tamper-Evident Partner Data Vending & Privacy Budget Audit Log (SQLite WAL + SHA-256 Chain)."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

GENESIS_HASH = "GENESIS_PARTNER_CLEANROOM_0000"
DEFAULT_PRIVACY_BUDGET_UNITS = 250


class PartnerVendingLedger:
    """Append-only SQLite WAL audit ledger chaining every partner query, redaction, and grant event."""

    def __init__(
        self,
        db_path: Optional[Path] = None,
        privacy_budget_units: int = DEFAULT_PRIVACY_BUDGET_UNITS,
    ) -> None:
        base_dir = Path("/tmp/partner-cleanroom")
        base_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = Path(db_path) if db_path else (base_dir / "partner_vending_audit.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.privacy_budget_units = privacy_budget_units
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS vending_audit_log (
                        seq_id INTEGER PRIMARY KEY AUTOINCREMENT,
                        event_id TEXT NOT NULL UNIQUE,
                        timestamp_utc TEXT NOT NULL,
                        agency_id TEXT NOT NULL,
                        advertiser_id TEXT NOT NULL,
                        action_type TEXT NOT NULL,
                        decision TEXT NOT NULL,
                        policy_rule TEXT NOT NULL,
                        k_redacted_count INTEGER NOT NULL DEFAULT 0,
                        privacy_units INTEGER NOT NULL DEFAULT 1,
                        duration_ms REAL NOT NULL DEFAULT 0.0,
                        summary TEXT NOT NULL,
                        prev_hash TEXT NOT NULL,
                        sha256_hash TEXT NOT NULL
                    )
                    """
                )
                conn.commit()
                count = conn.execute("SELECT COUNT(*) AS c FROM vending_audit_log").fetchone()["c"]
            finally:
                conn.close()
        if count == 0:
            self.seed_initial_entries()

    @staticmethod
    def compute_entry_hash(
        event_id: str,
        timestamp_utc: str,
        agency_id: str,
        advertiser_id: str,
        action_type: str,
        decision: str,
        policy_rule: str,
        k_redacted_count: int,
        privacy_units: int,
        summary: str,
        prev_hash: str,
    ) -> str:
        payload = {
            "action_type": str(action_type),
            "advertiser_id": str(advertiser_id),
            "agency_id": str(agency_id),
            "decision": str(decision),
            "event_id": str(event_id),
            "k_redacted_count": int(k_redacted_count),
            "policy_rule": str(policy_rule),
            "prev_hash": str(prev_hash),
            "privacy_units": int(privacy_units),
            "summary": str(summary),
            "timestamp_utc": str(timestamp_utc),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def append_event(
        self,
        agency_id: str,
        advertiser_id: str,
        action_type: str,
        decision: str,
        policy_rule: str,
        summary: str,
        k_redacted_count: int = 0,
        privacy_units: int = 1,
        duration_ms: float = 0.0,
    ) -> Dict[str, Any]:
        with self._lock:
            conn = self._connect()
            try:
                last = conn.execute(
                    "SELECT seq_id, sha256_hash FROM vending_audit_log ORDER BY seq_id DESC LIMIT 1"
                ).fetchone()
                next_seq = (int(last["seq_id"]) + 1) if last else 1
                prev_hash = str(last["sha256_hash"]) if last else GENESIS_HASH
                event_id = f"VND-{next_seq:05d}"
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                digest = self.compute_entry_hash(
                    event_id=event_id,
                    timestamp_utc=ts,
                    agency_id=agency_id,
                    advertiser_id=advertiser_id,
                    action_type=action_type,
                    decision=decision,
                    policy_rule=policy_rule,
                    k_redacted_count=int(k_redacted_count),
                    privacy_units=int(privacy_units),
                    summary=summary,
                    prev_hash=prev_hash,
                )
                conn.execute(
                    """
                    INSERT INTO vending_audit_log (
                        event_id, timestamp_utc, agency_id, advertiser_id,
                        action_type, decision, policy_rule, k_redacted_count,
                        privacy_units, duration_ms, summary, prev_hash, sha256_hash
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        ts,
                        agency_id,
                        advertiser_id,
                        action_type,
                        decision,
                        policy_rule,
                        int(k_redacted_count),
                        int(privacy_units),
                        round(float(duration_ms), 3),
                        summary,
                        prev_hash,
                        digest,
                    ),
                )
                conn.commit()
                return {
                    "event_id": event_id,
                    "timestamp_utc": ts,
                    "agency_id": agency_id,
                    "advertiser_id": advertiser_id,
                    "action_type": action_type,
                    "decision": decision,
                    "policy_rule": policy_rule,
                    "k_redacted_count": int(k_redacted_count),
                    "privacy_units": int(privacy_units),
                    "duration_ms": round(float(duration_ms), 3),
                    "summary": summary,
                    "prev_hash": prev_hash,
                    "sha256_hash": digest,
                }
            finally:
                conn.close()

    def seed_initial_entries(self) -> None:
        self.append_event(
            agency_id="system-control-plane",
            advertiser_id="all-tenants",
            action_type="LEDGER_INIT",
            decision="GENESIS_READY",
            policy_rule="CR-LEDGER-GENESIS-00",
            summary="Initialized SQLite WAL partner vending ledger with k>=25 privacy floor",
            k_redacted_count=0,
            privacy_units=0,
            duration_ms=0.32,
        )
        self.append_event(
            agency_id="agency-northstar-media",
            advertiser_id="adv-summit-gear",
            action_type="CLEANROOM_SQL",
            decision="REDACTED_K_FLOOR",
            policy_rule="CR-K-ANON-FLOOR-07",
            summary="Returned 4 aggregate cohorts (k>=25) and redacted 2 micro-cohorts (<25 shoppers)",
            k_redacted_count=2,
            privacy_units=2,
            duration_ms=1.14,
        )
        self.append_event(
            agency_id="agency-northstar-media",
            advertiser_id="adv-veloce-audio",
            action_type="CLEANROOM_SQL",
            decision="BLOCKED_CROSS_TENANT",
            policy_rule="CR-TENANT-GRANT-06",
            summary="Denied query on ungranted advertiser adv-veloce-audio",
            k_redacted_count=0,
            privacy_units=1,
            duration_ms=0.19,
        )

    def verify_chain_integrity(self) -> Dict[str, Any]:
        t0 = time.perf_counter()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM vending_audit_log ORDER BY seq_id ASC"
                ).fetchall()
            finally:
                conn.close()

        expected_prev = GENESIS_HASH
        total_redacted = 0
        for row in rows:
            total_redacted += int(row["k_redacted_count"])
            if str(row["prev_hash"]) != expected_prev:
                elapsed = round((time.perf_counter() - t0) * 1000.0, 3)
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "verify_ms": elapsed,
                    "genesis_hash": GENESIS_HASH,
                    "tampered_event_id": str(row["event_id"]),
                    "reason": f"Broken prev_hash link at {row['event_id']}",
                }
            recomputed = self.compute_entry_hash(
                event_id=str(row["event_id"]),
                timestamp_utc=str(row["timestamp_utc"]),
                agency_id=str(row["agency_id"]),
                advertiser_id=str(row["advertiser_id"]),
                action_type=str(row["action_type"]),
                decision=str(row["decision"]),
                policy_rule=str(row["policy_rule"]),
                k_redacted_count=int(row["k_redacted_count"]),
                privacy_units=int(row["privacy_units"]),
                summary=str(row["summary"]),
                prev_hash=str(row["prev_hash"]),
            )
            if recomputed != str(row["sha256_hash"]):
                elapsed = round((time.perf_counter() - t0) * 1000.0, 3)
                return {
                    "valid": False,
                    "checked_rows": len(rows),
                    "verify_ms": elapsed,
                    "genesis_hash": GENESIS_HASH,
                    "tampered_event_id": str(row["event_id"]),
                    "expected_hash": recomputed,
                    "stored_hash": str(row["sha256_hash"]),
                    "reason": f"SHA-256 payload mismatch on {row['event_id']}",
                }
            expected_prev = str(row["sha256_hash"])

        elapsed = round((time.perf_counter() - t0) * 1000.0, 3)
        return {
            "valid": True,
            "checked_rows": len(rows),
            "verify_ms": elapsed,
            "genesis_hash": GENESIS_HASH,
            "head_hash": expected_prev,
            "total_k_redactions_logged": total_redacted,
        }

    def list_recent_events(self, limit: int = 25) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM vending_audit_log ORDER BY seq_id DESC LIMIT ?",
                    (int(limit),),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_privacy_budget_summary(self) -> Dict[str, Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """
                    SELECT agency_id,
                           COUNT(*) AS query_events,
                           SUM(privacy_units) AS units_spent,
                           SUM(k_redacted_count) AS cohorts_redacted
                    FROM vending_audit_log
                    WHERE agency_id != 'system-control-plane'
                    GROUP BY agency_id
                    """
                ).fetchall()
            finally:
                conn.close()

        summary: Dict[str, Dict[str, Any]] = {}
        for r in rows:
            spent = int(r["units_spent"] or 0)
            summary[str(r["agency_id"])] = {
                "agency_id": str(r["agency_id"]),
                "query_events": int(r["query_events"] or 0),
                "units_spent": spent,
                "budget_limit": self.privacy_budget_units,
                "units_remaining": max(0, self.privacy_budget_units - spent),
                "cohorts_redacted": int(r["cohorts_redacted"] or 0),
            }
        return summary

    def reset(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.execute("DELETE FROM vending_audit_log")
                conn.execute("DELETE FROM sqlite_sequence WHERE name='vending_audit_log'")
                conn.commit()
            finally:
                conn.close()
        self.seed_initial_entries()
