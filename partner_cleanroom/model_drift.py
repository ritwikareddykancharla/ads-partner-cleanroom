"""Partner Custom Bidding Model Registry, Shadow Eval & PSI Drift Circuit-Breaker."""
from __future__ import annotations

import math
import random
import time
from typing import Any, Dict, List, Optional, Tuple

from .vending_ledger import PartnerVendingLedger

PSI_CIRCUIT_THRESHOLD = 0.25
ECE_CIRCUIT_THRESHOLD = 0.060
DEFAULT_SAFE_RANKER_ID = "amz-default-calibrated-ecpm-v4"

FEATURE_NAMES = (
    "shopper_intent_score",
    "historical_category_ctr",
    "price_index_ratio",
    "top_of_search_share",
)


def _sigmoid(x: float) -> float:
    if x >= 0:
        z = math.exp(-x)
        return 1.0 / (1.0 + z)
    z = math.exp(x)
    return z / (1.0 + z)


def _percentile(sorted_vals: List[float], pct: float) -> float:
    if not sorted_vals:
        return 0.0
    idx = (len(sorted_vals) - 1) * (pct / 100.0)
    lo = int(math.floor(idx))
    hi = int(math.ceil(idx))
    if lo == hi:
        return sorted_vals[lo]
    frac = idx - lo
    return sorted_vals[lo] * (1.0 - frac) + sorted_vals[hi] * frac


def compute_psi_10bin(baseline: List[float], live: List[float], bins: int = 10) -> float:
    """Computes 10-bin Population Stability Index (PSI) between baseline and live feature vectors."""
    if not baseline or not live:
        return 0.0
    s_base = sorted(baseline)
    edges = [s_base[int(len(s_base) * b / bins)] for b in range(1, bins)]

    base_counts = [0] * bins
    live_counts = [0] * bins

    def _bin_idx(val: float) -> int:
        for i, edge in enumerate(edges):
            if val <= edge:
                return i
        return bins - 1

    for v in baseline:
        base_counts[_bin_idx(v)] += 1
    for v in live:
        live_counts[_bin_idx(v)] += 1

    n_base = float(len(baseline))
    n_live = float(len(live))
    eps = 1e-4
    psi = 0.0
    for b_cnt, l_cnt in zip(base_counts, live_counts):
        p = max(eps, b_cnt / n_base)
        q = max(eps, l_cnt / n_live)
        psi += (q - p) * math.log(q / p)
    return round(max(0.0, psi), 4)


def compute_ece_and_brier(probs: List[float], labels: List[int], bins: int = 10) -> Tuple[float, float]:
    """Computes 10-bin Expected Calibration Error (ECE) and Brier Score."""
    if not probs or len(probs) != len(labels):
        return 0.0, 0.0
    n = float(len(probs))
    bin_totals = [0] * bins
    bin_prob_sums = [0.0] * bins
    bin_label_sums = [0.0] * bins
    brier_sum = 0.0

    for p, y in zip(probs, labels):
        brier_sum += (p - float(y)) ** 2
        idx = min(bins - 1, max(0, int(p * bins)))
        bin_totals[idx] += 1
        bin_prob_sums[idx] += p
        bin_label_sums[idx] += float(y)

    ece = 0.0
    for cnt, p_sum, y_sum in zip(bin_totals, bin_prob_sums, bin_label_sums):
        if cnt > 0:
            avg_conf = p_sum / cnt
            avg_acc = y_sum / cnt
            ece += (cnt / n) * abs(avg_acc - avg_conf)

    return round(ece, 4), round(brier_sum / n, 4)


class PartnerModelDriftGuard:
    """Registry, shadow impression evaluator, and PSI/ECE/latency fallback circuit-breaker."""

    def __init__(self, ledger: PartnerVendingLedger) -> None:
        self.ledger = ledger
        self._models: Dict[str, Dict[str, Any]] = {}
        self.reset()

    def reset(self) -> None:
        self._models = {
            "mdl-northstar-roas-v2": {
                "model_id": "mdl-northstar-roas-v2",
                "model_name": "Northstar Gradient Conversion Scorer v2.4",
                "agency_id": "agency-northstar-media",
                "advertiser_id": "adv-summit-gear",
                "feature_contract": "vended_sp_cohort_v2",
                "latency_sla_p99_ms": 6.0,
                "default_scenario": "healthy_shadow",
                "status": "ACTIVE_SHADOW_HEALTHY",
                "active_ranker": "mdl-northstar-roas-v2",
                "circuit_open": False,
                "weights": (2.35, 7.80, -1.15, 0.85, -2.15),
            },
            "mdl-kestrel-promo-v3": {
                "model_id": "mdl-kestrel-promo-v3",
                "model_name": "Kestrel Flash-Promo Bid Multiplier v3.1",
                "agency_id": "agency-kestrel-growth",
                "advertiser_id": "adv-veloce-audio",
                "feature_contract": "vended_promo_burst_v3",
                "latency_sla_p99_ms": 6.0,
                "default_scenario": "feature_drift_spike",
                "status": "MONITORING_SHADOW",
                "active_ranker": "mdl-kestrel-promo-v3",
                "circuit_open": False,
                "weights": (2.55, 8.10, -1.35, 0.92, -2.20),
            },
            "mdl-acorn-neural-v1": {
                "model_id": "mdl-acorn-neural-v1",
                "model_name": "Acorn Cross-Category Interaction Scorer v1.8",
                "agency_id": "agency-northstar-media",
                "advertiser_id": "adv-lumina-home",
                "feature_contract": "vended_sb_video_v1",
                "latency_sla_p99_ms": 6.0,
                "default_scenario": "latency_sla_breach",
                "status": "MONITORING_SHADOW",
                "active_ranker": "mdl-acorn-neural-v1",
                "circuit_open": False,
                "weights": (2.20, 7.40, -1.05, 0.78, -2.08),
            },
        }

    def list_models(self) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for m in self._models.values():
            item = {k: v for k, v in m.items() if k != "weights"}
            out.append(item)
        return out

    def _generate_impressions(
        self,
        sample_size: int,
        scenario: str,
        seed: int,
    ) -> Tuple[Dict[str, List[float]], Dict[str, List[float]], List[Tuple[float, float, float, float]], List[int]]:
        rng = random.Random(seed)
        base_feats: Dict[str, List[float]] = {f: [] for f in FEATURE_NAMES}
        live_feats: Dict[str, List[float]] = {f: [] for f in FEATURE_NAMES}
        live_rows: List[Tuple[float, float, float, float]] = []
        labels: List[int] = []

        for _ in range(sample_size):
            # Reference clean-room baseline distribution
            b_intent = min(0.99, max(0.02, rng.betavariate(2.5, 3.2)))
            b_ctr = min(0.22, max(0.005, rng.gauss(0.068, 0.022)))
            b_price = min(1.80, max(0.55, rng.gauss(1.02, 0.16)))
            b_tos = min(0.98, max(0.04, rng.betavariate(2.2, 2.4)))
            base_feats["shopper_intent_score"].append(b_intent)
            base_feats["historical_category_ctr"].append(b_ctr)
            base_feats["price_index_ratio"].append(b_price)
            base_feats["top_of_search_share"].append(b_tos)

            # Live shadow impression stream under selected scenario
            if scenario == "feature_drift_spike":
                l_intent = min(0.99, max(0.01, rng.betavariate(1.2, 5.4)))
                l_ctr = min(0.22, max(0.004, rng.gauss(0.041, 0.024)))
                l_price = min(1.95, max(0.55, rng.gauss(1.29, 0.19)))
                l_tos = min(0.98, max(0.02, rng.betavariate(1.5, 3.8)))
            elif scenario == "calibration_collapse":
                l_intent = min(0.99, max(0.02, rng.betavariate(2.4, 3.3)))
                l_ctr = min(0.22, max(0.005, rng.gauss(0.066, 0.022)))
                l_price = min(1.80, max(0.55, rng.gauss(1.05, 0.16)))
                l_tos = min(0.98, max(0.04, rng.betavariate(2.1, 2.5)))
            else:
                # healthy_shadow or latency_sla_breach (clean feature distribution)
                l_intent = min(0.99, max(0.02, rng.betavariate(2.5, 3.25)))
                l_ctr = min(0.22, max(0.005, rng.gauss(0.067, 0.022)))
                l_price = min(1.80, max(0.55, rng.gauss(1.03, 0.16)))
                l_tos = min(0.98, max(0.04, rng.betavariate(2.2, 2.42)))

            live_feats["shopper_intent_score"].append(l_intent)
            live_feats["historical_category_ctr"].append(l_ctr)
            live_feats["price_index_ratio"].append(l_price)
            live_feats["top_of_search_share"].append(l_tos)
            live_rows.append((l_intent, l_ctr, l_price, l_tos))

            # Ground-truth shopper conversion probability in Sponsored Ads auction
            true_logit = 2.38 * l_intent + 7.75 * l_ctr - 1.18 * l_price + 0.84 * l_tos - 2.16
            true_p = _sigmoid(true_logit)
            y = 1 if rng.random() < true_p else 0
            labels.append(y)

        return base_feats, live_feats, live_rows, labels

    def evaluate_partner_model(
        self,
        model_id: str = "mdl-kestrel-promo-v3",
        scenario: Optional[str] = None,
        sample_size: int = 5000,
    ) -> Dict[str, Any]:
        t_start = time.perf_counter()
        if model_id not in self._models:
            raise KeyError(f"Unknown partner model_id: {model_id}")

        model_meta = self._models[model_id]
        active_scenario = (scenario or model_meta["default_scenario"]).strip()
        if active_scenario not in (
            "healthy_shadow",
            "feature_drift_spike",
            "calibration_collapse",
            "latency_sla_breach",
        ):
            raise ValueError(f"Unsupported evaluation scenario: {active_scenario}")

        sample_n = max(500, min(10000, int(sample_size)))
        seed = sum(ord(c) for c in (model_id + active_scenario)) + 202611
        base_feats, live_feats, live_rows, labels = self._generate_impressions(
            sample_size=sample_n,
            scenario=active_scenario,
            seed=seed,
        )

        # Score live impressions in realistic 100-impression auction candidate slates and measure slate p50/p99 latency
        w0, w1, w2, w3, bias = model_meta["weights"]
        slate_size = 100
        slate_latencies_ms: List[float] = []
        partner_probs: List[float] = []
        default_probs: List[float] = []

        for offset in range(0, len(live_rows), slate_size):
            slate = live_rows[offset : offset + slate_size]
            t_slate = time.perf_counter()
            for l_intent, l_ctr, l_price, l_tos in slate:
                raw_logit = w0 * l_intent + w1 * l_ctr + w2 * l_price + w3 * l_tos + bias
                if active_scenario == "calibration_collapse":
                    # Partner pushed uncalibrated positive logit shift (+1.45) causing severe overbidding
                    raw_logit += 1.45
                elif active_scenario == "feature_drift_spike":
                    # Partner promo model extrapolates poorly when intent drops and price ratio rises
                    raw_logit += 0.92 * (l_price - 1.0) + 0.55
                elif active_scenario == "latency_sla_breach":
                    # Unoptimized deep cross-feature interaction expansion breaching the 6.0 ms auction slate SLA
                    cross_acc = 0.0
                    for k in range(1, 520):
                        cross_acc += math.sin(l_intent * k * 0.01) * math.cos(l_price * k * 0.01)
                    raw_logit += cross_acc * 1e-6

                p_partner = _sigmoid(raw_logit)
                partner_probs.append(p_partner)

                # Safe Amazon Ads default calibrated ranker
                def_logit = 2.35 * l_intent + 7.70 * l_ctr - 1.16 * l_price + 0.82 * l_tos - 2.15
                default_probs.append(_sigmoid(def_logit))

            slate_ms = (time.perf_counter() - t_slate) * 1000.0
            if active_scenario == "latency_sla_breach" and slate_ms < 7.4:
                # Guarantee deterministic cross-hardware SLA breach test even on ultra-wide SIMD silicon
                while (time.perf_counter() - t_slate) * 1000.0 < 7.6:
                    _ = math.sqrt(2.0)
                slate_ms = (time.perf_counter() - t_slate) * 1000.0
            slate_latencies_ms.append(slate_ms)

        sorted_lat = sorted(slate_latencies_ms)
        p50_slate_ms = round(_percentile(sorted_lat, 50.0), 3)
        p99_slate_ms = round(_percentile(sorted_lat, 99.0), 3)

        psi_by_feature = {
            fname: compute_psi_10bin(base_feats[fname], live_feats[fname])
            for fname in FEATURE_NAMES
        }
        max_psi_feature = max(psi_by_feature, key=lambda k: psi_by_feature[k])
        max_psi = psi_by_feature[max_psi_feature]

        partner_ece, partner_brier = compute_ece_and_brier(partner_probs, labels)
        default_ece, default_brier = compute_ece_and_brier(default_probs, labels)

        # Estimate counterfactual ROAS efficiency (value / predicted bid spend)
        partner_spend = sum(max(0.05, p * 12.5) for p in partner_probs)
        default_spend = sum(max(0.05, p * 12.0) for p in default_probs)
        realized_value = sum(48.0 * y for y in labels)
        # Weight value capture by calibration alignment
        partner_roas = round((realized_value * max(0.55, 1.06 - partner_ece * 2.4)) / max(1.0, partner_spend), 2)
        default_roas = round((realized_value * (1.0 - default_ece * 1.2)) / max(1.0, default_spend), 2)

        sla_ms = float(model_meta["latency_sla_p99_ms"])
        breach_reasons: List[str] = []
        if max_psi > PSI_CIRCUIT_THRESHOLD:
            breach_reasons.append(
                f"Feature PSI {max_psi:.3f} on '{max_psi_feature}' exceeded {PSI_CIRCUIT_THRESHOLD:.2f} threshold"
            )
        if partner_ece > ECE_CIRCUIT_THRESHOLD:
            breach_reasons.append(
                f"Calibration ECE {partner_ece:.3f} exceeded {ECE_CIRCUIT_THRESHOLD:.3f} guardrail"
            )
        if p99_slate_ms > sla_ms:
            breach_reasons.append(
                f"Slate p99 latency {p99_slate_ms:.2f} ms breached {sla_ms:.1f} ms auction SLA"
            )

        circuit_tripped = len(breach_reasons) > 0
        if circuit_tripped:
            verdict = "CIRCUIT_BREAKER_FALLBACK"
            policy_rule = "ML-DRIFT-CIRCUIT-TRIP"
            active_ranker = DEFAULT_SAFE_RANKER_ID
            model_meta["status"] = "FALLBACK_TRIPPED"
            model_meta["active_ranker"] = DEFAULT_SAFE_RANKER_ID
            model_meta["circuit_open"] = True
            summary = f"Tripped fallback to {DEFAULT_SAFE_RANKER_ID}: " + "; ".join(breach_reasons)
        else:
            verdict = "PROMOTE_PARTNER_SCORER"
            policy_rule = "ML-SHADOW-HEALTHY-OK"
            active_ranker = model_id
            model_meta["status"] = "ACTIVE_SHADOW_HEALTHY"
            model_meta["active_ranker"] = model_id
            model_meta["circuit_open"] = False
            summary = (
                f"Partner model {model_id} healthy across {sample_n} impressions "
                f"(max PSI={max_psi:.3f}, ECE={partner_ece:.3f}, p99={p99_slate_ms:.2f} ms)"
            )

        total_eval_ms = round((time.perf_counter() - t_start) * 1000.0, 3)
        receipt = self.ledger.append_event(
            agency_id=model_meta["agency_id"],
            advertiser_id=model_meta["advertiser_id"],
            action_type="MODEL_DRIFT_EVAL",
            decision=verdict,
            policy_rule=policy_rule,
            summary=summary,
            k_redacted_count=0,
            privacy_units=1,
            duration_ms=total_eval_ms,
        )

        return {
            "model_id": model_id,
            "model_name": model_meta["model_name"],
            "agency_id": model_meta["agency_id"],
            "advertiser_id": model_meta["advertiser_id"],
            "scenario": active_scenario,
            "impressions_evaluated": sample_n,
            "verdict": verdict,
            "circuit_tripped": circuit_tripped,
            "active_ranker": active_ranker,
            "fallback_ranker": DEFAULT_SAFE_RANKER_ID,
            "breach_reasons": breach_reasons,
            "metrics": {
                "max_psi": max_psi,
                "max_psi_feature": max_psi_feature,
                "psi_threshold": PSI_CIRCUIT_THRESHOLD,
                "psi_by_feature": psi_by_feature,
                "partner_ece": partner_ece,
                "ece_threshold": ECE_CIRCUIT_THRESHOLD,
                "partner_brier": partner_brier,
                "default_ranker_ece": default_ece,
                "default_ranker_brier": default_brier,
                "slate_p50_ms": p50_slate_ms,
                "slate_p99_ms": p99_slate_ms,
                "latency_sla_p99_ms": sla_ms,
                "counterfactual_partner_roas": partner_roas,
                "counterfactual_default_roas": default_roas,
            },
            "eval_duration_ms": total_eval_ms,
            "audit_receipt": receipt,
        }
