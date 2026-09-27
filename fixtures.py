"""Synthetic calls and a deliberately insecure comparison. Never a production policy."""

from __future__ import annotations

from copy import deepcopy
import hashlib
import hmac
import json
import secrets
import tempfile
from pathlib import Path
from typing import Any

from boundary import (
    ApprovalGate, DOMAIN, ReplayLedger, TrustedContext, canonical_json, issue_grant,
)

NOW = 1_790_467_200
AVAILABLE_TOOLS = ["reports.read", "reports.export"]
CONTEXT = {"actor": "analyst:sergio", "audience": "portfolio-research-host"}
PROPOSAL = {
    "tool": "reports.read", "target": "report:call-boundary:public",
    "args": {"format": "summary", "include": {"appendix": False}, "limit": 3},
}


def insecure_tool_name_baseline(proposal: Any) -> dict[str, Any]:
    """Fixture-only failure: availability mistaken for authorization."""
    allowed = type(proposal) is dict and proposal.get("tool") in AVAILABLE_TOOLS
    return {"allowed": allowed,
            "reason": "tool_available" if allowed else "tool_unavailable"}


def _sign_fixture(claims: dict[str, Any], key: bytes) -> str:
    # Allows malformed *signed* claims to test the verifier independently of issuer validation.
    return hmac.new(key, DOMAIN + canonical_json(claims), hashlib.sha256).hexdigest()


def build_vectors() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    # A one-off key is used only to invoke the issuer. No key/signature leaves this function.
    key = secrets.token_bytes(32)

    def case(identifier: str, title: str, description: str, reason: str,
             kind: str = "unauthorized") -> dict[str, Any]:
        nonce = hashlib.sha256(identifier.encode("ascii")).hexdigest()[:32]
        grant = issue_grant(key, TrustedContext(**CONTEXT), deepcopy(PROPOSAL),
                            now=NOW, nonce=nonce)
        item = {
            "id": identifier, "title": title, "kind": kind, "description": description,
            "proposal": deepcopy(PROPOSAL), "trusted_context": deepcopy(CONTEXT),
            "grant_claims": grant["claims"],
            "fixture": {"signature": "valid", "replay": False},
            "expected": {"allowed": reason == "approved", "reason": reason},
        }
        cases.append(item)
        return item

    case("approved-read", "A bounded read", "The approved proposal arrives unchanged.",
         "approved", "benign")
    item = case("key-order", "JSON key order", "Reordering object members preserves intent.",
                "approved", "benign")
    item["proposal"]["args"] = {"limit": 3, "include": {"appendix": False}, "format": "summary"}
    item = case("near-expiry", "Last valid second", "The call arrives one second before expiry.",
                "approved", "benign")
    item["grant_claims"]["issued_at"] = NOW - 59
    item["grant_claims"]["expires_at"] = NOW + 1

    item = case("no-approval", "Available is not approved", "The tool exists, but no grant exists.",
                "grant_invalid")
    item["grant_claims"] = None
    item = case("signature-tamper", "A changed signature", "A well-formed signature has one bit changed.",
                "bad_signature")
    item["fixture"]["signature"] = "tampered"
    item = case("target-swap", "A different report", "A public read is redirected to a private report.",
                "target_mismatch")
    item["proposal"]["target"] = "report:call-boundary:private"
    item = case("target-prefix", "A convincing prefix", "The approved target is only a prefix of the requested target.",
                "target_mismatch")
    item["proposal"]["target"] += ":internal"
    item = case("args-change", "Three becomes thirty", "A numeric argument changes after approval.",
                "args_mismatch")
    item["proposal"]["args"]["limit"] = 30
    item = case("nested-args", "A buried switch", "An appendix switch changes inside a nested object.",
                "args_mismatch")
    item["proposal"]["args"]["include"]["appendix"] = True
    item = case("extra-args", "An added export option", "A new argument was never part of the approval.",
                "args_mismatch")
    item["proposal"]["args"]["destination"] = "archive:external"
    item = case("bool-is-not-int", "False is not zero", "False and zero are distinct JSON values.",
                "args_mismatch")
    item["proposal"]["args"]["include"]["appendix"] = 0
    item = case("tool-swap", "Read becomes export", "Another available tool is substituted.",
                "tool_mismatch")
    item["proposal"]["tool"] = "reports.export"
    item = case("actor-swap", "Another caller", "The authenticated actor differs from the approved actor.",
                "recipient_mismatch")
    item["trusted_context"]["actor"] = "analyst:other"
    item = case("audience-swap", "Another host", "A valid grant is presented to the wrong execution host.",
                "recipient_mismatch")
    item["trusted_context"]["audience"] = "external-research-host"
    item = case("expired", "The expiry boundary", "At expires_at, the grant is already invalid.",
                "grant_expired")
    item["grant_claims"]["issued_at"] = NOW - 60
    item["grant_claims"]["expires_at"] = NOW
    item = case("future", "Not valid yet", "The issuer time is one second ahead of the host clock.",
                "future_grant")
    item["grant_claims"]["issued_at"] = NOW + 1
    item["grant_claims"]["expires_at"] = NOW + 61
    item = case("replay", "A second attempt", "The same nonce was committed by a previous accepted call.",
                "replay")
    item["fixture"]["replay"] = True
    item = case("proposal-extra", "An extra instruction", "Unknown proposal fields are rejected, even with a valid grant.",
                "input_invalid")
    item["proposal"]["override"] = "approved"
    item = case("envelope-extra", "An extended envelope", "Unknown grant-envelope fields are rejected.",
                "grant_invalid")
    item["fixture"]["extra_envelope_field"] = True
    item = case("claims-extra", "An extended claim", "A signed grant with an unknown claim is rejected.",
                "grant_invalid")
    item["grant_claims"]["admin"] = True
    item = case("boolean-time", "True is not a timestamp", "Python's bool-is-int relationship must not reach the policy.",
                "grant_invalid")
    item["grant_claims"]["issued_at"] = True
    item = case("boolean-version", "True is not version one", "A boolean version is not accepted as integer 1.",
                "grant_invalid")
    item["grant_claims"]["version"] = True
    item = case("long-window", "An oversized lifetime", "A signed approval exceeds the 300-second policy limit.",
                "invalid_window")
    item["grant_claims"]["expires_at"] = NOW + 301
    item = case("reversed-window", "Expiry before issuance", "A signed approval has a reversed time interval.",
                "invalid_window")
    item["grant_claims"]["expires_at"] = NOW - 1
    item = case("malformed-signature", "Invalid signature syntax", "A signature with invalid encoding is rejected before verification.",
                "grant_invalid")
    item["fixture"]["signature"] = "malformed"
    item = case("invalid-nonce", "A short nonce", "A signed nonce violates the fixed 128-bit encoding contract.",
                "grant_invalid")
    item["grant_claims"]["nonce"] = "00"
    item = case("null-arguments", "No arguments object", "Null cannot stand in for the approved arguments object.",
                "input_invalid")
    item["proposal"]["args"] = None
    item = case("signed-claim-change", "An edited grant", "A grant target changes without a new signature.",
                "bad_signature")
    item["fixture"]["change_claim_after_signing"] = True
    item = case("unavailable-tool", "An unknown tool", "Both policies reject an unavailable, unapproved tool.",
                "tool_mismatch", "negative_control")
    item["proposal"]["tool"] = "reports.delete"

    for item in cases:
        item["baseline"] = insecure_tool_name_baseline(item["proposal"])
    return {
        "schema_version": 1, "clock": NOW, "available_tools": AVAILABLE_TOOLS,
        "scope": "Synthetic deterministic authorization fixtures; no model or network execution.",
        "scenarios": cases,
    }


def materialize_grant(item: dict[str, Any], key: bytes) -> Any:
    claims = deepcopy(item["grant_claims"])
    if claims is None:
        return None
    signature = _sign_fixture(claims, key)
    mode = item["fixture"]["signature"]
    if mode == "tampered":
        signature = ("0" if signature[0] != "0" else "1") + signature[1:]
    elif mode == "malformed":
        signature = "not-a-signature"
    grant = {"claims": claims, "signature": signature}
    if item["fixture"].get("extra_envelope_field"):
        grant["override"] = True
    if item["fixture"].get("change_claim_after_signing"):
        grant["claims"]["target"] = "report:call-boundary:private"
    return grant


def run_vectors(vectors: dict[str, Any]) -> dict[str, Any]:
    key = secrets.token_bytes(32)
    results = []
    with tempfile.TemporaryDirectory(prefix="call-boundary-") as folder:
        for item in vectors["scenarios"]:
            ledger = ReplayLedger(Path(folder) / (item["id"] + ".sqlite3"))
            gate = ApprovalGate(key, ledger, clock=lambda: vectors["clock"])
            grant = materialize_grant(item, key)
            context = TrustedContext(**item["trusted_context"])
            if item["fixture"]["replay"]:
                first = gate.evaluate(item["proposal"], grant, context)
                if not first.allowed:
                    raise AssertionError("Replay fixture must first have an accepted call.")
                # Re-open the database: this is persisted state, not an in-memory set.
                gate = ApprovalGate(key, ReplayLedger(ledger.path), clock=lambda: vectors["clock"])
            actual = gate.evaluate(item["proposal"], grant, context)
            matched = actual.allowed == item["expected"]["allowed"] and actual.reason == item["expected"]["reason"]
            results.append({
                "id": item["id"], "kind": item["kind"], "baseline": item["baseline"],
                "expected": item["expected"], "actual": actual.to_dict(), "matched_expected": matched,
            })
    unauthorized = [item for item in results if item["kind"] == "unauthorized"]
    benign = [item for item in results if item["kind"] == "benign"]
    return {
        "schema_version": 1, "clock": vectors["clock"],
        "method": "One ephemeral signing key per run; separate persistent SQLite file per scenario.",
        "scope": "Curated local fixtures, not an attack success rate or live-model benchmark.",
        "summary": {
            "scenarios": len(results),
            "matched_expected": sum(item["matched_expected"] for item in results),
            "unauthorized_scenarios": len(unauthorized),
            "baseline_unauthorized_allows": sum(item["baseline"]["allowed"] for item in unauthorized),
            "bounded_unauthorized_allows": sum(item["actual"]["allowed"] for item in unauthorized),
            "benign_scenarios": len(benign),
            "bounded_benign_allows": sum(item["actual"]["allowed"] for item in benign),
        },
        "scenarios": results,
    }


def main() -> int:
    folder = Path(__file__).resolve().parent
    vectors = build_vectors()
    results = run_vectors(vectors)
    for name, document in (("vectors.json", vectors), ("results.json", results)):
        (folder / name).write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(results["summary"]))
    return 0 if all(item["matched_expected"] for item in results["scenarios"]) else 1


if __name__ == "__main__":
    raise SystemExit(main())
