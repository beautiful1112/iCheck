"""Model-independent, evidence-backed diagnosis and metadata-only repair proposals."""
import re
from urllib.parse import urlencode
from sqlalchemy import select
from ..models import AIModelConfig, AIModelRoute, AIProviderConfig, AuditEvent, Investigation, AIAuthoringQuotaReservation
from ..ai_failure_diagnostics import batch_model, batch_diagnostic, provider_diagnostic, diagnostic, timeout_diagnostic


def diagnose(db, investigation):
    failures = db.scalars(select(AuditEvent).where(AuditEvent.entity_type == "investigation",
        AuditEvent.entity_id == investigation.id, AuditEvent.event_type == "investigation.model.failed")
        .order_by(AuditEvent.occurred_at.desc(), AuditEvent.id.desc()).limit(20)).all()
    evidence = []
    value = None
    failed_model = db.get(AIModelConfig, investigation.model_id)
    for event in failures:
        details = event.details or {}
        candidate = db.get(AIModelConfig, details.get("model_id")) if details.get("model_id") else failed_model
        if isinstance(details.get("diagnostic"), dict):
            value = details["diagnostic"]
        else:
            # Legacy audits retain a safe status-only message; do not rewrite history.
            match = re.search(r"AI provider returned HTTP (\d{3})", str(details.get("error", "")))
            if match: value = provider_diagnostic(int(match[1]), model_name=candidate.model_name if candidate else "")
            elif details.get("error") == "AI provider returned an invalid graph decision":
                value = diagnostic("model_schema_invalid", "Model response failed local Agent validation.",
                    "The retained legacy record proves that the model response was rejected, but the exact field/rule was not retained.",
                    "Use the corrected bounded runtime. Historical responses cannot be reconstructed; no automatic retry is performed.")
                value.update(root_cause_known=False, evidence_source="legacy_model_audit")
        evidence.append({"audit_event_id": event.id, "event_type": event.event_type,
            "occurred_at": event.occurred_at.isoformat(), "candidate_index": details.get("candidate_index"),
            "model_id": details.get("model_id")})
        if value:
            failed_model = candidate; break
    if value is None and failed_model and batch_model(failed_model.model_name):
        value = batch_diagnostic()
    if value is None and (investigation.escalation_reason == "Reasoner failed: TimeoutError"
            or (investigation.escalation_reason or "").startswith("Worker timed out waiting for AI reasoning.")):
        value = timeout_diagnostic(worker=True)
    if value is None:
        value = diagnostic("runtime_diagnosis_incomplete", "No specific provider failure is retained.",
            "The available records do not prove a model/provider root cause.",
            "Inspect execution events and model-call receipts. Do not assume a device connectivity fault.")
    repair = None
    if failed_model:
        provider = db.get(AIProviderConfig, failed_model.provider_id)
        route = db.get(AIModelRoute, investigation.route_id)
        from .openrouter_setup import connection_for
        if provider and (connection_for(db, provider.id) is not None
                         or provider.base_url.rstrip("/") == "https://openrouter.ai/api/v1"):
            proposed = failed_model.model_name[:-6] if batch_model(failed_model.model_name) else None
            query = {"repair_provider": provider.id, "repair_source": investigation.id}
            if proposed: query["repair_model"] = proposed
            repair = {"provider_id": provider.id, "current_model_id": failed_model.id,
                "current_model_name": failed_model.model_name, "proposed_model_name": proposed,
                "purpose": route.purpose if route else None, "requires_human_approval": True,
                "configuration_url": "/settings/ai?" + urlencode(query),
                "steps": ["Review a synchronous model and the affected purpose routes.",
                    "Run the opt-in bounded inference/schema test.",
                    "Explicitly approve model/route replacement; retain previous model history.",
                    "Retry the original task as a new scoped investigation. Device approval remains separate."]}
    receipts = db.scalars(select(AIAuthoringQuotaReservation).where(
        AIAuthoringQuotaReservation.source_entity_type == "investigation",
        AIAuthoringQuotaReservation.source_entity_id == investigation.id,
    )).all()
    reported_tokens = sum(receipt.known_tokens or 0 for receipt in receipts)
    return {"contract": "icheck.ai-self-repair-preview/v1", "investigation_id": investigation.id,
        "diagnostic": value, "evidence": evidence, "repair": repair,
        "model_inference_performed": False, "configuration_changed": False,
        "tool_calls_before_failure": investigation.tool_calls_used,
        "model_usage": {"reported_tokens": reported_tokens, "investigation_tokens": investigation.tokens_used,
            "late_usage_tokens": max(0, reported_tokens - investigation.tokens_used),
            "unresolved_charges": any(receipt.external_charge_unknown for receipt in receipts)}}


def diagnose_for_ai(db, arguments, principal):
    from .authorization_scope import scope_contains
    from .situation_closure_reads import investigation_receipts_visible
    row = db.get(Investigation, arguments["investigation_id"])
    if (row is None or not scope_contains(db, principal, row.authorization_scope)
            or not investigation_receipts_visible(db, row, principal)):
        raise LookupError("Investigation not found")
    return diagnose(db, row), []
