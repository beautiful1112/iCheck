"""Constrain upstream series before PromQL joins, functions and aggregation.

Prometheus itself is a trusted evaluator, not an authorization service. Its
ingestion labels must be assigned by a trusted gateway/operator. Filtering
returned aggregates cannot repair an unscoped upstream query.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

import promql_parser as promql
from sqlalchemy.orm import Session

from ..database import (
    DEFAULT_REGION_ID,
    DEFAULT_TENANT_ID,
    require_locking_transaction,
    session_namespace,
)
from ..models import MetricBackend
from .authorization_scope import authorized_device_ids_query, has_global_scope
from .control_plane_auth import PrincipalContext

TENANT_LABEL = "icheck_tenant_id"
REGION_LABEL = "icheck_region_id"
DEVICE_LABEL = "icheck_device_id"
PROTECTED_LABELS = frozenset({TENANT_LABEL, REGION_LABEL, DEVICE_LABEL})
MAX_SCOPE_DEVICES = 10_000
MAX_QUERY_NODES = 512
MAX_QUERY_SELECTORS = 128
MAX_COMPILED_BYTES = 1_000_000


class MetricScopeError(ValueError):
    """A query cannot be safely evaluated under the current authority."""


@dataclass(frozen=True)
class MetricQueryAuthority:
    tenant_id: str
    region_id: str
    backend_revision: int
    device_ids: tuple[str, ...] | None


def query_authority(
    db: Session,
    backend: MetricBackend,
    principal: PrincipalContext | None,
    *,
    internal_service: bool = False,
) -> MetricQueryAuthority:
    try:
        require_locking_transaction(db, purpose="Metric query authority checks")
    except ValueError as exc:
        raise MetricScopeError(str(exc)) from exc
    selected = session_namespace(db)
    if principal is not None:
        if not principal.permits("metrics.read"):
            raise MetricScopeError("Metric read permission is required")
        namespace = (principal.tenant_id, principal.region_id)
        if selected is not None and selected != namespace:
            raise MetricScopeError("Metric query namespace does not match the session")
    elif internal_service:
        # Namespace-less local development sessions are default-only, never a
        # route to a backend in an arbitrary tenant. Native workers bind theirs.
        namespace = selected or (DEFAULT_TENANT_ID, DEFAULT_REGION_ID)
    else:
        raise MetricScopeError("Metric queries require an authenticated authority")
    db.refresh(backend)
    if (backend.tenant_id, backend.region_id) != namespace:
        raise MetricScopeError("Metric backend is outside the selected namespace")
    if not backend.enabled:
        raise MetricScopeError("Metric backend is disabled")
    device_ids = None
    if principal is not None and not has_global_scope(principal):
        # Re-evaluate current placement, not caller-supplied site labels or an
        # unbounded inventory materialization. Overflow must not truncate scope.
        ids = db.scalars(
            authorized_device_ids_query(principal)
            .order_by(None).order_by("id").limit(MAX_SCOPE_DEVICES + 1)
        ).all()
        if len(ids) > MAX_SCOPE_DEVICES:
            raise MetricScopeError("Metric device scope exceeds its limit; narrow the scope")
        device_ids = tuple(sorted(set(ids)))
    return MetricQueryAuthority(*namespace, backend.revision, device_ids)


def _scope_matchers(authority: MetricQueryAuthority) -> list[promql.Matcher]:
    matchers = [
        promql.Matcher(promql.MatchOp.Equal, TENANT_LABEL, authority.tenant_id),
        promql.Matcher(promql.MatchOp.Equal, REGION_LABEL, authority.region_id),
    ]
    if authority.device_ids is not None:
        if authority.device_ids:
            pattern = "|".join(re.escape(value).replace(r"\-", "-") for value in authority.device_ids)
            matchers.append(promql.Matcher(promql.MatchOp.Re, DEVICE_LABEL, pattern))
        else:
            # An impossible conjunction also excludes unlabeled infrastructure.
            matchers.extend([
                promql.Matcher(promql.MatchOp.Equal, DEVICE_LABEL, ""),
                promql.Matcher(promql.MatchOp.NotEqual, DEVICE_LABEL, ""),
            ])
    return matchers


def compile_scoped_query(query: str, authority: MetricQueryAuthority) -> str:
    if not isinstance(query, str) or not query:
        raise MetricScopeError("PromQL input exceeds its byte limit or is empty")
    try:
        input_bytes = query.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise MetricScopeError("PromQL input must be valid UTF-8") from exc
    if len(input_bytes) > 8192:
        raise MetricScopeError("PromQL input exceeds its byte limit or is empty")
    try:
        expression = promql.parse(query)
    except (ValueError, RuntimeError) as exc:
        # Parser messages can contain caller-supplied private labels.
        raise MetricScopeError("Invalid or unsupported PromQL expression") from exc
    scope = _scope_matchers(authority)
    nodes = selectors = compiled_size = 0
    literals: list[str] = []

    def literal(value):
        nonlocal compiled_size
        encoded = json.dumps(value, ensure_ascii=False)
        compiled_size += len(encoded.encode("utf-8"))
        if compiled_size > MAX_COMPILED_BYTES:
            raise MetricScopeError("Compiled PromQL exceeds its byte limit; narrow the scope")
        marker = f"icheck_scope_literal_{len(literals)}"
        literals.append(encoded)
        return json.dumps(marker)

    def qualify(node):
        nonlocal nodes, selectors, compiled_size
        nodes += 1
        if nodes > MAX_QUERY_NODES:
            raise MetricScopeError("PromQL expression exceeds its node limit")
        if isinstance(node, promql.Call):
            if node.func.name == "info":
                # info() implicitly looks up target_info outside its visible
                # vector argument. An ordinary selector rewrite is insufficient.
                raise MetricScopeError("PromQL info() is not supported by the scope boundary")
            if node.func.name in {"label_replace", "label_join"}:
                destination = node.args[1]
                if not isinstance(destination, promql.StringLiteral):
                    raise MetricScopeError("Invalid PromQL label destination")
                if destination.val in PROTECTED_LABELS:
                    raise MetricScopeError("PromQL cannot rewrite authorization labels")
        if isinstance(node, promql.StringLiteral):
            return promql.parse(literal(node.val))
        if not isinstance(node, promql.VectorSelector):
            return None
        selectors += 1
        if selectors > MAX_QUERY_SELECTORS:
            raise MetricScopeError("PromQL expression exceeds its selector limit")
        if node.matchers.or_matchers:
            raise MetricScopeError("Nonstandard OR label matchers are not supported")
        matchers = list(node.matchers.matchers)
        if node.name is not None:
            matchers.append(promql.Matcher(promql.MatchOp.Equal, "__name__", node.name))
        # The native display formatter also fails to escape matcher values and
        # string literals. Render safe temporary literal tokens, then restore
        # correctly quoted originals in ONE pass after formatting the AST.
        operations = (
            (promql.MatchOp.Equal, "="), (promql.MatchOp.NotEqual, "!="),
            (promql.MatchOp.Re, "=~"), (promql.MatchOp.NotRe, "!~"),
        )
        rendered = []
        for matcher in matchers + scope:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", matcher.name) is None:
                raise MetricScopeError("Quoted UTF-8 PromQL label names are not supported")
            operator = next(text for operation, text in operations if operation == matcher.op)
            rendered.append(matcher.name + operator + literal(matcher.value))
        text = "{" + ",".join(rendered) + "}"
        if node.at is not None:
            text += " " + str(node.at)
        if node.offset is not None:
            sign = "-" if node.offset.total_seconds() < 0 else ""
            text += " offset " + sign + promql.display_duration(abs(node.offset))
        compiled_size += len(text.encode("utf-8"))
        if compiled_size > MAX_COMPILED_BYTES:
            raise MetricScopeError("Compiled PromQL exceeds its byte limit; narrow the scope")
        # Rust AST properties expose copies: assigning node.matchers does NOT
        # modify the tree. Replace the leaf with a newly parsed expression.
        return promql.parse(text)

    try:
        formatted = str(promql.transform(expression, pre_visit=qualify))
        compiled = re.sub(
            r'"icheck_scope_literal_(\d+)"',
            lambda match: literals[int(match.group(1))], formatted,
        )
        if len(compiled.encode("utf-8")) > MAX_COMPILED_BYTES:
            raise MetricScopeError("Compiled PromQL exceeds its byte limit; narrow the scope")
        roundtrip = promql.parse(compiled)
        checked = 0

        def verify(node):
            nonlocal checked
            if isinstance(node, promql.VectorSelector):
                checked += 1
                actual = {(m.name, str(m.op), m.value) for m in node.matchers.matchers}
                required = {(m.name, str(m.op), m.value) for m in scope}
                if node.matchers.or_matchers or not required.issubset(actual):
                    raise MetricScopeError("PromQL scope verification failed")
            return True

        promql.walk(roundtrip, pre_visit=verify)
        if checked != selectors:
            raise MetricScopeError("PromQL selector verification failed")
        return compiled
    except MetricScopeError:
        raise
    except (ValueError, RuntimeError) as exc:
        raise MetricScopeError("PromQL cannot be safely scoped") from exc
