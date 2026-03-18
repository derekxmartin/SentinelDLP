"""gRPC server implementing SentinelDLPService (P2-T6).

Runs alongside FastAPI on port 50051. Implements:
  - Register: Agent registration → DB entry
  - Heartbeat: Status + last_checkin update
  - GetPolicies: Serialized active policy set
  - ReportIncident: Creates incident in DB
  - DetectContent: Runs detection engine, returns verdict
  - PolicyUpdates: Server-stream stub (placeholder)

Supports mTLS when cert/key files are provided.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from pathlib import Path

import grpc

from server.database import async_session
from server.detection.engine import DetectionEngine
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)
from server.detection.file_inspector import FileInspector
from server.detection.models import ComponentType, ParsedMessage
from server.proto import sentineldlp_pb2 as pb2
from server.proto import sentineldlp_pb2_grpc as pb2_grpc
from server.services import agent_service

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity / Channel enum mappings (proto ↔ DB)
# ---------------------------------------------------------------------------

_SEVERITY_TO_PROTO = {
    "info": pb2.SEVERITY_INFO,
    "low": pb2.SEVERITY_LOW,
    "medium": pb2.SEVERITY_MEDIUM,
    "high": pb2.SEVERITY_HIGH,
    "critical": pb2.SEVERITY_CRITICAL,
}

_CHANNEL_TO_PROTO = {
    "usb": pb2.CHANNEL_USB,
    "network_share": pb2.CHANNEL_NETWORK_SHARE,
    "clipboard": pb2.CHANNEL_CLIPBOARD,
    "browser_upload": pb2.CHANNEL_BROWSER_UPLOAD,
    "email": pb2.CHANNEL_EMAIL,
    "http_upload": pb2.CHANNEL_HTTP_UPLOAD,
    "discover": pb2.CHANNEL_DISCOVER,
}


# ---------------------------------------------------------------------------
# Detection engine factory (shared with REST API)
# ---------------------------------------------------------------------------


def _build_default_engine() -> DetectionEngine:
    """Build detection engine with built-in data identifiers."""
    engine = DetectionEngine()

    identifiers = [
        DataIdentifierConfig(
            name="Credit Card Number",
            patterns=[r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"],
            validator="luhn", confidence=0.95,
        ),
        DataIdentifierConfig(
            name="US SSN",
            patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
            validator="ssn_area", confidence=0.9,
        ),
        DataIdentifierConfig(
            name="Email Address",
            patterns=[r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"],
            validator="email_domain", confidence=0.85,
        ),
    ]

    analyzer = DataIdentifierAnalyzer(
        name="built_in_data_identifiers",
        identifiers=identifiers,
    )
    engine.register(analyzer)
    return engine


# ---------------------------------------------------------------------------
# Service implementation
# ---------------------------------------------------------------------------


class SentinelDLPServicer(pb2_grpc.SentinelDLPServiceServicer):
    """Implements all SentinelDLP gRPC RPCs."""

    # --- Register ---

    async def Register(self, request, context):
        """Agent registration — creates or updates agent record."""
        try:
            capabilities = None
            if request.HasField("capabilities"):
                cap = request.capabilities
                capabilities = {
                    "usb_monitor": cap.usb_monitor,
                    "network_share_monitor": cap.network_share_monitor,
                    "clipboard_monitor": cap.clipboard_monitor,
                    "browser_monitor": cap.browser_monitor,
                    "discover": cap.discover,
                }

            async with async_session() as db:
                agent = await agent_service.register_agent(
                    db,
                    hostname=request.hostname,
                    os_version=request.os_version or None,
                    agent_version=request.agent_version or None,
                    driver_version=request.driver_version or None,
                    ip_address=request.ip_address or None,
                    capabilities=capabilities,
                )
                await db.commit()

                return pb2.RegisterResponse(
                    agent_id=str(agent.id),
                    success=True,
                    message="Agent registered successfully",
                    heartbeat_interval_seconds=60,
                )
        except Exception as exc:
            logger.error("Register failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.RegisterResponse(success=False, message=str(exc))

    # --- Heartbeat ---

    async def Heartbeat(self, request, context):
        """Update agent heartbeat and return policy update status."""
        try:
            agent_id = uuid.UUID(request.agent_id)
        except ValueError:
            context.set_code(grpc.StatusCode.INVALID_ARGUMENT)
            context.set_details("Invalid agent_id")
            return pb2.HeartbeatResponse(success=False)

        try:
            async with async_session() as db:
                agent = await agent_service.heartbeat(
                    db, agent_id, policy_version=request.policy_version
                )
                if agent is None:
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details("Agent not found")
                    return pb2.HeartbeatResponse(success=False)

                await db.commit()

                return pb2.HeartbeatResponse(
                    success=True,
                    policy_update_available=False,
                    latest_policy_version=agent.policy_version,
                )
        except Exception as exc:
            logger.error("Heartbeat failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.HeartbeatResponse(success=False)

    # --- GetPolicies ---

    async def GetPolicies(self, request, context):
        """Return all active policies in proto format."""
        try:
            async with async_session() as db:
                policies = await agent_service.get_active_policies(db)

                policy_defs = []
                for p in policies:
                    # Build detection rules
                    rules = []
                    for rule in p.detection_rules:
                        conditions = []
                        for c in rule.conditions:
                            config_json = json.dumps(c.config) if isinstance(c.config, dict) else str(c.config or "{}")
                            conditions.append(pb2.RuleConditionDef(
                                condition_type=c.condition_type.value if hasattr(c.condition_type, "value") else str(c.condition_type),
                                component=c.component.value if hasattr(c.component, "value") else str(c.component),
                                config_json=config_json,
                                match_count_min=c.match_count_min,
                            ))
                        rules.append(pb2.DetectionRuleDef(
                            rule_id=str(rule.id),
                            name=rule.name,
                            rule_type=rule.rule_type,
                            conditions=conditions,
                        ))

                    # Build exceptions
                    exceptions = []
                    for exc in p.exceptions:
                        exc_conditions = []
                        for c in exc.conditions:
                            config_json = json.dumps(c.config) if isinstance(c.config, dict) else str(c.config or "{}")
                            exc_conditions.append(pb2.RuleConditionDef(
                                condition_type=c.condition_type.value if hasattr(c.condition_type, "value") else str(c.condition_type),
                                component=c.component.value if hasattr(c.component, "value") else str(c.component),
                                config_json=config_json,
                                match_count_min=c.match_count_min,
                            ))
                        exceptions.append(pb2.PolicyExceptionDef(
                            exception_id=str(exc.id),
                            name=exc.name,
                            scope=exc.scope.value if hasattr(exc.scope, "value") else str(exc.scope),
                            exception_type=exc.exception_type,
                            conditions=exc_conditions,
                        ))

                    # Build response rule
                    response_rule = None
                    if p.response_rule:
                        rr = p.response_rule
                        actions = []
                        for a in getattr(rr, "actions", []):
                            actions.append(pb2.ResponseActionDef(
                                action_type=a.action_type.value if hasattr(a.action_type, "value") else str(a.action_type),
                                config_json=json.dumps(a.config) if a.config else "{}",
                                order=a.order,
                            ))
                        response_rule = pb2.ResponseRuleDef(
                            rule_id=str(rr.id),
                            name=rr.name,
                            actions=actions,
                        )

                    # Severity thresholds
                    thresholds = []
                    if p.severity_thresholds:
                        raw = p.severity_thresholds
                        if isinstance(raw, str):
                            raw = json.loads(raw)
                        for t in raw:
                            thresholds.append(pb2.SeverityThreshold(
                                threshold=t["threshold"],
                                severity=_SEVERITY_TO_PROTO.get(t["severity"], pb2.SEVERITY_MEDIUM),
                            ))

                    policy_defs.append(pb2.PolicyDefinition(
                        policy_id=str(p.id),
                        name=p.name,
                        description=p.description or "",
                        severity=_SEVERITY_TO_PROTO.get(p.severity.value, pb2.SEVERITY_MEDIUM),
                        status=p.status.value,
                        ttd_fallback=p.ttd_fallback,
                        severity_thresholds=thresholds,
                        detection_rules=rules,
                        exceptions=exceptions,
                        response_rule=response_rule,
                    ))

                return pb2.GetPoliciesResponse(
                    policy_version=1,
                    policies=policy_defs,
                )
        except Exception as exc:
            logger.error("GetPolicies failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.GetPoliciesResponse()

    # --- PolicyUpdates (server-stream stub) ---

    async def PolicyUpdates(self, request, context):
        """Server-stream for policy updates. Stub — yields nothing."""
        # In production, this would watch for policy changes and push updates
        # For now, just return immediately (no updates)
        return

    # --- ReportIncident ---

    async def ReportIncident(self, request, context):
        """Agent reports a policy violation → creates incident in DB."""
        try:
            inc = request.incident
            matches = []
            for m in inc.matches:
                matches.append({
                    "identifier": m.identifier,
                    "pattern": m.pattern,
                    "matched_values": list(m.matched_values),
                    "count": m.count,
                    "component": m.component,
                })

            async with async_session() as db:
                incident = await agent_service.create_incident_from_report(
                    db,
                    agent_id=request.agent_id,
                    policy_id=inc.policy_id or None,
                    policy_name=inc.policy_name,
                    severity=inc.severity,
                    channel=inc.channel,
                    source_type=inc.source_type,
                    file_path=inc.file_path or None,
                    file_name=inc.file_name or None,
                    file_size=inc.file_size,
                    file_type=inc.file_type or None,
                    user=inc.user or None,
                    source_ip=inc.source_ip or None,
                    destination=inc.destination or None,
                    match_count=inc.match_count,
                    matches=matches,
                    action_taken=inc.action_taken or "log",
                    user_justification=inc.user_justification or None,
                )
                await db.commit()

                return pb2.ReportIncidentResponse(
                    success=True,
                    incident_id=str(incident.id),
                    message="Incident created",
                )
        except Exception as exc:
            logger.error("ReportIncident failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.ReportIncidentResponse(success=False, message=str(exc))

    # --- DetectContent (TTD) ---

    async def DetectContent(self, request, context):
        """Two-Tier Detection — run detection engine on submitted content."""
        try:
            timeout = request.timeout_seconds or 30
            fallback = request.fallback_action or "log"

            # Build message from file content
            if request.file_content:
                inspector = FileInspector()
                try:
                    message = inspector.inspect(
                        request.file_content,
                        filename=request.file_name or "unknown",
                    )
                except Exception:
                    message = ParsedMessage()
                    if request.file_content:
                        try:
                            text = request.file_content.decode("utf-8", errors="replace")
                            message.add_component(ComponentType.BODY, text)
                        except Exception:
                            pass
            elif request.content_excerpt:
                message = ParsedMessage()
                text = request.content_excerpt.decode("utf-8", errors="replace")
                message.add_component(ComponentType.BODY, text)
            else:
                return pb2.DetectContentResponse(
                    request_id=request.request_id,
                    verdict=pb2.TTD_ALLOW,
                    message="No content provided",
                )

            # Run detection with timeout
            engine = _build_default_engine()

            try:
                result = await asyncio.wait_for(
                    asyncio.get_event_loop().run_in_executor(
                        None, engine.detect, message
                    ),
                    timeout=timeout,
                )
            except asyncio.TimeoutError:
                # Return fallback action on timeout
                verdict_map = {
                    "allow": pb2.TTD_ALLOW,
                    "block": pb2.TTD_BLOCK,
                    "log": pb2.TTD_LOG,
                }
                return pb2.DetectContentResponse(
                    request_id=request.request_id,
                    verdict=verdict_map.get(fallback, pb2.TTD_LOG),
                    message=f"Detection timed out after {timeout}s, fallback: {fallback}",
                )

            # Determine verdict
            if result.has_matches:
                verdict = pb2.TTD_BLOCK
                # Find highest severity among matches
                severity = pb2.SEVERITY_MEDIUM
            else:
                verdict = pb2.TTD_ALLOW
                severity = pb2.SEVERITY_UNSPECIFIED

            # Build match details
            match_details = []
            for m in result.matches:
                match_details.append(pb2.MatchDetail(
                    identifier=m.rule_name,
                    pattern=m.metadata.get("identifier", ""),
                    matched_values=[m.matched_text],
                    count=1,
                    component=m.component.component_type.value,
                ))

            return pb2.DetectContentResponse(
                request_id=request.request_id,
                verdict=verdict,
                severity=severity,
                total_match_count=result.match_count,
                policy_results=[],
                message="Detection complete",
            )
        except Exception as exc:
            logger.error("DetectContent failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.DetectContentResponse(
                request_id=request.request_id,
                verdict=pb2.TTD_LOG,
                message=str(exc),
            )


# ---------------------------------------------------------------------------
# Server startup
# ---------------------------------------------------------------------------


async def serve(
    port: int = 50051,
    server_cert: str | None = None,
    server_key: str | None = None,
    ca_cert: str | None = None,
) -> grpc.aio.Server:
    """Start the gRPC server.

    Args:
        port: Port to listen on.
        server_cert: Path to server certificate (PEM) for mTLS.
        server_key: Path to server private key (PEM) for mTLS.
        ca_cert: Path to CA certificate (PEM) for client verification.

    Returns:
        The running gRPC server instance.
    """
    server = grpc.aio.server()
    pb2_grpc.add_SentinelDLPServiceServicer_to_server(
        SentinelDLPServicer(), server
    )

    if server_cert and server_key and ca_cert:
        # mTLS
        cert_data = Path(server_cert).read_bytes()
        key_data = Path(server_key).read_bytes()
        ca_data = Path(ca_cert).read_bytes()

        creds = grpc.ssl_server_credentials(
            [(key_data, cert_data)],
            root_certificates=ca_data,
            require_client_auth=True,
        )
        server.add_secure_port(f"[::]:{port}", creds)
        logger.info("gRPC server starting on port %d with mTLS", port)
    else:
        # Insecure (development)
        server.add_insecure_port(f"[::]:{port}")
        logger.info("gRPC server starting on port %d (insecure)", port)

    await server.start()
    return server
