"""gRPC server implementing AkesoDLPService (P2-T6).

Runs alongside FastAPI on port 50051. Implements:
  - Register: Agent registration → DB entry
  - Heartbeat: Status + last_checkin update, real policy version check
  - GetPolicies: Serialized active policy set
  - ReportIncident: Creates incident in DB
  - DetectContent: Runs detection engine, returns verdict
  - PolicyUpdates: Server-stream pushing real-time policy changes

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
from server.policy_events import get_bus
from server.detection.analyzers.data_identifier_analyzer import (
    DataIdentifierAnalyzer,
    DataIdentifierConfig,
)
from server.detection.file_inspector import FileInspector
from server.detection.models import ComponentType, ParsedMessage
from server.proto import akesodlp_pb2 as pb2
from server.proto import akesodlp_pb2_grpc as pb2_grpc
from server.services import agent_service
from server.services.siem_emitter import SIEMConfig, SIEMEmitter, DLPEventType
from server.services.report_generator import IncidentRecord
from server.config import settings

logger = logging.getLogger(__name__)

# Initialize SIEM emitter from env config.
_siem_emitter: SIEMEmitter | None = None

def _get_siem_emitter() -> SIEMEmitter | None:
    global _siem_emitter
    if _siem_emitter is not None:
        return _siem_emitter
    if getattr(settings, "siem_enabled", False):
        cfg = SIEMConfig(
            endpoint=getattr(settings, "siem_endpoint", "http://localhost:8080/api/v1/ingest"),
            api_key=getattr(settings, "siem_api_key", ""),
            enabled=True,
        )
        _siem_emitter = SIEMEmitter(cfg)
        logger.info("SIEM emitter initialized: %s", cfg.endpoint)
    return _siem_emitter


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

_UPDATE_TYPE_TO_PROTO = {
    "POLICY_ADD": pb2.POLICY_ADD,
    "POLICY_MODIFY": pb2.POLICY_MODIFY,
    "POLICY_REMOVE": pb2.POLICY_REMOVE,
    "POLICY_FULL_SYNC": pb2.POLICY_FULL_SYNC,
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
            patterns=[
                r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
            ],
            validator="luhn",
            confidence=0.95,
        ),
        DataIdentifierConfig(
            name="US SSN",
            patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],
            validator="ssn_area",
            confidence=0.9,
        ),
        DataIdentifierConfig(
            name="Email Address",
            patterns=[r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b"],
            validator="email_domain",
            confidence=0.85,
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


class AkesoDLPServicer(pb2_grpc.AkesoDLPServiceServicer):
    """Implements all AkesoDLP gRPC RPCs."""

    # --- Register ---

    async def Register(self, request, context):
        """Agent registration — creates or updates agent record."""
        print(f"[gRPC] Register called: hostname={request.hostname}", flush=True)
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

                current_ver = get_bus().get_version()

                # Deliver any pending commands for this agent
                from server.command_queue import get_command_queue

                pending_cmds = get_command_queue().drain(str(agent_id))
                proto_cmds = [
                    pb2.AgentCommand(
                        command_type=c.command_type,
                        parameters=c.parameters,
                    )
                    for c in pending_cmds
                ]

                return pb2.HeartbeatResponse(
                    success=True,
                    policy_update_available=(request.policy_version < current_ver),
                    latest_policy_version=current_ver,
                    commands=proto_cmds,
                )
        except Exception as exc:
            logger.error("Heartbeat failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.HeartbeatResponse(success=False)

    # --- Shared policy serialization helpers ---

    @staticmethod
    def _build_policy_definition(policy) -> pb2.PolicyDefinition:
        """Serialize a DB Policy object into a proto PolicyDefinition."""
        # Detection rules
        rules = []
        for rule in policy.detection_rules:
            conditions = []
            for c in rule.conditions:
                config_json = (
                    json.dumps(c.config)
                    if isinstance(c.config, dict)
                    else str(c.config or "{}")
                )
                conditions.append(
                    pb2.RuleConditionDef(
                        condition_type=c.condition_type.value
                        if hasattr(c.condition_type, "value")
                        else str(c.condition_type),
                        component=c.component.value
                        if hasattr(c.component, "value")
                        else str(c.component),
                        config_json=config_json,
                        match_count_min=c.match_count_min,
                    )
                )
            rules.append(
                pb2.DetectionRuleDef(
                    rule_id=str(rule.id),
                    name=rule.name,
                    rule_type=rule.rule_type,
                    conditions=conditions,
                )
            )

        # Exceptions
        exceptions = []
        for exc in policy.exceptions:
            exc_conditions = []
            for c in exc.conditions:
                config_json = (
                    json.dumps(c.config)
                    if isinstance(c.config, dict)
                    else str(c.config or "{}")
                )
                exc_conditions.append(
                    pb2.RuleConditionDef(
                        condition_type=c.condition_type.value
                        if hasattr(c.condition_type, "value")
                        else str(c.condition_type),
                        component=c.component.value
                        if hasattr(c.component, "value")
                        else str(c.component),
                        config_json=config_json,
                        match_count_min=c.match_count_min,
                    )
                )
            exceptions.append(
                pb2.PolicyExceptionDef(
                    exception_id=str(exc.id),
                    name=exc.name,
                    scope=exc.scope.value
                    if hasattr(exc.scope, "value")
                    else str(exc.scope),
                    exception_type=exc.exception_type,
                    conditions=exc_conditions,
                )
            )

        # Response rule
        response_rule = None
        if policy.response_rule:
            rr = policy.response_rule
            actions = []
            for a in getattr(rr, "actions", []):
                actions.append(
                    pb2.ResponseActionDef(
                        action_type=a.action_type.value
                        if hasattr(a.action_type, "value")
                        else str(a.action_type),
                        config_json=json.dumps(a.config) if a.config else "{}",
                        order=a.order,
                    )
                )
            response_rule = pb2.ResponseRuleDef(
                rule_id=str(rr.id),
                name=rr.name,
                actions=actions,
            )

        # Severity thresholds
        thresholds = []
        if policy.severity_thresholds:
            raw = policy.severity_thresholds
            if isinstance(raw, str):
                raw = json.loads(raw)
            for t in raw:
                thresholds.append(
                    pb2.SeverityThreshold(
                        threshold=t["threshold"],
                        severity=_SEVERITY_TO_PROTO.get(
                            t["severity"], pb2.SEVERITY_MEDIUM
                        ),
                    )
                )

        return pb2.PolicyDefinition(
            policy_id=str(policy.id),
            name=policy.name,
            description=policy.description or "",
            severity=_SEVERITY_TO_PROTO.get(policy.severity.value, pb2.SEVERITY_MEDIUM),
            status=policy.status.value,
            ttd_fallback=policy.ttd_fallback,
            severity_thresholds=thresholds,
            detection_rules=rules,
            exceptions=exceptions,
            response_rule=response_rule,
        )

    # --- GetPolicies ---

    async def GetPolicies(self, request, context):
        """Return all active policies in proto format."""
        try:
            async with async_session() as db:
                policies = await agent_service.get_active_policies(db)
                policy_defs = [self._build_policy_definition(p) for p in policies]

                return pb2.GetPoliciesResponse(
                    policy_version=get_bus().get_version(),
                    policies=policy_defs,
                )
        except Exception as exc:
            logger.error("GetPolicies failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.GetPoliciesResponse()

    # --- PolicyUpdates (server-stream) ---

    async def PolicyUpdates(self, request, context):
        """Server-stream pushing real-time policy changes to agents."""
        from server.services import policy_service

        bus = get_bus()
        queue = await bus.subscribe()

        try:
            # Full sync if agent is behind
            current_ver = bus.get_version()
            if request.current_version < current_ver:
                logger.info(
                    "PolicyUpdates: agent %s at v%d, server at v%d — sending full sync",
                    request.agent_id,
                    request.current_version,
                    current_ver,
                )
                async with async_session() as db:
                    policies = await agent_service.get_active_policies(db)
                    for p in policies:
                        yield pb2.PolicyUpdate(
                            update_type=pb2.POLICY_FULL_SYNC,
                            new_version=current_ver,
                            policy=self._build_policy_definition(p),
                            policy_id=str(p.id),
                        )

            # Stream incremental updates
            while not context.cancelled():
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                except asyncio.TimeoutError:
                    continue  # Re-check cancelled

                update = pb2.PolicyUpdate(
                    update_type=_UPDATE_TYPE_TO_PROTO.get(
                        event["update_type"], pb2.POLICY_UPDATE_TYPE_UNSPECIFIED
                    ),
                    new_version=event.get("new_version", 0),
                    policy_id=event.get("policy_id", ""),
                )

                if event["update_type"] in ("POLICY_ADD", "POLICY_MODIFY"):
                    try:
                        async with async_session() as db:
                            policy = await policy_service.get_policy(
                                db, uuid.UUID(event["policy_id"])
                            )
                            if policy:
                                update.policy.CopyFrom(
                                    self._build_policy_definition(policy)
                                )
                    except Exception:
                        logger.exception(
                            "PolicyUpdates: failed to fetch policy %s",
                            event["policy_id"],
                        )

                yield update

        except asyncio.CancelledError:
            pass
        except Exception:
            logger.exception(
                "PolicyUpdates: stream error for agent %s", request.agent_id
            )
        finally:
            await bus.unsubscribe(queue)
            logger.debug("PolicyUpdates: agent %s disconnected", request.agent_id)

    # --- ReportIncident ---

    async def ReportIncident(self, request, context):
        """Agent reports a policy violation → creates incident in DB."""
        try:
            inc = request.incident
            matches = []
            for m in inc.matches:
                matches.append(
                    {
                        "identifier": m.identifier,
                        "pattern": m.pattern,
                        "matched_values": list(m.matched_values),
                        "count": m.count,
                        "component": m.component,
                    }
                )

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

                # Emit to SIEM.
                emitter = _get_siem_emitter()
                if emitter:
                    sev_map = {v: k for k, v in _SEVERITY_TO_PROTO.items()}
                    ch_map = {v: k for k, v in _CHANNEL_TO_PROTO.items()}
                    record = IncidentRecord(
                        id=str(incident.id),
                        policy_name=inc.policy_name,
                        severity=sev_map.get(inc.severity, "medium"),
                        status="new",
                        channel=ch_map.get(inc.channel, "unknown"),
                        source_type=inc.source_type or "endpoint",
                        user=inc.user or None,
                        file_name=inc.file_name or None,
                        action_taken=inc.action_taken or "log",
                        match_count=inc.match_count,
                        created_at=incident.created_at,
                    )
                    event_type = (
                        DLPEventType.FILE_BLOCKED
                        if inc.action_taken == "block"
                        else DLPEventType.INCIDENT_CREATED
                    )
                    await emitter.emit_incident(record, event_type)

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
                            text = request.file_content.decode(
                                "utf-8", errors="replace"
                            )
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
                match_details.append(
                    pb2.MatchDetail(
                        identifier=m.rule_name,
                        pattern=m.metadata.get("identifier", ""),
                        matched_values=[m.matched_text],
                        count=1,
                        component=m.component.component_type.value,
                    )
                )

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

    # --- GetDiscoverScans ---

    async def GetDiscoverScans(self, request, context):
        """Return pending/running discover scans assigned to this agent."""
        try:
            agent_id = request.agent_id
            async with async_session() as db:
                from server.services import discover_service
                from server.models.discover import DiscoverStatus

                scans, _ = await discover_service.list_discovers(
                    db,
                    status_filter=DiscoverStatus.RUNNING.value,
                    agent_id=agent_id,
                )
                # Also include unassigned running scans (agent_id is null)
                unassigned, _ = await discover_service.list_discovers(
                    db,
                    status_filter=DiscoverStatus.RUNNING.value,
                )

                seen_ids = set()
                proto_scans = []
                for scan in list(scans) + list(unassigned):
                    sid = str(scan.id)
                    if sid in seen_ids:
                        continue
                    seen_ids.add(sid)
                    proto_scans.append(
                        pb2.DiscoverScanDef(
                            discover_id=sid,
                            name=scan.name or "",
                            scan_path=scan.scan_path or "",
                            recursive=scan.recursive
                            if scan.recursive is not None
                            else True,
                            file_extensions=scan.file_extensions or [],
                            path_exclusions=scan.path_exclusions or [],
                        )
                    )

                return pb2.GetDiscoverScansResponse(scans=proto_scans)
        except Exception as exc:
            logger.error("GetDiscoverScans failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.GetDiscoverScansResponse()

    # --- ReportDiscoverResults ---

    async def ReportDiscoverResults(self, request, context):
        """Agent reports discover scan results — update DB status to completed."""
        try:
            discover_id = uuid.UUID(request.discover_id)
            async with async_session() as db:
                from server.services import discover_service

                scan = await discover_service.get_discover(db, discover_id)
                if scan is None:
                    context.set_code(grpc.StatusCode.NOT_FOUND)
                    context.set_details("Discover scan not found")
                    return pb2.ReportDiscoverResultsResponse(
                        success=False,
                        message="Scan not found",
                    )

                # Convert findings to JSON-serializable list
                findings_json = []
                for f in request.findings:
                    findings_json.append(
                        {
                            "file_path": f.file_path,
                            "file_name": f.file_name,
                            "file_size": f.file_size,
                            "file_owner": f.file_owner,
                            "policy_name": f.policy_name,
                            "severity": pb2.Severity.Name(f.severity),
                            "match_count": f.match_count,
                            "action_taken": f.action_taken,
                        }
                    )

                # Assign agent_id if not already set
                if not scan.agent_id:
                    scan.agent_id = request.agent_id

                await discover_service.complete_discover(
                    db,
                    scan,
                    {
                        "files_examined": request.files_examined,
                        "files_scanned": request.files_scanned,
                        "violations_found": request.violations_found,
                        "files_quarantined": request.files_quarantined,
                        "duration_ms": request.duration_ms,
                        "findings": findings_json,
                    },
                )
                await db.commit()

                return pb2.ReportDiscoverResultsResponse(
                    success=True,
                    message=f"Results recorded: {request.violations_found} violations",
                )
        except Exception as exc:
            logger.error("ReportDiscoverResults failed: %s", exc, exc_info=True)
            context.set_code(grpc.StatusCode.INTERNAL)
            context.set_details(str(exc))
            return pb2.ReportDiscoverResultsResponse(
                success=False,
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
    from server.grpc_rate_limiter import RateLimitInterceptor

    server = grpc.aio.server(interceptors=[RateLimitInterceptor()])
    pb2_grpc.add_AkesoDLPServiceServicer_to_server(AkesoDLPServicer(), server)

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
        server.add_secure_port(f"0.0.0.0:{port}", creds)
        logger.info("gRPC server starting on port %d with mTLS", port)
    else:
        # Insecure (development)
        server.add_insecure_port(f"0.0.0.0:{port}")
        logger.info("gRPC server starting on port %d (insecure)", port)

    await server.start()
    return server
