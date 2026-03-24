import datetime

from google.protobuf import timestamp_pb2 as _timestamp_pb2
from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from collections.abc import Iterable as _Iterable, Mapping as _Mapping
from typing import ClassVar as _ClassVar, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class PolicyUpdateType(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    POLICY_UPDATE_TYPE_UNSPECIFIED: _ClassVar[PolicyUpdateType]
    POLICY_ADD: _ClassVar[PolicyUpdateType]
    POLICY_MODIFY: _ClassVar[PolicyUpdateType]
    POLICY_REMOVE: _ClassVar[PolicyUpdateType]
    POLICY_FULL_SYNC: _ClassVar[PolicyUpdateType]

class TTDVerdict(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    TTD_VERDICT_UNSPECIFIED: _ClassVar[TTDVerdict]
    TTD_ALLOW: _ClassVar[TTDVerdict]
    TTD_BLOCK: _ClassVar[TTDVerdict]
    TTD_LOG: _ClassVar[TTDVerdict]

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_UNSPECIFIED: _ClassVar[Severity]
    SEVERITY_INFO: _ClassVar[Severity]
    SEVERITY_LOW: _ClassVar[Severity]
    SEVERITY_MEDIUM: _ClassVar[Severity]
    SEVERITY_HIGH: _ClassVar[Severity]
    SEVERITY_CRITICAL: _ClassVar[Severity]

class Channel(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    CHANNEL_UNSPECIFIED: _ClassVar[Channel]
    CHANNEL_USB: _ClassVar[Channel]
    CHANNEL_NETWORK_SHARE: _ClassVar[Channel]
    CHANNEL_CLIPBOARD: _ClassVar[Channel]
    CHANNEL_BROWSER_UPLOAD: _ClassVar[Channel]
    CHANNEL_EMAIL: _ClassVar[Channel]
    CHANNEL_HTTP_UPLOAD: _ClassVar[Channel]
    CHANNEL_DISCOVER: _ClassVar[Channel]
POLICY_UPDATE_TYPE_UNSPECIFIED: PolicyUpdateType
POLICY_ADD: PolicyUpdateType
POLICY_MODIFY: PolicyUpdateType
POLICY_REMOVE: PolicyUpdateType
POLICY_FULL_SYNC: PolicyUpdateType
TTD_VERDICT_UNSPECIFIED: TTDVerdict
TTD_ALLOW: TTDVerdict
TTD_BLOCK: TTDVerdict
TTD_LOG: TTDVerdict
SEVERITY_UNSPECIFIED: Severity
SEVERITY_INFO: Severity
SEVERITY_LOW: Severity
SEVERITY_MEDIUM: Severity
SEVERITY_HIGH: Severity
SEVERITY_CRITICAL: Severity
CHANNEL_UNSPECIFIED: Channel
CHANNEL_USB: Channel
CHANNEL_NETWORK_SHARE: Channel
CHANNEL_CLIPBOARD: Channel
CHANNEL_BROWSER_UPLOAD: Channel
CHANNEL_EMAIL: Channel
CHANNEL_HTTP_UPLOAD: Channel
CHANNEL_DISCOVER: Channel

class RegisterRequest(_message.Message):
    __slots__ = ("hostname", "os_version", "agent_version", "driver_version", "ip_address", "capabilities")
    HOSTNAME_FIELD_NUMBER: _ClassVar[int]
    OS_VERSION_FIELD_NUMBER: _ClassVar[int]
    AGENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    DRIVER_VERSION_FIELD_NUMBER: _ClassVar[int]
    IP_ADDRESS_FIELD_NUMBER: _ClassVar[int]
    CAPABILITIES_FIELD_NUMBER: _ClassVar[int]
    hostname: str
    os_version: str
    agent_version: str
    driver_version: str
    ip_address: str
    capabilities: AgentCapabilities
    def __init__(self, hostname: _Optional[str] = ..., os_version: _Optional[str] = ..., agent_version: _Optional[str] = ..., driver_version: _Optional[str] = ..., ip_address: _Optional[str] = ..., capabilities: _Optional[_Union[AgentCapabilities, _Mapping]] = ...) -> None: ...

class AgentCapabilities(_message.Message):
    __slots__ = ("usb_monitor", "network_share_monitor", "clipboard_monitor", "browser_monitor", "discover")
    USB_MONITOR_FIELD_NUMBER: _ClassVar[int]
    NETWORK_SHARE_MONITOR_FIELD_NUMBER: _ClassVar[int]
    CLIPBOARD_MONITOR_FIELD_NUMBER: _ClassVar[int]
    BROWSER_MONITOR_FIELD_NUMBER: _ClassVar[int]
    DISCOVER_FIELD_NUMBER: _ClassVar[int]
    usb_monitor: bool
    network_share_monitor: bool
    clipboard_monitor: bool
    browser_monitor: bool
    discover: bool
    def __init__(self, usb_monitor: bool = ..., network_share_monitor: bool = ..., clipboard_monitor: bool = ..., browser_monitor: bool = ..., discover: bool = ...) -> None: ...

class RegisterResponse(_message.Message):
    __slots__ = ("agent_id", "success", "message", "heartbeat_interval_seconds")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    HEARTBEAT_INTERVAL_SECONDS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    success: bool
    message: str
    heartbeat_interval_seconds: int
    def __init__(self, agent_id: _Optional[str] = ..., success: bool = ..., message: _Optional[str] = ..., heartbeat_interval_seconds: _Optional[int] = ...) -> None: ...

class HeartbeatRequest(_message.Message):
    __slots__ = ("agent_id", "policy_version", "status", "metrics", "timestamp")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    METRICS_FIELD_NUMBER: _ClassVar[int]
    TIMESTAMP_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    policy_version: int
    status: AgentStatus
    metrics: AgentMetrics
    timestamp: _timestamp_pb2.Timestamp
    def __init__(self, agent_id: _Optional[str] = ..., policy_version: _Optional[int] = ..., status: _Optional[_Union[AgentStatus, _Mapping]] = ..., metrics: _Optional[_Union[AgentMetrics, _Mapping]] = ..., timestamp: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class AgentStatus(_message.Message):
    __slots__ = ("driver_loaded", "detection_engine_ready", "pending_incidents", "uptime_seconds")
    DRIVER_LOADED_FIELD_NUMBER: _ClassVar[int]
    DETECTION_ENGINE_READY_FIELD_NUMBER: _ClassVar[int]
    PENDING_INCIDENTS_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECONDS_FIELD_NUMBER: _ClassVar[int]
    driver_loaded: bool
    detection_engine_ready: bool
    pending_incidents: int
    uptime_seconds: int
    def __init__(self, driver_loaded: bool = ..., detection_engine_ready: bool = ..., pending_incidents: _Optional[int] = ..., uptime_seconds: _Optional[int] = ...) -> None: ...

class AgentMetrics(_message.Message):
    __slots__ = ("files_scanned", "files_blocked", "incidents_reported", "ttd_requests", "cpu_usage_percent", "memory_usage_bytes")
    FILES_SCANNED_FIELD_NUMBER: _ClassVar[int]
    FILES_BLOCKED_FIELD_NUMBER: _ClassVar[int]
    INCIDENTS_REPORTED_FIELD_NUMBER: _ClassVar[int]
    TTD_REQUESTS_FIELD_NUMBER: _ClassVar[int]
    CPU_USAGE_PERCENT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_USAGE_BYTES_FIELD_NUMBER: _ClassVar[int]
    files_scanned: int
    files_blocked: int
    incidents_reported: int
    ttd_requests: int
    cpu_usage_percent: float
    memory_usage_bytes: int
    def __init__(self, files_scanned: _Optional[int] = ..., files_blocked: _Optional[int] = ..., incidents_reported: _Optional[int] = ..., ttd_requests: _Optional[int] = ..., cpu_usage_percent: _Optional[float] = ..., memory_usage_bytes: _Optional[int] = ...) -> None: ...

class HeartbeatResponse(_message.Message):
    __slots__ = ("success", "policy_update_available", "latest_policy_version", "commands")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    POLICY_UPDATE_AVAILABLE_FIELD_NUMBER: _ClassVar[int]
    LATEST_POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    COMMANDS_FIELD_NUMBER: _ClassVar[int]
    success: bool
    policy_update_available: bool
    latest_policy_version: int
    commands: _containers.RepeatedCompositeFieldContainer[AgentCommand]
    def __init__(self, success: bool = ..., policy_update_available: bool = ..., latest_policy_version: _Optional[int] = ..., commands: _Optional[_Iterable[_Union[AgentCommand, _Mapping]]] = ...) -> None: ...

class AgentCommand(_message.Message):
    __slots__ = ("command_type", "parameters")
    class ParametersEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    COMMAND_TYPE_FIELD_NUMBER: _ClassVar[int]
    PARAMETERS_FIELD_NUMBER: _ClassVar[int]
    command_type: str
    parameters: _containers.ScalarMap[str, str]
    def __init__(self, command_type: _Optional[str] = ..., parameters: _Optional[_Mapping[str, str]] = ...) -> None: ...

class GetPoliciesRequest(_message.Message):
    __slots__ = ("agent_id", "current_version")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    CURRENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    current_version: int
    def __init__(self, agent_id: _Optional[str] = ..., current_version: _Optional[int] = ...) -> None: ...

class GetPoliciesResponse(_message.Message):
    __slots__ = ("policy_version", "policies")
    POLICY_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICIES_FIELD_NUMBER: _ClassVar[int]
    policy_version: int
    policies: _containers.RepeatedCompositeFieldContainer[PolicyDefinition]
    def __init__(self, policy_version: _Optional[int] = ..., policies: _Optional[_Iterable[_Union[PolicyDefinition, _Mapping]]] = ...) -> None: ...

class PolicyDefinition(_message.Message):
    __slots__ = ("policy_id", "name", "description", "severity", "status", "ttd_fallback", "severity_thresholds", "detection_rules", "exceptions", "response_rule")
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    DESCRIPTION_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    TTD_FALLBACK_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_THRESHOLDS_FIELD_NUMBER: _ClassVar[int]
    DETECTION_RULES_FIELD_NUMBER: _ClassVar[int]
    EXCEPTIONS_FIELD_NUMBER: _ClassVar[int]
    RESPONSE_RULE_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    name: str
    description: str
    severity: Severity
    status: str
    ttd_fallback: str
    severity_thresholds: _containers.RepeatedCompositeFieldContainer[SeverityThreshold]
    detection_rules: _containers.RepeatedCompositeFieldContainer[DetectionRuleDef]
    exceptions: _containers.RepeatedCompositeFieldContainer[PolicyExceptionDef]
    response_rule: ResponseRuleDef
    def __init__(self, policy_id: _Optional[str] = ..., name: _Optional[str] = ..., description: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., status: _Optional[str] = ..., ttd_fallback: _Optional[str] = ..., severity_thresholds: _Optional[_Iterable[_Union[SeverityThreshold, _Mapping]]] = ..., detection_rules: _Optional[_Iterable[_Union[DetectionRuleDef, _Mapping]]] = ..., exceptions: _Optional[_Iterable[_Union[PolicyExceptionDef, _Mapping]]] = ..., response_rule: _Optional[_Union[ResponseRuleDef, _Mapping]] = ...) -> None: ...

class SeverityThreshold(_message.Message):
    __slots__ = ("threshold", "severity")
    THRESHOLD_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    threshold: int
    severity: Severity
    def __init__(self, threshold: _Optional[int] = ..., severity: _Optional[_Union[Severity, str]] = ...) -> None: ...

class DetectionRuleDef(_message.Message):
    __slots__ = ("rule_id", "name", "rule_type", "conditions")
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    RULE_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    name: str
    rule_type: str
    conditions: _containers.RepeatedCompositeFieldContainer[RuleConditionDef]
    def __init__(self, rule_id: _Optional[str] = ..., name: _Optional[str] = ..., rule_type: _Optional[str] = ..., conditions: _Optional[_Iterable[_Union[RuleConditionDef, _Mapping]]] = ...) -> None: ...

class RuleConditionDef(_message.Message):
    __slots__ = ("condition_type", "component", "config_json", "match_count_min")
    CONDITION_TYPE_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_FIELD_NUMBER: _ClassVar[int]
    CONFIG_JSON_FIELD_NUMBER: _ClassVar[int]
    MATCH_COUNT_MIN_FIELD_NUMBER: _ClassVar[int]
    condition_type: str
    component: str
    config_json: str
    match_count_min: int
    def __init__(self, condition_type: _Optional[str] = ..., component: _Optional[str] = ..., config_json: _Optional[str] = ..., match_count_min: _Optional[int] = ...) -> None: ...

class PolicyExceptionDef(_message.Message):
    __slots__ = ("exception_id", "name", "scope", "exception_type", "conditions")
    EXCEPTION_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SCOPE_FIELD_NUMBER: _ClassVar[int]
    EXCEPTION_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONDITIONS_FIELD_NUMBER: _ClassVar[int]
    exception_id: str
    name: str
    scope: str
    exception_type: str
    conditions: _containers.RepeatedCompositeFieldContainer[RuleConditionDef]
    def __init__(self, exception_id: _Optional[str] = ..., name: _Optional[str] = ..., scope: _Optional[str] = ..., exception_type: _Optional[str] = ..., conditions: _Optional[_Iterable[_Union[RuleConditionDef, _Mapping]]] = ...) -> None: ...

class ResponseRuleDef(_message.Message):
    __slots__ = ("rule_id", "name", "actions")
    RULE_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    ACTIONS_FIELD_NUMBER: _ClassVar[int]
    rule_id: str
    name: str
    actions: _containers.RepeatedCompositeFieldContainer[ResponseActionDef]
    def __init__(self, rule_id: _Optional[str] = ..., name: _Optional[str] = ..., actions: _Optional[_Iterable[_Union[ResponseActionDef, _Mapping]]] = ...) -> None: ...

class ResponseActionDef(_message.Message):
    __slots__ = ("action_type", "config_json", "order")
    ACTION_TYPE_FIELD_NUMBER: _ClassVar[int]
    CONFIG_JSON_FIELD_NUMBER: _ClassVar[int]
    ORDER_FIELD_NUMBER: _ClassVar[int]
    action_type: str
    config_json: str
    order: int
    def __init__(self, action_type: _Optional[str] = ..., config_json: _Optional[str] = ..., order: _Optional[int] = ...) -> None: ...

class PolicyUpdatesRequest(_message.Message):
    __slots__ = ("agent_id", "current_version")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    CURRENT_VERSION_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    current_version: int
    def __init__(self, agent_id: _Optional[str] = ..., current_version: _Optional[int] = ...) -> None: ...

class PolicyUpdate(_message.Message):
    __slots__ = ("update_type", "new_version", "policy", "policy_id")
    UPDATE_TYPE_FIELD_NUMBER: _ClassVar[int]
    NEW_VERSION_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    update_type: PolicyUpdateType
    new_version: int
    policy: PolicyDefinition
    policy_id: str
    def __init__(self, update_type: _Optional[_Union[PolicyUpdateType, str]] = ..., new_version: _Optional[int] = ..., policy: _Optional[_Union[PolicyDefinition, _Mapping]] = ..., policy_id: _Optional[str] = ...) -> None: ...

class ReportIncidentRequest(_message.Message):
    __slots__ = ("agent_id", "incident")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    INCIDENT_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    incident: IncidentReport
    def __init__(self, agent_id: _Optional[str] = ..., incident: _Optional[_Union[IncidentReport, _Mapping]] = ...) -> None: ...

class IncidentReport(_message.Message):
    __slots__ = ("policy_id", "policy_name", "severity", "channel", "source_type", "file_path", "file_name", "file_size", "file_type", "user", "source_ip", "destination", "match_count", "matches", "action_taken", "user_justification", "detected_at")
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    SOURCE_TYPE_FIELD_NUMBER: _ClassVar[int]
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    FILE_TYPE_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    SOURCE_IP_FIELD_NUMBER: _ClassVar[int]
    DESTINATION_FIELD_NUMBER: _ClassVar[int]
    MATCH_COUNT_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    ACTION_TAKEN_FIELD_NUMBER: _ClassVar[int]
    USER_JUSTIFICATION_FIELD_NUMBER: _ClassVar[int]
    DETECTED_AT_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    policy_name: str
    severity: Severity
    channel: Channel
    source_type: str
    file_path: str
    file_name: str
    file_size: int
    file_type: str
    user: str
    source_ip: str
    destination: str
    match_count: int
    matches: _containers.RepeatedCompositeFieldContainer[MatchDetail]
    action_taken: str
    user_justification: str
    detected_at: _timestamp_pb2.Timestamp
    def __init__(self, policy_id: _Optional[str] = ..., policy_name: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., channel: _Optional[_Union[Channel, str]] = ..., source_type: _Optional[str] = ..., file_path: _Optional[str] = ..., file_name: _Optional[str] = ..., file_size: _Optional[int] = ..., file_type: _Optional[str] = ..., user: _Optional[str] = ..., source_ip: _Optional[str] = ..., destination: _Optional[str] = ..., match_count: _Optional[int] = ..., matches: _Optional[_Iterable[_Union[MatchDetail, _Mapping]]] = ..., action_taken: _Optional[str] = ..., user_justification: _Optional[str] = ..., detected_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class MatchDetail(_message.Message):
    __slots__ = ("identifier", "pattern", "matched_values", "count", "component")
    IDENTIFIER_FIELD_NUMBER: _ClassVar[int]
    PATTERN_FIELD_NUMBER: _ClassVar[int]
    MATCHED_VALUES_FIELD_NUMBER: _ClassVar[int]
    COUNT_FIELD_NUMBER: _ClassVar[int]
    COMPONENT_FIELD_NUMBER: _ClassVar[int]
    identifier: str
    pattern: str
    matched_values: _containers.RepeatedScalarFieldContainer[str]
    count: int
    component: str
    def __init__(self, identifier: _Optional[str] = ..., pattern: _Optional[str] = ..., matched_values: _Optional[_Iterable[str]] = ..., count: _Optional[int] = ..., component: _Optional[str] = ...) -> None: ...

class ReportIncidentResponse(_message.Message):
    __slots__ = ("success", "incident_id", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    INCIDENT_ID_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    incident_id: str
    message: str
    def __init__(self, success: bool = ..., incident_id: _Optional[str] = ..., message: _Optional[str] = ...) -> None: ...

class DetectContentRequest(_message.Message):
    __slots__ = ("agent_id", "request_id", "file_content", "file_name", "file_type", "file_size", "file_hash_sha256", "content_excerpt", "policy_ids", "timeout_seconds", "fallback_action", "user", "source_ip", "channel", "requested_at")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    FILE_CONTENT_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_TYPE_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    FILE_HASH_SHA256_FIELD_NUMBER: _ClassVar[int]
    CONTENT_EXCERPT_FIELD_NUMBER: _ClassVar[int]
    POLICY_IDS_FIELD_NUMBER: _ClassVar[int]
    TIMEOUT_SECONDS_FIELD_NUMBER: _ClassVar[int]
    FALLBACK_ACTION_FIELD_NUMBER: _ClassVar[int]
    USER_FIELD_NUMBER: _ClassVar[int]
    SOURCE_IP_FIELD_NUMBER: _ClassVar[int]
    CHANNEL_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_AT_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    request_id: str
    file_content: bytes
    file_name: str
    file_type: str
    file_size: int
    file_hash_sha256: str
    content_excerpt: bytes
    policy_ids: _containers.RepeatedScalarFieldContainer[str]
    timeout_seconds: int
    fallback_action: str
    user: str
    source_ip: str
    channel: Channel
    requested_at: _timestamp_pb2.Timestamp
    def __init__(self, agent_id: _Optional[str] = ..., request_id: _Optional[str] = ..., file_content: _Optional[bytes] = ..., file_name: _Optional[str] = ..., file_type: _Optional[str] = ..., file_size: _Optional[int] = ..., file_hash_sha256: _Optional[str] = ..., content_excerpt: _Optional[bytes] = ..., policy_ids: _Optional[_Iterable[str]] = ..., timeout_seconds: _Optional[int] = ..., fallback_action: _Optional[str] = ..., user: _Optional[str] = ..., source_ip: _Optional[str] = ..., channel: _Optional[_Union[Channel, str]] = ..., requested_at: _Optional[_Union[datetime.datetime, _timestamp_pb2.Timestamp, _Mapping]] = ...) -> None: ...

class DetectContentResponse(_message.Message):
    __slots__ = ("request_id", "verdict", "severity", "policy_results", "total_match_count", "message")
    REQUEST_ID_FIELD_NUMBER: _ClassVar[int]
    VERDICT_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    POLICY_RESULTS_FIELD_NUMBER: _ClassVar[int]
    TOTAL_MATCH_COUNT_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    request_id: str
    verdict: TTDVerdict
    severity: Severity
    policy_results: _containers.RepeatedCompositeFieldContainer[TTDPolicyResult]
    total_match_count: int
    message: str
    def __init__(self, request_id: _Optional[str] = ..., verdict: _Optional[_Union[TTDVerdict, str]] = ..., severity: _Optional[_Union[Severity, str]] = ..., policy_results: _Optional[_Iterable[_Union[TTDPolicyResult, _Mapping]]] = ..., total_match_count: _Optional[int] = ..., message: _Optional[str] = ...) -> None: ...

class TTDPolicyResult(_message.Message):
    __slots__ = ("policy_id", "policy_name", "matched", "severity", "matches", "match_count")
    POLICY_ID_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    MATCHED_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    MATCHES_FIELD_NUMBER: _ClassVar[int]
    MATCH_COUNT_FIELD_NUMBER: _ClassVar[int]
    policy_id: str
    policy_name: str
    matched: bool
    severity: Severity
    matches: _containers.RepeatedCompositeFieldContainer[MatchDetail]
    match_count: int
    def __init__(self, policy_id: _Optional[str] = ..., policy_name: _Optional[str] = ..., matched: bool = ..., severity: _Optional[_Union[Severity, str]] = ..., matches: _Optional[_Iterable[_Union[MatchDetail, _Mapping]]] = ..., match_count: _Optional[int] = ...) -> None: ...

class GetDiscoverScansRequest(_message.Message):
    __slots__ = ("agent_id",)
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    def __init__(self, agent_id: _Optional[str] = ...) -> None: ...

class GetDiscoverScansResponse(_message.Message):
    __slots__ = ("scans",)
    SCANS_FIELD_NUMBER: _ClassVar[int]
    scans: _containers.RepeatedCompositeFieldContainer[DiscoverScanDef]
    def __init__(self, scans: _Optional[_Iterable[_Union[DiscoverScanDef, _Mapping]]] = ...) -> None: ...

class DiscoverScanDef(_message.Message):
    __slots__ = ("discover_id", "name", "scan_path", "recursive", "file_extensions", "path_exclusions")
    DISCOVER_ID_FIELD_NUMBER: _ClassVar[int]
    NAME_FIELD_NUMBER: _ClassVar[int]
    SCAN_PATH_FIELD_NUMBER: _ClassVar[int]
    RECURSIVE_FIELD_NUMBER: _ClassVar[int]
    FILE_EXTENSIONS_FIELD_NUMBER: _ClassVar[int]
    PATH_EXCLUSIONS_FIELD_NUMBER: _ClassVar[int]
    discover_id: str
    name: str
    scan_path: str
    recursive: bool
    file_extensions: _containers.RepeatedScalarFieldContainer[str]
    path_exclusions: _containers.RepeatedScalarFieldContainer[str]
    def __init__(self, discover_id: _Optional[str] = ..., name: _Optional[str] = ..., scan_path: _Optional[str] = ..., recursive: bool = ..., file_extensions: _Optional[_Iterable[str]] = ..., path_exclusions: _Optional[_Iterable[str]] = ...) -> None: ...

class ReportDiscoverResultsRequest(_message.Message):
    __slots__ = ("agent_id", "discover_id", "files_examined", "files_scanned", "violations_found", "files_quarantined", "duration_ms", "findings")
    AGENT_ID_FIELD_NUMBER: _ClassVar[int]
    DISCOVER_ID_FIELD_NUMBER: _ClassVar[int]
    FILES_EXAMINED_FIELD_NUMBER: _ClassVar[int]
    FILES_SCANNED_FIELD_NUMBER: _ClassVar[int]
    VIOLATIONS_FOUND_FIELD_NUMBER: _ClassVar[int]
    FILES_QUARANTINED_FIELD_NUMBER: _ClassVar[int]
    DURATION_MS_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    agent_id: str
    discover_id: str
    files_examined: int
    files_scanned: int
    violations_found: int
    files_quarantined: int
    duration_ms: int
    findings: _containers.RepeatedCompositeFieldContainer[DiscoverFinding]
    def __init__(self, agent_id: _Optional[str] = ..., discover_id: _Optional[str] = ..., files_examined: _Optional[int] = ..., files_scanned: _Optional[int] = ..., violations_found: _Optional[int] = ..., files_quarantined: _Optional[int] = ..., duration_ms: _Optional[int] = ..., findings: _Optional[_Iterable[_Union[DiscoverFinding, _Mapping]]] = ...) -> None: ...

class DiscoverFinding(_message.Message):
    __slots__ = ("file_path", "file_name", "file_size", "file_owner", "policy_name", "severity", "match_count", "action_taken")
    FILE_PATH_FIELD_NUMBER: _ClassVar[int]
    FILE_NAME_FIELD_NUMBER: _ClassVar[int]
    FILE_SIZE_FIELD_NUMBER: _ClassVar[int]
    FILE_OWNER_FIELD_NUMBER: _ClassVar[int]
    POLICY_NAME_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    MATCH_COUNT_FIELD_NUMBER: _ClassVar[int]
    ACTION_TAKEN_FIELD_NUMBER: _ClassVar[int]
    file_path: str
    file_name: str
    file_size: int
    file_owner: str
    policy_name: str
    severity: Severity
    match_count: int
    action_taken: str
    def __init__(self, file_path: _Optional[str] = ..., file_name: _Optional[str] = ..., file_size: _Optional[int] = ..., file_owner: _Optional[str] = ..., policy_name: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., match_count: _Optional[int] = ..., action_taken: _Optional[str] = ...) -> None: ...

class ReportDiscoverResultsResponse(_message.Message):
    __slots__ = ("success", "message")
    SUCCESS_FIELD_NUMBER: _ClassVar[int]
    MESSAGE_FIELD_NUMBER: _ClassVar[int]
    success: bool
    message: str
    def __init__(self, success: bool = ..., message: _Optional[str] = ...) -> None: ...
