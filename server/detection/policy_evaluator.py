"""Policy evaluator — Symantec 16.0-style policy evaluation engine.

Implements compound rules (AND), multi-rule OR, detection+group AND,
exception evaluation (entire message then MCO), and severity calculation
with match count thresholds.

Policy structure:
  Policy
    ├── detection_rules: list[DetectionRule]  (OR logic between rules)
    │     └── conditions: list[RuleCondition]  (AND logic within a rule)
    ├── groups: list[SenderRecipientGroup]     (AND with detection)
    ├── exceptions: list[PolicyException]
    └── severity_levels: list[SeverityLevel]

Evaluation flow:
  1. Run detection engine → DetectionResult
  2. Evaluate detection rules (OR across rules, AND within conditions)
  3. Apply group constraints (AND with detection)
  4. Evaluate exceptions (entire-message first, then MCO per-component)
  5. Calculate severity from remaining match count
  6. Build PolicyViolation result
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

from server.detection.models import (
    ComponentType,
    DetectionResult,
    Match,
    ParsedMessage,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """Incident severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConditionOperator(str, Enum):
    """Operators for rule conditions."""

    MATCHES = "matches"  # analyzer produced matches
    NOT_MATCHES = "not_matches"  # analyzer produced NO matches
    COUNT_GTE = "count_gte"  # match count >= threshold
    COUNT_LTE = "count_lte"  # match count <= threshold


class ExceptionScope(str, Enum):
    """How an exception applies."""

    ENTIRE_MESSAGE = "entire_message"  # Exclude entire message
    COMPONENT = "component"  # MCO: remove matched component only


class GroupMatchMode(str, Enum):
    """How to match sender/recipient against a group."""

    EXACT = "exact"
    DOMAIN = "domain"
    REGEX = "regex"


# ---------------------------------------------------------------------------
# Data classes — policy structure
# ---------------------------------------------------------------------------


@dataclass
class RuleCondition:
    """A single condition within a detection rule.

    A condition checks whether a specific analyzer produced matches
    (or a match count threshold).

    Attributes:
        analyzer_name: Name of the analyzer whose matches to check.
        operator: How to evaluate the matches.
        threshold: For count operators, the comparison value.
        component_types: Optional list to restrict which components
            the condition checks. None means all.
    """

    analyzer_name: str
    operator: ConditionOperator = ConditionOperator.MATCHES
    threshold: int = 0
    component_types: list[ComponentType] | None = None

    def evaluate(self, detection: DetectionResult) -> bool:
        """Evaluate this condition against a detection result."""
        matches = detection.matches_for_analyzer(self.analyzer_name)

        # Filter by component types if specified
        if self.component_types:
            ct_set = set(self.component_types)
            matches = [m for m in matches if m.component.component_type in ct_set]

        count = len(matches)

        if self.operator == ConditionOperator.MATCHES:
            return count > 0
        elif self.operator == ConditionOperator.NOT_MATCHES:
            return count == 0
        elif self.operator == ConditionOperator.COUNT_GTE:
            return count >= self.threshold
        elif self.operator == ConditionOperator.COUNT_LTE:
            return count <= self.threshold

        return False


@dataclass
class DetectionRule:
    """A detection rule composed of one or more conditions (AND logic).

    All conditions must be satisfied for the rule to match.
    Multiple rules within a policy use OR logic.

    Attributes:
        name: Unique name for this rule.
        conditions: Conditions that must ALL be true.
    """

    name: str
    conditions: list[RuleCondition] = field(default_factory=list)

    def evaluate(self, detection: DetectionResult) -> bool:
        """Evaluate: all conditions must match (AND)."""
        if not self.conditions:
            return False
        return all(c.evaluate(detection) for c in self.conditions)

    def matched_analyzers(self, detection: DetectionResult) -> set[str]:
        """Return analyzer names that contributed matches for true conditions."""
        names = set()
        for cond in self.conditions:
            if cond.evaluate(detection):
                names.add(cond.analyzer_name)
        return names


@dataclass
class SenderRecipientGroup:
    """A group of senders or recipients for group AND logic.

    Attributes:
        name: Group name (e.g., "Executive Team").
        members: List of member identifiers (emails, domains, patterns).
        match_mode: How to compare message metadata against members.
        field: Which metadata field to check (e.g., "sender", "recipients").
    """

    name: str
    members: list[str] = field(default_factory=list)
    match_mode: GroupMatchMode = GroupMatchMode.EXACT
    field: str = "sender"  # "sender" or "recipients"

    def matches_message(self, message: ParsedMessage) -> bool:
        """Check if the message matches this group."""
        value = message.metadata.get(self.field, "")

        # For recipients, check if ANY recipient matches
        if isinstance(value, list):
            return any(self._matches_value(v) for v in value)

        return self._matches_value(str(value))

    def _matches_value(self, value: str) -> bool:
        """Check if a single value matches any member."""
        value_lower = value.lower()

        for member in self.members:
            member_lower = member.lower()

            if self.match_mode == GroupMatchMode.EXACT:
                if value_lower == member_lower:
                    return True
            elif self.match_mode == GroupMatchMode.DOMAIN:
                # Extract domain from email
                if "@" in value_lower:
                    domain = value_lower.split("@", 1)[1]
                    if domain == member_lower or domain.endswith("." + member_lower):
                        return True
                elif value_lower == member_lower:
                    return True
            elif self.match_mode == GroupMatchMode.REGEX:
                if re.search(member, value, re.IGNORECASE):
                    return True

        return False


@dataclass
class PolicyException:
    """An exception that can exclude matches from policy evaluation.

    Entire-message exceptions prevent any incident. MCO (matched component
    only) exceptions remove only the matches from matching components.

    Attributes:
        name: Exception name.
        scope: ENTIRE_MESSAGE or COMPONENT (MCO).
        condition: A callable that takes (message, detection) and returns True
            if the exception applies. For declarative configs, use the
            factory methods.
        groups: Optional sender/recipient groups for exception matching.
        analyzer_names: For MCO, which analyzer's matches to exclude.
    """

    name: str
    scope: ExceptionScope = ExceptionScope.ENTIRE_MESSAGE
    groups: list[SenderRecipientGroup] = field(default_factory=list)
    analyzer_names: list[str] | None = None
    component_types: list[ComponentType] | None = None
    # Custom condition function: (message, detection) → bool
    condition: Callable[[ParsedMessage, DetectionResult], bool] | None = None

    def applies(self, message: ParsedMessage, detection: DetectionResult) -> bool:
        """Check if this exception applies to the message."""
        # Custom condition takes priority
        if self.condition is not None:
            return self.condition(message, detection)

        # Group-based exception: any group matches → exception applies
        if self.groups:
            return any(g.matches_message(message) for g in self.groups)

        return False

    def filter_matches(self, matches: list[Match]) -> list[Match]:
        """For MCO scope, remove matches that this exception covers.

        Returns the filtered match list (matches NOT covered by exception).
        """
        if self.scope == ExceptionScope.ENTIRE_MESSAGE:
            # Entire message exception removes ALL matches
            return []

        # MCO: filter by analyzer names and/or component types
        result = []
        for match in matches:
            excluded = True

            if self.analyzer_names:
                if match.analyzer_name not in self.analyzer_names:
                    excluded = False

            if excluded and self.component_types:
                if match.component.component_type not in self.component_types:
                    excluded = False

            if not excluded:
                result.append(match)

        return result


@dataclass
class SeverityLevel:
    """A severity tier based on match count thresholds.

    Attributes:
        severity: The severity level.
        min_matches: Minimum match count to trigger this level.
    """

    severity: Severity
    min_matches: int


@dataclass
class Policy:
    """A DLP policy with detection rules, groups, exceptions, and severity.

    Evaluation flow:
    1. Detection rules are OR'd — any rule matching triggers the policy.
    2. Groups are AND'd with detection — sender/recipient must match.
    3. Exceptions are evaluated: entire-message first, then MCO.
    4. Severity is calculated from remaining match count.

    Attributes:
        name: Policy name.
        description: Policy description.
        detection_rules: Rules to evaluate (OR logic between rules).
        groups: Sender/recipient constraints (AND with detection).
        exceptions: Exceptions to exclude matches/messages.
        severity_levels: Sorted by min_matches descending for tier lookup.
        default_severity: Severity when no tier matches.
        enabled: Whether this policy is active.
    """

    name: str
    description: str = ""
    detection_rules: list[DetectionRule] = field(default_factory=list)
    groups: list[SenderRecipientGroup] = field(default_factory=list)
    exceptions: list[PolicyException] = field(default_factory=list)
    severity_levels: list[SeverityLevel] = field(default_factory=list)
    default_severity: Severity = Severity.LOW
    enabled: bool = True


@dataclass
class PolicyViolation:
    """Result of evaluating a single policy against a message.

    Attributes:
        policy_name: Name of the violated policy.
        triggered: Whether the policy was violated.
        severity: Calculated severity level.
        matched_rules: Names of rules that matched.
        matches: Remaining matches after exception filtering.
        match_count: Number of remaining matches.
        exceptions_applied: Names of exceptions that were applied.
        errors: Any errors during evaluation.
    """

    policy_name: str
    triggered: bool = False
    severity: Severity = Severity.LOW
    matched_rules: list[str] = field(default_factory=list)
    matches: list[Match] = field(default_factory=list)
    match_count: int = 0
    exceptions_applied: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class EvaluationResult:
    """Result of evaluating all policies against a message.

    Attributes:
        message_id: ID of the evaluated message.
        violations: List of policy violations.
        has_violations: Whether any policy was violated.
        highest_severity: The highest severity across all violations.
    """

    message_id: str
    violations: list[PolicyViolation] = field(default_factory=list)

    @property
    def has_violations(self) -> bool:
        return any(v.triggered for v in self.violations)

    @property
    def highest_severity(self) -> Severity | None:
        """Return the highest severity across all triggered violations."""
        severity_order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        triggered = [v for v in self.violations if v.triggered]
        if not triggered:
            return None
        return max(triggered, key=lambda v: severity_order.index(v.severity)).severity

    @property
    def triggered_policies(self) -> list[str]:
        return [v.policy_name for v in self.violations if v.triggered]


# ---------------------------------------------------------------------------
# PolicyEvaluator
# ---------------------------------------------------------------------------


class PolicyEvaluator:
    """Evaluates messages against DLP policies using Symantec 16.0 logic.

    The evaluator takes a ParsedMessage, runs detection, and evaluates
    all registered policies. Each policy is evaluated independently:

    1. **Detection rules** (OR): Any rule matching triggers the policy.
       Within a rule, all conditions use AND logic.
    2. **Groups** (AND): If groups are defined, sender/recipient must
       match at least one group.
    3. **Exceptions**: Entire-message exceptions checked first. If any
       applies, the policy is not violated. MCO exceptions then remove
       specific matches.
    4. **Severity**: Calculated from remaining match count against
       severity level thresholds.

    Example:
        >>> evaluator = PolicyEvaluator(engine)
        >>> evaluator.add_policy(pci_policy)
        >>> result = evaluator.evaluate(message)
        >>> if result.has_violations:
        ...     print(result.highest_severity)
    """

    def __init__(self, engine: object | None = None) -> None:
        """Initialize the evaluator.

        Args:
            engine: Optional DetectionEngine to run detection. If None,
                detection results must be passed to evaluate_with_result().
        """
        self._engine = engine
        self._policies: list[Policy] = []

    @property
    def policies(self) -> list[Policy]:
        """Return registered policies (read-only copy)."""
        return list(self._policies)

    def add_policy(self, policy: Policy) -> None:
        """Register a policy for evaluation.

        Raises:
            ValueError: If a policy with the same name already exists.
        """
        if any(p.name == policy.name for p in self._policies):
            raise ValueError(f"Policy with name {policy.name!r} already registered")
        self._policies.append(policy)
        logger.debug("Registered policy: %s", policy.name)

    def remove_policy(self, name: str) -> None:
        """Remove a policy by name.

        Raises:
            KeyError: If no policy with that name exists.
        """
        for i, p in enumerate(self._policies):
            if p.name == name:
                self._policies.pop(i)
                logger.debug("Removed policy: %s", name)
                return
        raise KeyError(f"No policy registered with name {name!r}")

    def evaluate(self, message: ParsedMessage) -> EvaluationResult:
        """Run detection and evaluate all policies against a message.

        Args:
            message: The parsed message to evaluate.

        Returns:
            EvaluationResult with violations for each policy.

        Raises:
            RuntimeError: If no engine is configured.
        """
        if self._engine is None:
            raise RuntimeError(
                "No DetectionEngine configured. Use evaluate_with_result() "
                "or pass an engine to the constructor."
            )
        detection = self._engine.detect(message)
        return self.evaluate_with_result(message, detection)

    def evaluate_with_result(
        self,
        message: ParsedMessage,
        detection: DetectionResult,
    ) -> EvaluationResult:
        """Evaluate all policies given pre-computed detection results.

        Args:
            message: The parsed message.
            detection: Pre-computed detection results.

        Returns:
            EvaluationResult with violations for each policy.
        """
        result = EvaluationResult(message_id=message.message_id)

        for policy in self._policies:
            if not policy.enabled:
                continue

            try:
                violation = self._evaluate_policy(policy, message, detection)
                result.violations.append(violation)
            except Exception as exc:
                logger.error(
                    "Policy %r evaluation failed: %s",
                    policy.name,
                    exc,
                    exc_info=True,
                )
                violation = PolicyViolation(
                    policy_name=policy.name,
                    errors=[f"Evaluation failed: {exc}"],
                )
                result.violations.append(violation)

        return result

    def _evaluate_policy(
        self,
        policy: Policy,
        message: ParsedMessage,
        detection: DetectionResult,
    ) -> PolicyViolation:
        """Evaluate a single policy against detection results."""
        violation = PolicyViolation(policy_name=policy.name)

        # Step 1: Detection rules (OR across rules)
        matched_rules: list[str] = []
        contributing_analyzers: set[str] = set()

        for rule in policy.detection_rules:
            if rule.evaluate(detection):
                matched_rules.append(rule.name)
                contributing_analyzers.update(rule.matched_analyzers(detection))

        if not matched_rules:
            # No detection rule matched — no violation
            return violation

        violation.matched_rules = matched_rules

        # Step 2: Group constraints (AND with detection)
        if policy.groups:
            group_matched = any(g.matches_message(message) for g in policy.groups)
            if not group_matched:
                # Group constraint not satisfied — no violation
                return violation

        # Step 3: Collect matches from contributing analyzers
        relevant_matches = [
            m for m in detection.matches if m.analyzer_name in contributing_analyzers
        ]

        # Step 4: Exception evaluation
        # 4a: Entire-message exceptions first
        for exc in policy.exceptions:
            if exc.scope == ExceptionScope.ENTIRE_MESSAGE:
                if exc.applies(message, detection):
                    violation.exceptions_applied.append(exc.name)
                    # Entire message exception — no violation
                    return violation

        # 4b: MCO (Matched Component Only) exceptions
        for exc in policy.exceptions:
            if exc.scope == ExceptionScope.COMPONENT:
                if exc.applies(message, detection):
                    before_count = len(relevant_matches)
                    relevant_matches = exc.filter_matches(relevant_matches)
                    if len(relevant_matches) < before_count:
                        violation.exceptions_applied.append(exc.name)

        # After exceptions, check if any matches remain
        if not relevant_matches:
            return violation

        # Step 5: Policy is violated
        violation.triggered = True
        violation.matches = relevant_matches
        violation.match_count = len(relevant_matches)

        # Step 6: Severity calculation
        violation.severity = self._calculate_severity(policy, len(relevant_matches))

        return violation

    def _calculate_severity(self, policy: Policy, match_count: int) -> Severity:
        """Calculate severity based on match count and severity levels.

        Severity levels are checked from highest min_matches to lowest.
        The first level where match_count >= min_matches wins.
        """
        if not policy.severity_levels:
            return policy.default_severity

        # Sort by min_matches descending
        sorted_levels = sorted(
            policy.severity_levels, key=lambda s: s.min_matches, reverse=True
        )

        for level in sorted_levels:
            if match_count >= level.min_matches:
                return level.severity

        return policy.default_severity
