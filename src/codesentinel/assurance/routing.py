"""Deterministic, evidence-aware P8 risk routing."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from codesentinel.domain import CodeLocation, DiffAnalysis, RiskCategory, RiskMap, RiskRoute
from codesentinel.domain.enums import Severity
from codesentinel.domain.models import SkippedCandidate
from codesentinel.skills.security import SanitizedDiffView

from .models import RiskRoutingResult, SemanticRiskHint, SkillPlanEntry

ROUTER_VERSION = "1.0.0"
ALWAYS_ON_SKILLS = (
    "detect_secret",
    "security_semantic_review",
    "review_code_quality",
)
SKILL_UNIVERSE = (
    *ALWAYS_ON_SKILLS,
    "detect_injection",
    "detect_dangerous_call",
)


@dataclass(frozen=True, slots=True)
class _RouteSpec:
    category: RiskCategory
    severity: Severity
    skills: tuple[str, ...]
    reason: str


_RULES: tuple[tuple[re.Pattern[str], _RouteSpec], ...] = (
    (
        re.compile(
            r"\b(?:execute|executemany|raw|query)\s*\(|\b(?:SELECT|INSERT|UPDATE|DELETE)\b",
            re.I,
        ),
        _RouteSpec(
            RiskCategory.SQL_INJECTION,
            Severity.HIGH,
            ("detect_injection", "security_semantic_review"),
            "Database query construction changed and requires injection analysis.",
        ),
    ),
    (
        re.compile(r"\b(?:os\.system|os\.popen|subprocess\.|shell\s*=\s*True)"),
        _RouteSpec(
            RiskCategory.COMMAND_INJECTION,
            Severity.HIGH,
            (
                "detect_injection",
                "detect_dangerous_call",
                "security_semantic_review",
            ),
            "Command execution surface changed and requires injection and dangerous-call checks.",
        ),
    ),
    (
        re.compile(r"\b(?:eval|exec|pickle\.loads?|yaml\.load)\s*\("),
        _RouteSpec(
            RiskCategory.DANGEROUS_CALL,
            Severity.HIGH,
            ("detect_dangerous_call", "security_semantic_review"),
            "A dangerous execution or deserialization API changed.",
        ),
    ),
    (
        re.compile(
            r"\b(?:auth|authorize|permission|is_admin|role|access[_-]?control|jwt|token)\b",
            re.I,
        ),
        _RouteSpec(
            RiskCategory.AUTH_BOUNDARY,
            Severity.HIGH,
            ("security_semantic_review", "review_code_quality"),
            "Authentication or authorization boundary logic changed.",
        ),
    ),
    (
        re.compile(r"^\s*(?:for|while)\b|\b(?:sleep|select\s+\*|\.all\(\)|N\+1)\b", re.I),
        _RouteSpec(
            RiskCategory.PERFORMANCE,
            Severity.MEDIUM,
            ("review_code_quality",),
            "A loop, blocking call, or broad data access may affect performance.",
        ),
    ),
    (
        re.compile(r"^\s*except(?:\s+Exception)?\s*:"),
        _RouteSpec(
            RiskCategory.EXCEPTION_HANDLING,
            Severity.MEDIUM,
            ("review_code_quality",),
            "Broad exception handling changed and requires semantic review.",
        ),
    ),
    (
        re.compile(r"^\s*(?:if|elif|return)\b"),
        _RouteSpec(
            RiskCategory.LOGIC,
            Severity.MEDIUM,
            ("review_code_quality",),
            "Control-flow or return semantics changed.",
        ),
    ),
)


_CATEGORY_SKILLS = {
    RiskCategory.SECRET: ("detect_secret", "security_semantic_review"),
    RiskCategory.SQL_INJECTION: ("detect_injection", "security_semantic_review"),
    RiskCategory.COMMAND_INJECTION: (
        "detect_injection",
        "detect_dangerous_call",
        "security_semantic_review",
    ),
    RiskCategory.DANGEROUS_CALL: ("detect_dangerous_call", "security_semantic_review"),
    RiskCategory.AUTH_BOUNDARY: ("security_semantic_review", "review_code_quality"),
    RiskCategory.LOGIC: ("review_code_quality",),
    RiskCategory.EXCEPTION_HANDLING: ("review_code_quality",),
    RiskCategory.PERFORMANCE: ("review_code_quality",),
    RiskCategory.TEST_GAP: ("review_code_quality",),
    RiskCategory.SCOPE_LIMIT: ("security_semantic_review", "review_code_quality"),
    RiskCategory.TOOL_FAILURE: ("security_semantic_review", "review_code_quality"),
}


def _hash(*parts: object) -> str:
    return hashlib.sha256("\0".join(str(part) for part in parts).encode()).hexdigest()


def _location(line) -> CodeLocation:
    return CodeLocation(
        file_path=line.file_path,
        start_line=line.line_number,
        end_line=line.line_number,
        side=line.side,
        hunk_id=line.hunk_id,
        snippet_hash=line.content_hash,
    )


def _location_key(location: CodeLocation) -> tuple[object, ...]:
    return (
        location.file_path,
        location.hunk_id,
        location.side,
        location.start_line,
        location.end_line,
        location.snippet_hash,
    )


class RiskRouter:
    """Build a stable RiskMap from cloud-safe lines plus optional weak hints."""

    def build(
        self,
        diff: DiffAnalysis,
        sanitized: SanitizedDiffView,
        *,
        semantic_hints: tuple[SemanticRiskHint, ...] = (),
        semantic_failure_reason: str | None = None,
    ) -> RiskRoutingResult:
        if diff.review_id != sanitized.review_id:
            raise ValueError("DiffAnalysis and SanitizedDiffView review IDs must match")
        if diff.diff_hash != sanitized.source_diff_hash:
            raise ValueError("DiffAnalysis and SanitizedDiffView hashes must match")
        if not sanitized.cloud_safe:
            raise ValueError("risk routing requires a cloud-safe sanitized view")
        if semantic_hints and semantic_failure_reason is not None:
            raise ValueError("semantic hints and semantic failure are mutually exclusive")

        valid_locations = {
            _location_key(_location(line)): _location(line) for line in sanitized.lines
        }
        candidates: dict[tuple[RiskCategory, tuple[object, ...]], dict[str, object]] = {}
        for line in sanitized.lines:
            if line.side != "new" or line.kind.value != "addition":
                continue
            location = _location(line)
            for pattern, spec in _RULES:
                content_match = pattern.search(line.content)
                auth_path_match = (
                    spec.category is RiskCategory.AUTH_BOUNDARY
                    and pattern.search(line.file_path)
                )
                if content_match or auth_path_match:
                    self._merge_candidate(candidates, spec, location, "rule")

        self._add_test_gap_routes(diff, sanitized, candidates)

        for hint in semantic_hints:
            skills = _CATEGORY_SKILLS[hint.category]
            spec = _RouteSpec(hint.category, hint.severity_hint, skills, hint.reason)
            for location in hint.locations:
                trusted_location = valid_locations.get(_location_key(location))
                if trusted_location is None:
                    raise ValueError("semantic hint references a line outside sanitized context")
                self._merge_candidate(candidates, spec, trusted_location, "llm")

        routes = tuple(
            self._build_route(diff.review_id, key, value)
            for key, value in sorted(
                candidates.items(), key=lambda item: (item[0][0].value, item[0][1])
            )
        )
        planned = set(ALWAYS_ON_SKILLS)
        route_ids_by_skill: dict[str, list[str]] = {name: [] for name in SKILL_UNIVERSE}
        for route in routes:
            for skill in route.required_skills:
                planned.add(skill)
                route_ids_by_skill[skill].append(route.route_id)

        skipped = tuple(
            SkippedCandidate(
                skill=skill,
                reason="No changed line matched this Skill's frozen risk triggers.",
            )
            for skill in SKILL_UNIVERSE
            if skill not in planned
        )
        risk_map = RiskMap(
            review_id=diff.review_id,
            routes=routes,
            always_on_skills=ALWAYS_ON_SKILLS,
            planned_skill_count=len(planned),
            skipped_candidates=skipped,
            model_used=bool(semantic_hints) or semantic_failure_reason is not None,
        )
        skill_plan = tuple(
            SkillPlanEntry(
                skill_name=skill,
                planned=skill in planned,
                mandatory=skill in planned,
                route_ids=tuple(sorted(route_ids_by_skill[skill])),
                reason=(
                    "Always-on coverage required by the frozen MVP trust boundary."
                    if skill in ALWAYS_ON_SKILLS
                    else "A deterministic risk route requires this Skill."
                    if skill in planned
                    else "No changed line matched this Skill's frozen risk triggers."
                ),
            )
            for skill in SKILL_UNIVERSE
        )
        semantic_status = (
            "failed"
            if semantic_failure_reason is not None
            else "success"
            if semantic_hints
            else "not_requested"
        )
        return RiskRoutingResult(
            risk_map=risk_map,
            skill_plan=skill_plan,
            semantic_status=semantic_status,
            semantic_failure_reason=semantic_failure_reason,
        )

    @staticmethod
    def _merge_candidate(
        candidates: dict,
        spec: _RouteSpec,
        location: CodeLocation,
        source: str,
    ) -> None:
        key = (spec.category, _location_key(location))
        existing = candidates.get(key)
        if existing is None:
            candidates[key] = {
                "spec": spec,
                "location": location,
                "sources": {source},
                "reasons": {spec.reason},
            }
            return
        existing["sources"].add(source)
        existing["reasons"].add(spec.reason)
        current: _RouteSpec = existing["spec"]
        severity = max((current.severity, spec.severity), key=_severity_rank)
        skills = tuple(dict.fromkeys((*current.skills, *spec.skills)))
        existing["spec"] = _RouteSpec(current.category, severity, skills, current.reason)

    def _add_test_gap_routes(self, diff: DiffAnalysis, sanitized, candidates: dict) -> None:
        changed_paths = {
            item.new_path or item.old_path
            for item in diff.files
            if item.language == "python" and not item.is_binary
        }
        has_source = any(path and not _is_test_path(path) for path in changed_paths)
        has_test = any(path and _is_test_path(path) for path in changed_paths)
        if not has_source or has_test:
            return
        first_source_line = next(
            (
                line
                for line in sanitized.lines
                if line.side == "new" and not _is_test_path(line.file_path)
            ),
            None,
        )
        if first_source_line is None:
            return
        self._merge_candidate(
            candidates,
            _RouteSpec(
                RiskCategory.TEST_GAP,
                Severity.LOW,
                ("review_code_quality",),
                "Production Python changed without a corresponding test-file change.",
            ),
            _location(first_source_line),
            "rule",
        )

    @staticmethod
    def _build_route(review_id: str, key: tuple, value: dict) -> RiskRoute:
        spec: _RouteSpec = value["spec"]
        location: CodeLocation = value["location"]
        sources = value["sources"]
        source = "hybrid" if len(sources) > 1 else next(iter(sources))
        return RiskRoute(
            route_id=(
                f"route-{_hash(review_id, spec.category.value, *_location_key(location))[:20]}"
            ),
            category=spec.category,
            severity_hint=spec.severity,
            locations=(location,),
            required_skills=spec.skills,
            reason=" ".join(sorted(value["reasons"])),
            mandatory=True,
            route_source=source,
        )


def _severity_rank(value: Severity) -> int:
    return {
        Severity.INFO: 0,
        Severity.LOW: 1,
        Severity.MEDIUM: 2,
        Severity.HIGH: 3,
        Severity.CRITICAL: 4,
    }[value]


def _is_test_path(path: str) -> bool:
    lowered = path.lower()
    return (
        lowered.startswith("tests/")
        or "/tests/" in lowered
        or lowered.startswith("test_")
        or "/test_" in lowered
    )
