"""Translate a P8 routing plan into complete, auditable CoverageRecords."""

from __future__ import annotations

import hashlib

from codesentinel.domain import CoverageRecord, CoverageStatus

from .models import RiskRoutingResult


def _coverage_id(review_id: str, skill_name: str) -> str:
    digest = hashlib.sha256(f"{review_id}\0{skill_name}\0p8-plan".encode()).hexdigest()
    return f"coverage-{digest[:20]}"


def reconcile_coverage(
    routing: RiskRoutingResult,
    executed: tuple[CoverageRecord, ...],
) -> tuple[CoverageRecord, ...]:
    """Bind execution records to routes and materialize every skip or missing result."""

    by_skill: dict[str, CoverageRecord] = {}
    for record in executed:
        if record.skill_name in by_skill:
            raise ValueError("executed coverage must contain at most one record per Skill")
        by_skill[record.skill_name] = record

    expected = {entry.skill_name for entry in routing.skill_plan}
    unexpected = set(by_skill) - expected
    if unexpected:
        raise ValueError("executed coverage contains a Skill outside the frozen plan")

    records = []
    for entry in routing.skill_plan:
        actual = by_skill.get(entry.skill_name)
        if not entry.planned:
            if actual is not None:
                raise ValueError("a skipped Skill must not publish an execution record")
            records.append(
                CoverageRecord(
                    coverage_id=_coverage_id(
                        routing.risk_map.review_id,
                        entry.skill_name,
                    ),
                    skill_name=entry.skill_name,
                    skill_version="1.0.0",
                    status=CoverageStatus.SKIPPED,
                    mandatory=False,
                    route_ids=(),
                    files_checked=(),
                    reason=entry.reason,
                    error_code=None,
                    duration_ms=0,
                )
            )
            continue
        if actual is None:
            records.append(
                CoverageRecord(
                    coverage_id=_coverage_id(
                        routing.risk_map.review_id,
                        entry.skill_name,
                    ),
                    skill_name=entry.skill_name,
                    skill_version="1.0.0",
                    status=CoverageStatus.FAILED,
                    mandatory=entry.mandatory,
                    route_ids=entry.route_ids,
                    files_checked=(),
                    reason="The planned Skill did not publish an execution result.",
                    error_code="MISSING_EXECUTION_RESULT",
                    duration_ms=0,
                )
            )
            continue
        updated = actual.model_copy(
            update={
                "mandatory": entry.mandatory,
                "route_ids": entry.route_ids,
            }
        )
        records.append(CoverageRecord.model_validate_json(updated.model_dump_json()))
    return tuple(records)
