"""Typed semantic contracts exchanged by final-review stages."""

from __future__ import annotations

from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


RECONCILIATION_MAX_FINDINGS = 8
RECONCILIATION_MAX_TARGETS_PER_FINDING = 12
RECONCILIATION_MAX_SYSTEM_GAPS = 8


class _ReviewTargetBase(BaseModel):
    """Shared fields for one exact reviewer-selected artifact."""

    model_config = ConfigDict(extra="forbid")

    component_id: str


ReviewAddress = Annotated[
    str,
    Field(pattern=r"^(?:0[xX][0-9A-Fa-f]+|[0-9]+)$"),
]


class FunctionReviewTarget(_ReviewTargetBase):
    kind: Literal["function"]
    address: ReviewAddress


class AddressReviewTarget(_ReviewTargetBase):
    kind: Literal["address"]
    address: ReviewAddress


class GlobalReviewTarget(_ReviewTargetBase):
    kind: Literal["global"]
    address: ReviewAddress


class ComponentRecoveryReviewTarget(_ReviewTargetBase):
    """One exact parent byte range and the recovered-artifact analysis it requires."""

    kind: Literal["component_recovery"]
    address: ReviewAddress
    size: int = Field(gt=0, le=64 * 1024 * 1024)
    analysis_objective: str = Field(min_length=1)


class NamedTypeReviewTarget(_ReviewTargetBase):
    kind: Literal["named_type"]
    name: str


class RelationshipReviewTarget(_ReviewTargetBase):
    kind: Literal["relationship"]
    source_address: ReviewAddress
    callsite_address: ReviewAddress | None = None
    destination_address: ReviewAddress
    relationship_kind: str


class LocalVariableReviewTarget(_ReviewTargetBase):
    kind: Literal["local_variable"]
    function_address: ReviewAddress
    lvar_index: int | None = None
    current_name: str | None = None

    @model_validator(mode="after")
    def validate_anchor(self) -> "LocalVariableReviewTarget":
        if self.lvar_index is None and not self.current_name:
            raise ValueError(
                "local_variable targets require lvar_index or current_name"
            )
        return self


# Reconciliation can enforce these existing artifact targets. Child-recovery
# waves belong to independent review and must not leak into its sibling policy.
ReconciliationTarget = Annotated[
    Union[
        FunctionReviewTarget,
        AddressReviewTarget,
        GlobalReviewTarget,
        NamedTypeReviewTarget,
        RelationshipReviewTarget,
        LocalVariableReviewTarget,
    ],
    Field(discriminator="kind"),
]

ReviewTarget = Annotated[
    Union[
        FunctionReviewTarget,
        AddressReviewTarget,
        GlobalReviewTarget,
        ComponentRecoveryReviewTarget,
        NamedTypeReviewTarget,
        RelationshipReviewTarget,
        LocalVariableReviewTarget,
    ],
    Field(discriminator="kind"),
]


class ReviewFinding(BaseModel):
    notebook_refs: list[str] = Field(default_factory=list)
    finding_id: str
    classification: Literal[
        "confirmed_error",
        "unsupported_claim",
        "application_gap",
        "coverage_gap",
        "proposed_investigation",
        "uncertain",
    ]
    priority: Literal["high", "medium", "low"]
    component_id: str
    targets: list[ReviewTarget] = Field(min_length=1)
    title: str
    current_claim: str
    evidence_summary: str
    evidence_refs: list[str] = Field(default_factory=list)
    consequence: str
    recommended_verification: str
    parent_gap_id: str | None = None


class StageReviewReport(BaseModel):
    stage: str
    lane: str
    assessment: str
    findings: list[ReviewFinding] = Field(default_factory=list)
    cleared_targets: list[str] = Field(default_factory=list)
    deferred_questions: list[str] = Field(default_factory=list)


class SystemElement(BaseModel):
    notebook_refs: list[str] = Field(default_factory=list)
    element_id: str
    component_id: str
    related_component_ids: list[str] = Field(default_factory=list)
    workflow: str
    supported_behavior: str
    durable_support: str
    evidence_refs: list[str] = Field(default_factory=list)


class SystemGap(BaseModel):
    notebook_refs: list[str] = Field(default_factory=list)
    gap_id: str
    priority: Literal["high", "medium", "low"]
    component_id: str
    related_component_ids: list[str] = Field(default_factory=list)
    workflow: str
    missing_or_weak_stage: str
    supporting_evidence: str
    evidence_refs: list[str] = Field(default_factory=list)
    consequence: str
    symmetry_only: bool


class SystemModelReport(BaseModel):
    stage: Literal["system_model"]
    assessment: str
    supported_elements: list[SystemElement] = Field(default_factory=list)
    supported_gaps: list[SystemGap] = Field(default_factory=list)
    prose_only_or_isolated_claims: list[str] = Field(default_factory=list)
    preserved_uncertainty: list[str] = Field(default_factory=list)


class ReconciliationFinding(ReviewFinding):
    """One bounded exact finding in a finite reconciliation campaign."""

    targets: list[ReconciliationTarget] = Field(
        min_length=1,
        max_length=RECONCILIATION_MAX_TARGETS_PER_FINDING,
    )


class ReconciliationArtifactReport(StageReviewReport):
    """Artifact report whose worklist is small enough to freeze and finish."""

    findings: list[ReconciliationFinding] = Field(
        default_factory=list,
        max_length=RECONCILIATION_MAX_FINDINGS,
    )


class ReconciliationSystemModelReport(SystemModelReport):
    """System review constrained to its highest-consequence supported gaps."""

    supported_gaps: list[SystemGap] = Field(
        default_factory=list,
        max_length=RECONCILIATION_MAX_SYSTEM_GAPS,
    )


class PlanningDisposition(BaseModel):
    source_finding_id: str
    route: Literal["application_wave", "backlog_parent"]
    priority: Literal["high", "medium", "low"]
    related_source_finding_ids: list[str] = Field(default_factory=list)
    rationale: str


class PlanningWave(BaseModel):
    wave_id: str
    source_finding_ids: list[str]
    rationale: str


class PlanningReport(BaseModel):
    stage: Literal["planning"]
    assessment: str
    dispositions: list[PlanningDisposition] = Field(default_factory=list)
    proposed_waves: list[PlanningWave] = Field(default_factory=list)
