from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    cwe: str
    severity: Severity
    confidence: Literal["high", "medium", "low"]
    file: str
    line: int
    evidence: str
    description: str
    source: str = "deterministic-rule"


class Remediation(BaseModel):
    finding_id: str
    rule_id: str
    summary: str
    steps: list[str] = Field(default_factory=list)
    patch: str = ""
    tests: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class MigrationModule(BaseModel):
    component: str
    current: str
    target: str
    rationale: str
    effort: Literal["S", "M", "L", "XL"]
    risk: Literal["low", "medium", "high"]
    order: int


class MigrationPlan(BaseModel):
    strategy: str
    summary: str
    quick_wins: list[str] = Field(default_factory=list)
    phases: list[str] = Field(default_factory=list)
    modules: list[MigrationModule] = Field(default_factory=list)


class ScanOutput(BaseModel):
    target: str
    engine: str
    model: str
    scanned_files: int
    languages: list[str]
    generated_at: str
    summary: str
    findings: list[Finding]
    remediations: list[Remediation]
    migration: MigrationPlan


class ScanReport(ScanOutput):
    trace: list[str] = Field(default_factory=list)


class FindingList(BaseModel):
    findings: list[Finding]


class RemediationList(BaseModel):
    remediations: list[Remediation]


class MigratedFile(BaseModel):
    path: str
    content: str
    change_summary: str = ""


class MigrationResult(BaseModel):
    summary: str
    remaining_risks: list[str] = Field(default_factory=list)
    suggested_tests: list[str] = Field(default_factory=list)
    files: list[MigratedFile]
