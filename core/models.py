"""Version 1 interchange contract. Missing evidence is never a safe result."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import (
    AwareDatetime, BaseModel, ConfigDict, Field, StringConstraints, model_validator,
)

MAX_SCAN_INPUTS = 10_000
MAX_INPUT_BYTES = 64 * 1024 * 1024
MAX_SCAN_BYTES = 3_000_000_000
MAX_INLINE_SCAN_BYTES = 256 * 1024 * 1024
MAX_UPLOAD_BATCH_BYTES = 64 * 1024 * 1024

Text = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Count = Annotated[int, Field(strict=True, ge=0)]
Positive = Annotated[int, Field(strict=True, gt=0)]
SourceType = Literal["pcap", "source", "cloud"]
Usage = Literal["key_establishment", "signature", "encryption", "hash", "mac", "kdf", "unknown"]
EvidenceKind = Literal["declared", "configured", "offered", "observed"]


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class ConfiguredTLSPolicy(ContractModel):
    name: Text | None = None
    protocols: list[Text] | None = None
    cipher_suites: list[Text] | None = None
    hybrid_pq_capable: bool | None = None
    hybrid_groups: list[Text] | None = None
    classical_fallback: bool | None = None
    negotiated_group: Literal[None] = None
    reference: Text
    mapping_version: Text


class Parameters(ContractModel):
    key_bits: Positive | None = None
    mode: Text | None = None
    named_group: Text | None = None
    hash_algorithm: Text | None = None
    iterations: Positive | None = None
    configured_tls_policy: ConfiguredTLSPolicy | None = None


class Evidence(ContractModel):
    file: Text
    locator: Text
    detail: Text


class Finding(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    id: Text
    asset_id: Text
    source_type: SourceType
    algorithm: Text
    parameters: Parameters = Field(default_factory=Parameters)
    usage: Usage
    evidence_kind: EvidenceKind
    evidence: list[Evidence] = Field(min_length=1)
    confidence: Literal["high", "medium", "low"]
    quantum_status: Literal["vulnerable", "resistant_primitive", "hybrid", "unknown", "not_applicable"] = "unknown"
    challenge_tier: Literal["critical", "medium", "resilient", "unknown"] = "unknown"
    classical_issues: list[Text] = Field(default_factory=list)
    posture_issues: list[Text] = Field(default_factory=list)
    owner: Text | None = None
    observed_at: AwareDatetime | None = None
    rule_id: Text | None = None
    rationale: Text | None = None
    recommendation: Text | None = None
    references: list[Text] = Field(default_factory=list)


class Coverage(ContractModel):
    source_type: SourceType
    input_name: Text
    unit: Literal["files", "packets", "sessions", "resources", "inputs"]
    assessed: Count = 0
    unknown: Count = 0
    unsupported: Count = 0
    failed: Count = 0


class ScanError(ContractModel):
    source_type: SourceType
    input_name: Text
    code: Text
    message: Text


class Relationship(ContractModel):
    source_asset_id: Text
    target_asset_id: Text
    kind: Text
    evidence: list[Evidence] = Field(min_length=1)


class InventoryAsset(ContractModel):
    asset_id: Text
    source_type: SourceType
    kind: Text
    parent_id: Text | None = None
    owner: Text | None = None
    snapshot_at: AwareDatetime | None = None
    account: Text | None = None
    region: Text | None = None
    configuration: dict[str, Any]
    evidence: list[Evidence] = Field(min_length=1)


class Snapshot(ContractModel):
    source_type: SourceType
    input_name: Text
    file: Text
    locator: Text
    generated_at: AwareDatetime
    age_seconds: float


class AdapterResult(ContractModel):
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[Coverage] = Field(min_length=1)
    errors: list[ScanError] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    tool_versions: dict[Text, Text] = Field(default_factory=dict)
    assets: list[InventoryAsset] = Field(default_factory=list)
    snapshots: list[Snapshot] = Field(default_factory=list)


class ScanInput(ContractModel):
    name: Text
    source_type: SourceType
    format: Literal["normalized", "raw"]
    content: str = Field(max_length=MAX_INPUT_BYTES)
    encoding: Literal["utf-8", "base64"] = "utf-8"


class AdapterContext(ContractModel):
    evaluated_at: AwareDatetime


class ScanRequest(ContractModel):
    inputs: list[ScanInput] = Field(min_length=1, max_length=MAX_SCAN_INPUTS)
    evaluated_at: AwareDatetime | None = None
    label: Text | None = None
    synthetic: bool = False

    @model_validator(mode="after")
    def check_inputs(self) -> ScanRequest:
        names = [item.name for item in self.inputs]
        if len(names) != len(set(names)):
            raise ValueError("Input names must be unique within a scan")
        if any(len(item.content.encode("utf-8")) > MAX_INPUT_BYTES for item in self.inputs):
            raise ValueError("Each input must be at most 64 MiB encoded")
        if sum(len(item.content.encode("utf-8")) for item in self.inputs) > MAX_INLINE_SCAN_BYTES:
            raise ValueError("Combined input contents must be at most 256 MiB encoded")
        return self


class ScanResult(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    scan_id: Text
    status: Literal["completed", "partial", "failed"]
    started_at: AwareDatetime
    evaluated_at: AwareDatetime
    ruleset_version: Text
    tool_versions: dict[str, str] = Field(default_factory=dict)
    input_hashes: dict[str, str] = Field(default_factory=dict)
    findings: list[Finding] = Field(default_factory=list)
    coverage: list[Coverage] = Field(default_factory=list)
    errors: list[ScanError] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    assets: list[InventoryAsset] = Field(default_factory=list)
    snapshots: list[Snapshot] = Field(default_factory=list)
    score: dict[str, Any] = Field(default_factory=dict)
    label: Text | None = None
    synthetic: bool = False
