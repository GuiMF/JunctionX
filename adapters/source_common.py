"""Internal parser interface; no submitted source is executed."""

from dataclasses import dataclass, field

from core.models import Parameters, Usage

SCANNER_VERSION = "0.3.0"
RULESET_VERSION = "source-api-v4"


class SourceParseError(ValueError):
    """Unsupported or malformed syntax; never expose source in its message."""


@dataclass
class Detection:
    """One explicit call occurrence, with 1-based line and column positions.

    Nested hash constructor calls are separate occurrences even when their digest
    also supplies a parent MAC/KDF/signature parameter. References to constructors
    without a call are not separate occurrences. Slots disambiguate facts at the
    same position and must not contain mutable algorithm names or parameters.
    """

    line: int
    column: int
    algorithm: str
    usage: Usage
    parameters: Parameters = field(default_factory=Parameters)
    api: str = "crypto-call"
    rule: str = "api-call"
    slot: str = "call"
    confidence: str = "medium"
