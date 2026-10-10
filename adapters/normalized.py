"""Import labelled integration fixtures; this module does not scan source files."""

import base64
import json

from pydantic import BaseModel, ConfigDict
from typing import Literal

from core.models import AdapterContext, AdapterResult, ScanInput

FIXTURE_FORMAT = "quantumtrace.normalized.v1"
IMPORTER_VERSION = "1.0.0"


class NormalizedFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    fixture_format: Literal["quantumtrace.normalized.v1"]
    result: AdapterResult


def input_bytes(scan_input: ScanInput) -> bytes:
    """Decode exactly the submitted content; input names are never opened as paths."""
    if scan_input.encoding == "base64":
        return base64.b64decode(scan_input.content, validate=True)
    return scan_input.content.encode("utf-8")


def import_normalized(scan_input: ScanInput, context: AdapterContext) -> AdapterResult:
    fixture = NormalizedFixture.model_validate(json.loads(input_bytes(scan_input)))
    result = fixture.result.model_copy(deep=True)
    result.tool_versions["normalized-fixture-importer"] = IMPORTER_VERSION
    return result
