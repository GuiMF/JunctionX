import hashlib
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

@dataclass
class ScanInput:
    path: str = ""
    inline_content: bytes = b""

@dataclass
class AdapterContext:
    pass

@dataclass
class Finding:
    id: str
    asset_id: str
    source_type: str
    algorithm: str
    usage: str
    evidence_kind: str
    evidence: List[Dict[str, Any]]
    confidence: str
    observed_at: str
    key_bits: Optional[int] = None
    mode: Optional[str] = None

@dataclass
class AdapterResult:
    findings: List[Finding] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    assessed_sessions: int = 0
    unknown_sessions: int = 0
    unsupported_sessions: int = 0
    failed_sessions: int = 0

def stable_asset_id(capture_identity: str, flow_key: str) -> str:
    hash_input = f"{capture_identity}|{flow_key}".encode('utf-8')
    return f"asset-{hashlib.sha256(hash_input).hexdigest()[:12]}"

def stable_finding_id(role: str, slot: str, evidence_kind: str) -> str:
    hash_input = f"{role}|{slot}|{evidence_kind}".encode('utf-8')
    return f"finding-{hashlib.sha256(hash_input).hexdigest()[:12]}"
