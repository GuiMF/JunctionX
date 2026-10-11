"""Challenge classification must agree across assessment, scoring and exports."""
from core.assessment import assess_finding
from core.models import ScanRequest
from core.service import ScanService
from core.scoring import score_findings
from export.cyclonedx import export_cyclonedx, validate_cyclonedx
from test_assessment import finding


def test_score_counts_legacy_hashes_but_excludes_http_and_missing_context():
    items = [
        finding('SHA-1', 'hash', id='hash', asset_id='hash'),
        finding('EC', 'unknown', id='ec', asset_id='ec'),
        finding('HTTP', 'unknown', id='http', asset_id='http', source_type='cloud', evidence_kind='configured', posture_issues=['HTTP forwarding']),
        finding('HMAC', 'mac', id='mac', asset_id='mac'),
        finding('MD5', 'hash', id='offered', asset_id='offered', evidence_kind='offered'),
    ]
    score = score_findings(map(assess_finding, items))
    assert score['value'] == 75
    assert score['assessed_assets'] == 2
    assert score['unknown_assets'] == score['assets_with_unknowns'] == 1
    assert score['not_applicable_assets'] == score['offered_only_assets'] == 1
    assert score['quantum_vulnerable_assets'] == 1
    assert score['classical_issue_assets'] == score['posture_issue_assets'] == 1


def test_real_hash_scan_exports_new_status_and_classical_issue():
    scan = ScanService().run_scan(ScanRequest(inputs=[{
        'name': 'hashes.py', 'source_type': 'source', 'format': 'raw',
        'content': 'import hashlib\nhashlib.sha1(b"example")\n',
    }]))
    assert scan.status == 'completed'
    assert scan.score['value'] == 50
    assert scan.findings[0].quantum_status == 'quantum_weakened'
    document = export_cyclonedx(scan)
    validate_cyclonedx(document)
    properties = {p['name']: p['value'] for p in document['components'][0]['properties']}
    assert properties['quantumtrace:quantum_status'] == 'quantum_weakened'
    assert properties['quantumtrace:challenge_tier'] == 'medium'
    assert 'collision' in properties['quantumtrace:classical_issues']


def test_tls_policy_explains_unobserved_negotiation_without_inventing_a_group():
    item = finding('unknown', 'key_establishment', source_type='cloud', evidence_kind='configured', parameters={
        'configured_tls_policy': {'name': 'example-policy', 'hybrid_pq_capable': True, 'reference': 'https://example.org/policy', 'mapping_version': 'test'},
    })
    result = assess_finding(item)
    assert result.quantum_status == result.challenge_tier == 'unknown'
    assert result.rule_id.startswith('QT-TLS-NEGOTIATION-UNOBSERVED@')
    assert result.parameters.named_group is None
    assert 'ServerHello' in result.recommendation
    item.parameters.named_group = 'unsupported-group'
    assert not assess_finding(item).rule_id.startswith('QT-TLS-NEGOTIATION-UNOBSERVED@')
