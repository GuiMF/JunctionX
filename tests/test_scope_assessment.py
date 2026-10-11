"""Challenge classification must agree across assessment, scoring and exports."""
import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import create_app
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


def test_raw_source_and_cloud_assessments_survive_api_storage_scoring_and_exports():
    directory = Path(__file__).resolve().parents[1] / 'cloud-posture'
    snapshots = {path.name: json.loads(path.read_text()) for path in directory.glob('*.json')}
    request = {
        'evaluated_at': '2026-10-10T12:00:00Z',
        'inputs': [
            {'name': 'cloud.json', 'source_type': 'cloud', 'format': 'raw', 'content': json.dumps(snapshots)},
            {'name': 'hashes.py', 'source_type': 'source', 'format': 'raw',
             'content': 'import hashlib\nhashlib.sha1(b"example")\n'},
        ],
    }
    with TestClient(create_app()) as client:
        response = client.post('/api/scans', json=request)
        assert response.status_code == 201
        scan = response.json()
        assert scan['status'] == 'completed' and not scan['errors']
        findings = scan['findings']
        ec_keys = [item for item in findings if item['algorithm'] == 'EC']
        assert len(ec_keys) == 2
        assert all(item['usage'] == 'unknown' and item['quantum_status'] == 'vulnerable'
                   and item['challenge_tier'] == 'critical' for item in ec_keys)
        http = [item for item in findings if item['algorithm'] == 'HTTP']
        assert len(http) == 2 and all(item['quantum_status'] == 'not_applicable' for item in http)
        assert sum('http_forwarding' in item['posture_issues'] for item in http) == 1
        policies = [item for item in findings if item['parameters']['configured_tls_policy']]
        assert len(policies) == 5
        assert all(item['quantum_status'] == 'unknown' and item['parameters']['named_group'] is None for item in policies)
        digest = next(item for item in findings if item['algorithm'] == 'SHA-1')
        assert digest['quantum_status'] == 'quantum_weakened' and digest['challenge_tier'] == 'medium'
        # Eleven critical assets, four resilient AES keys, and one medium hash.
        # Five unobserved TLS negotiations and two HTTP listeners are excluded.
        assert scan['score']['assessed_assets'] == 16
        assert scan['score']['total_assets'] == 23
        assert scan['score']['assets_with_unknowns'] == 5
        assert scan['score']['not_applicable_assets'] == 2
        assert scan['score']['value'] == 71.88

        url = f"/api/scans/{scan['scan_id']}"
        assert client.get(url).json() == scan
        assert client.get(url + '/export?format=json').json() == scan
        exported = client.get(url + '/export?format=cyclonedx')
        assert exported.status_code == 200
        document = exported.json()
        validate_cyclonedx(document)
        for component, item in zip(document['components'], sorted(findings, key=lambda item: item['id']), strict=True):
            properties = {prop['name']: prop['value'] for prop in component['properties']}
            assert properties['quantumtrace:quantum_status'] == item['quantum_status']
            assert properties['quantumtrace:challenge_tier'] == item['challenge_tier']
            assert json.loads(properties['quantumtrace:posture_issues']) == item['posture_issues']
