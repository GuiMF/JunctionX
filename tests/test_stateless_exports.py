import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.main import create_app
from export.cyclonedx import validate_cyclonedx


@pytest.mark.parametrize("format", ["json", "cyclonedx"])
def test_export_on_another_instance_without_saved_scan(format):
    request = json.loads((Path(__file__).parents[1] / 'examples/scan-source.request.json').read_text())
    with TestClient(create_app()) as first:
        scan = first.post('/api/scans', json=request).json()
        expected = first.get(f'/api/scans/{scan["scan_id"]}/export?format={format}').json()
    with TestClient(create_app()) as second:
        assert second.get(f'/api/scans/{scan["scan_id"]}/export').status_code == 404
        exported = second.post(f'/api/exports?format={format}', json=scan)
        assert exported.status_code == 200, exported.text
        assert exported.json() == expected
        if format == 'cyclonedx':
            validate_cyclonedx(exported.json())
        assert 'attachment' in exported.headers['content-disposition']
        assert second.get(f'/api/scans/{scan["scan_id"]}').status_code == 404


def test_stateless_export_validates_input_without_echoing_it():
    with TestClient(create_app()) as client:
        response = client.post('/api/exports', json={'secret': 'never-echo-this'})
        assert response.status_code == 422
        assert 'never-echo-this' not in response.text


@pytest.mark.parametrize("format", ["json", "cyclonedx"])
def test_stateless_export_rejects_duplicate_finding_ids_without_echoing_them(format):
    request = json.loads((Path(__file__).parents[1] / 'examples/scan-source.request.json').read_text())
    with TestClient(create_app()) as client:
        scan = client.post('/api/scans', json=request).json()
        scan['findings'][0]['id'] = 'private-finding-id-never-echo'
        scan['findings'].append(dict(scan['findings'][0]))
        response = client.post(f'/api/exports?format={format}', json=scan)
        assert response.status_code == 422
        assert response.json() == {'detail': 'Finding IDs must be unique for export'}
        assert 'private-finding-id-never-echo' not in response.text
