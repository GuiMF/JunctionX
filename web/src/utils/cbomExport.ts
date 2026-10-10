import type { ScanResult, Finding } from '../types/contract';

export function exportProjectJson(scanResult: ScanResult) {
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(scanResult, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `quantumtrace-scan-${scanResult.scan_id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}

export function exportCycloneDxCbom(scanResult: ScanResult) {
  const cyclonedx = {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${scanResult.scan_id}`,
    version: 1,
    metadata: {
      timestamp: scanResult.evaluated_at,
      tools: {
        components: [
          {
            type: 'application',
            name: 'QuantumTrace',
            version: '1.0.0-junctionx'
          }
        ]
      },
      component: {
        type: 'application',
        name: 'TargetEnvironment',
        version: '1.0.0'
      }
    },
    components: scanResult.findings.map((f: Finding) => ({
      type: 'cryptographic-asset',
      name: f.algorithm,
      'bom-ref': f.id,
      cryptoProperties: {
        assetType: f.usage === 'signature' ? 'algorithm' : f.usage === 'key_establishment' ? 'protocol' : 'cipher',
        algorithmProperties: {
          primitive: f.usage,
          parameterSetIdentifier: f.algorithm,
          curve: f.parameters.named_group || undefined,
          executionEnvironment: f.source_type
        },
        oid: f.rule_id
      },
      evidence: {
        occurrences: f.evidence.map((ev) => ({
          location: ev.file,
          line: ev.locator,
          symbol: ev.detail
        }))
      },
      properties: [
        { name: 'quantumtrace:quantum_status', value: f.quantum_status },
        { name: 'quantumtrace:challenge_tier', value: f.challenge_tier },
        { name: 'quantumtrace:evidence_kind', value: f.evidence_kind },
        { name: 'quantumtrace:owner', value: f.owner || 'unassigned' },
        { name: 'quantumtrace:recommendation', value: f.recommendation }
      ]
    }))
  };

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(cyclonedx, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `quantumtrace-cbom-${scanResult.scan_id}.cdx.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}
