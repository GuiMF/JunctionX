import React from 'react';
import type { ScanResult } from '../types/contract';

export const ScanCoverageNotice: React.FC<{ scan: ScanResult }> = ({ scan }) => {
  if (scan.status === 'completed') return null;
  const gaps = scan.coverage.filter(item => item.unsupported > 0 || item.failed > 0);
  return <section aria-label="Incomplete scan coverage" className="rounded border border-amber-200 bg-amber-50 p-4 text-[13px] text-amber-900">
    <h2 className="font-semibold">{scan.status === 'failed' ? 'Scan failed' : 'Scan partially completed'}</h2>
    <p className="mt-1">{scan.status === 'failed' ? 'The submitted inputs could not be processed successfully.' : 'Available findings are shown, but some input coverage is unsupported or failed.'} Unresolved finding assessments are reported separately below.</p>
    {gaps.length > 0 && <details className="mt-2"><summary className="cursor-pointer font-medium">View coverage gaps</summary><ul className="mt-2 space-y-1">{gaps.map((item, index) => <li key={index} className="break-words">{item.input_name} ({item.source_type}): {item.unsupported} unsupported, {item.failed} failed {item.unit}</li>)}</ul></details>}
  </section>;
};
