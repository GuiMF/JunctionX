import scan from '../../../examples/scan-original.response.json';
import migration from '../../../examples/migration.json';
import type { ScanResult } from '../types/contract';
import type { MigrationComparison } from '../types/ui';

// Generated from backend fixtures; the UI never maintains separate findings.
export const mockScanResult = scan as ScanResult;
export const mockMigrationComparison = migration as MigrationComparison;
