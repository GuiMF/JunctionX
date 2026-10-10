# QuantumTrace — Frontend Architecture & Execution Plan (Person 05)

> **Owner:** Person 05 — Experience & Demo  
> **Workspace Boundary:** `web/` + `docs/demo.md`  
> **Target Stack:** React (Vite + TypeScript + Tailwind CSS)  
> **Role Objective:** Turn fragmented cryptographic discoveries into a compelling, evidence-backed migration cockpit that wins the 3-minute hackathon pitch.

---

## 1. Hackathon Scoring Strategy & Person 05's Impact

The brief allocates:
- **40% Accuracy & Risk Scoring:** The UI must visually and semantically separate **Quantum Exposure** (Shor's algorithm breaks RSA/ECC) from **Classical Weaknesses** (MD5, SHA-1, ECB mode) and **Operational Posture** (key rotation, unencrypted HTTP, certificate expiry). It must never invent safety where evidence is missing.
- **25% Input Coverage:** Clearly display source metrics with real units (packets/sessions for network, files/lines for source, ARNs/resources for cloud) and explicit counts for **assessed**, **unknown**, **unsupported**, and **failed**.
- **20% Traceability & Standardization:** Every finding card/row must expand to show **exact evidence** (file line numbers, PCAP stream/frame ID, or AWS JSON pointer). Direct export buttons for **CycloneDX 1.6 CBOM** and normalized project JSON.
- **15% Usability & Demo:** Deliver an intuitive, snappy interface where a judge can identify the single highest-priority issue in under 60 seconds, view its cryptographic evidence, and inspect the before/after migration plan.

---

## 2. Core Architectural Philosophy

### Rule 1: Build Against Fixtures First (Zero Dependency on Backend Completion)
Do not wait for Person 01 (PCAP), Person 02 (Source), Person 03 (Cloud), or Person 04 (API). The contract is frozen (`Finding v1`). We define mock fixture data immediately so the UI is 100% testable and interactive within Hour 2.

### Rule 2: Bulletproof Pitch Resilience (Offline Fallback)
Hackathon presentations fail when live backends crash on stage. The frontend will include a **"Demo Preset / Offline Mode"** toggle that seamlessly loads rich, pre-evaluated fixtures if the live API or network times out.

---

## 3. Data Contracts (TypeScript Definitions)

Person 05 should implement `web/src/types/contract.ts` mirroring the frozen `Finding v1` and `ScanResult v1`:

```typescript
export type SourceType = 'pcap' | 'source' | 'cloud';
export type UsageType = 'key_establishment' | 'signature' | 'encryption' | 'hash' | 'mac' | 'kdf' | 'unknown';
export type EvidenceKind = 'declared' | 'configured' | 'offered' | 'observed';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type QuantumStatus = 'vulnerable' | 'resistant_primitive' | 'hybrid' | 'unknown' | 'not_applicable';
export type ChallengeTier = 'critical' | 'medium' | 'resilient' | 'unknown';

export interface FindingEvidence {
  file: string;
  locator: string; // e.g. "lines 42-48", "stream 3, frame 14", "/LoadBalancers/0/Listeners/1"
  detail: string;
}

export interface Finding {
  schema_version: '1.0';
  id: string;
  asset_id: string;
  source_type: SourceType;
  algorithm: string;
  parameters: {
    key_bits?: number | null;
    mode?: string | null;
    named_group?: string | null;
  };
  usage: UsageType;
  evidence_kind: EvidenceKind;
  evidence: FindingEvidence[];
  confidence: ConfidenceLevel;
  quantum_status: QuantumStatus;
  challenge_tier: ChallengeTier;
  classical_issues: string[];
  owner?: string | null;
  observed_at?: string | null;
  rule_id: string;
  rationale: string;
  recommendation: string;
  references: string[];
}

export interface CoverageBreakdown {
  assessed: number;
  unknown: number;
  unsupported: number;
  failed: number;
  unit: string; // "sessions", "files", "resources"
}

export interface ScanResult {
  schema_version: '1.0';
  scan_id: string;
  started_at: string;
  evaluated_at: string;
  ruleset_version: string;
  tool_versions: Record<string, string>;
  input_hashes: Record<string, string>;
  findings: Finding[];
  coverage: {
    network: CoverageBreakdown;
    source: CoverageBreakdown;
    cloud: CoverageBreakdown;
  };
  errors: string[];
}
```

---

## 4. UI Layout & Component Hierarchy

```
App
├── Navbar (Logo, Scan Status, Mode Toggle: "Live API" vs "Demo Fixtures", Export Button)
├── UploadHero / IngestBar
│   ├── Dropzone for PCAP, Source code archive, AWS JSON exports
│   └── "Load Sample Hackathon Data" (1-click instant demo)
├── CoverageDashboard (3 Source Cards: Network, Code, Cloud with Assessed vs Unknown badges)
├── RiskPostureBanner (Separating Shor/Quantum Break, Classical Weaknesses, Operational Hygiene)
├── FilterBar (Filter by Owner, Input Source, Risk Tier, Evidence Kind, Search)
├── FindingsInventoryTable
│   ├── Priority Badge (Critical / Medium / Resilient)
│   ├── Algorithm & Usage (e.g. RSA-1024 [Signature], Ed25519 [Signature], TLS 1.3 [KEM Draft])
│   ├── Source & Owner Tag (e.g. "cloud" -> Team Alpha)
│   ├── Evidence Kind Pill ("Configured" vs "Observed" vs "Declared")
│   └── Action: "Inspect Evidence"
├── EvidenceDrawer (Slide-over deep dive)
│   ├── Code viewer / Packet frame detail / Cloud JSON pointer
│   ├── Exact rationale & risk justification
│   └── Specific migration recommendation (e.g. "Migrate RSA-1024 to ML-DSA-65")
└── MigrationComparisonModal ("Before vs After" Demo)
    ├── Original Fixture: partner-api-alb (ELBSecurityPolicy-TLS13-1-2-2021-06) -> Non-PQ TLS 1.3
    ├── Modified Fixture: partner-api-alb (ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09) -> Hybrid PQ
    └── Clear Callout: "PQ-capable configuration; negotiated wire use unverified"
```

---

## 5. Execution Roadmap (Milestones U1 to U5)

| Sprint / Milestone | Target Window | Deliverables | Key Verification |
|---|---|---|---|
| **U1 · Scaffolding & Fixture UI** | Hours 0–3 | Setup Vite + React + Tailwind in `web/`. Implement `types/contract.ts`, mock `scanResultFixture.json`, Layout, Coverage Cards, and Findings Table. | App loads mock data immediately; table sorts and displays all 3 source types. |
| **U2 · Ingestion Flow & API Hookup** | Hours 3–6 | Build file upload / preset loader. Hook to `POST /api/scans` and `GET /api/scans/:id` (with graceful mock fallback). Add Loading, Error, and Empty states. | Uploading triggers scan simulation or live backend; passes Gate 1. |
| **U3 · Prioritization & Evidence Deep-Dive** | Hours 6–12 | Implement FilterBar (Owner, Source, Tier, Evidence Kind). Build EvidenceDrawer showing syntax snippet / packet hex / JSON locator + remediation steps. | A judge can locate the critical RSA-1024 finding and its line number in 15 seconds. |
| **U4 · Before/After Cloud Migration Diff** | Hours 12–18 | Implement side-by-side comparison between original and upgraded AWS ALB fixtures (`partner-api-alb`). Emphasize honest posture: config upgraded, but wire traffic unverified. | Visually highlights configuration change without falsifying observed traffic. |
| **U5 · Polish, Export & Pitch Rehearsal** | Hours 18–24 | Wire up CycloneDX 1.6 & JSON export downloads. Build keyboard shortcuts, polish typography, write `docs/demo.md`, record backup pitch video. Feature freeze at Hour 21. | Pitch runs under 3 minutes cleanly; zero console errors on clean startup. |

---

## 6. Critical Accuracy Guardrails for the UI

1. **ClientHello Offer ≠ ServerHello Selection:**  
   Never display a client cipher suite offer as "negotiated encryption". Label it clearly as `Offered (ClientHello)`.
2. **Ed25519 is NOT Post-Quantum:**  
   Ed25519 is elliptic curve (classical). Tag it as `Quantum Vulnerable (Shor)`.
3. **TLS 1.3 ≠ Quantum Resilient:**  
   Unless a standardized hybrid group (like X25519MLKEM768) is negotiated, TLS 1.3 is still classical. Keep key exchange and authentication statuses distinct.
4. **Preserve Unknowns:**  
   In TLS 1.3, certificates are encrypted on the wire. The UI must explicitly state: `Authentication: Unknown (encrypted handshake)` rather than assuming RSA or PQC.
5. **Simulated Config ≠ Wire Traffic:**  
   When showing the ALB upgrade to `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`, explicitly display:  
   *`"Configuration: Post-Quantum Capable. Observed Wire Negotiation: Unverified."`*

---

## 7. The 3-Minute Demo Pitch Choreography (`docs/demo.md`)

- **0:00 – 0:25 (The Problem & Ingestion):**  
  Click "Load Sample Environment". Explain: *"Organizations don't know where their crypto lives. QuantumTrace ingests 2,000 packets, 24 code files across 3 languages, and 21 AWS resources."*
- **0:25 – 1:00 (Coverage & Honest Uncertainty):**  
  Point to the Coverage Cards. Explain: *"Notice we don't give a fake 100% score. We show 12 verified algorithms, 4 unknown parameters, and 2 unsupported legacy protocols. Honesty first."*
- **1:00 – 1:35 (Evidence Traceability):**  
  Click on `RSA-1024` and open the Evidence Drawer. Show exact file and line number. Point to the recommendation: *"Migrate to ML-DSA-65. Notice it says ML-DSA for signatures, not ML-KEM."*
- **1:35 – 2:15 (Before vs After Migration):**  
  Switch to the "Migration Comparison" tab. Compare `partner-api-alb` before and after. Show how the policy upgraded, while keeping the badge *"negotiated traffic unverified"*.
- **2:15 – 2:40 (Actionable Ownership & CBOM Export):**  
  Filter by Owner `Team-Identity`. Click "Export CycloneDX 1.6 CBOM".
- **2:40 – 3:00 (Architecture & Conclusion):**  
  Summary of reused components (TShark, deterministic Python engine) vs our original evidence correlation model. Done on time!
