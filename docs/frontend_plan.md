# QuantumTrace — Frontend Architecture & Execution Plan (Person 05)

> **Owner:** Person 05 — Experience & Demo  
> **Workspace Boundary:** `web/` + `docs/demo.md`  
> **Target Stack:** React (Vite 5 + TypeScript + Tailwind CSS v3)  
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

Person 05 implements `web/src/types/contract.ts` mirroring the frozen `Finding v1` and `ScanResult v1`:

```typescript
export type SourceType = 'pcap' | 'source' | 'cloud';
export type UsageType = 'key_establishment' | 'signature' | 'encryption' | 'hash' | 'mac' | 'kdf' | 'unknown';
export type EvidenceKind = 'declared' | 'configured' | 'offered' | 'observed';
export type ConfidenceLevel = 'high' | 'medium' | 'low';
export type QuantumStatus = 'vulnerable' | 'resistant_primitive' | 'hybrid' | 'unknown' | 'not_applicable';
export type ChallengeTier = 'critical' | 'medium' | 'resilient' | 'unknown';

export interface FindingEvidence {
  file: string;
  locator: string; // e.g. "lines 42-45", "stream 44, frame 116", "/LoadBalancers/2/Listeners/0/SslPolicy"
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
├── Navbar (Logo, Scan Status, Tab Switcher: "Inventory" vs "Migration", Export Actions)
├── UploadBar (Drag & drop files or 1-click "Load Hackathon Dataset")
├── CoverageCards (3 Cards: Network Traffic, Source Code, Cloud with Assessed/Unknown badges)
├── RiskPostureBanner (Separating Shor Quantum Risk, Classical Flaws, Operational Hygiene)
├── FindingsTable (Search, Source filter, Tier filter, Evidence Kind filter, Owner filter)
├── EvidenceModal (Inspector slide-over showing exact locator, rule rationale, FIPS recommendation)
├── MigrationView (Side-by-side Before/After diff of partner-api-alb with unverified wire callout)
└── Footer (Scan ID, Ruleset version, Hackathon edition stamp)
```

---

## 5. Execution Roadmap & Live Progress

| Sprint / Milestone | Target Window | Deliverables | Current Status |
|---|---|---|---|
| **U1 · Scaffolding & Fixture UI** | Hours 0–3 | Setup Vite 5 + React + Tailwind in `web/`. Implement `types/contract.ts`, `fixtures/mockData.ts`, Layout, Coverage Cards, and Findings Table. | ✅ **DONE** (Built & verified, Node 18+ compatible) |
| **U2 · Complete Flow & Ingestion** | Hours 3–6 | Ingestion bar, simulated scan, Evidence Modal, CycloneDX 1.6 & JSON export. Hook to live `POST /api/scans` when Person 04 delivers API. | 🟡 **IN PROGRESS** (UI flow & exports 100% done; awaiting backend endpoint at Hour 6) |
| **U3 · Prioritization & Evidence Deep-Dive** | Hours 6–12 | Multi-criteria FilterBar (Owner, Source, Tier, Evidence Kind). Evidence inspector showing syntax snippet / packet hex / JSON pointer. | ✅ **INITIAL VERSION COMPLETE** (Filters & Inspector active in UI; awaiting live adapter fixtures) |
| **U4 · Before/After Cloud Migration Diff** | Hours 12–18 | Side-by-side comparison between original and upgraded AWS ALB fixtures (`partner-api-alb`). Emphasize honest posture: config upgraded, wire unverified. | ✅ **AHEAD OF SCHEDULE** (Fully built in `MigrationView.tsx`) |
| **U5 · Polish, Export & Pitch Rehearsal** | Hours 18–24 | CycloneDX 1.6 & JSON exports, keyboard shortcuts, typography polish, write `docs/demo.md`, record backup pitch video. Feature freeze at Hour 21. | 🟡 **READY FOR REHEARSAL** (Exports working; demo script ready) |

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

---

## 8. Current Status Summary (Hour ~1.5 / 24h)

```
[=====================>.......................................] 35% of Total Journey
Person 05 Status: AHEAD OF SCHEDULE

Shipped Artifacts:
  - web/src/types/contract.ts          (Strict contract types for Finding, ScanResult, Coverage)
  - web/src/fixtures/mockData.ts        (Multi-source demo fixtures with intentional edge cases)
  - web/src/components/Navbar.tsx       (Tab navigation, demo reset, JSON & CycloneDX export)
  - web/src/components/UploadBar.tsx    (File ingest + 1-click dataset trigger)
  - web/src/components/CoverageCards.tsx(3-source metrics: assessed vs unknown counts)
  - web/src/components/RiskPostureBanner.tsx (Shor vs Classical vs Operational split)
  - web/src/components/FindingsTable.tsx (Multi-filter search table + tier badges)
  - web/src/components/EvidenceModal.tsx (Deep-dive locator inspector)
  - web/src/components/MigrationView.tsx (Before/after ALB comparison with audit callout)
  - web/src/utils/cbomExport.ts         (CycloneDX 1.6 CBOM and Project JSON generator)

Next Immediate Milestone:
  - Integration Gate 1 (Hour 3-6): Connect live fetch to Person 04's POST /api/scans endpoint once backend comes online.
