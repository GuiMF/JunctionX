---
name: Cryptographic Discovery & Quantum Resilience Workspace
colors:
  surface: '#f8f9ff'
  surface-dim: '#cbdbf5'
  surface-bright: '#f8f9ff'
  surface-container-lowest: '#ffffff'
  surface-container-low: '#eff4ff'
  surface-container: '#e5eeff'
  surface-container-high: '#dce9ff'
  surface-container-highest: '#d3e4fe'
  on-surface: '#0b1c30'
  on-surface-variant: '#3f4850'
  inverse-surface: '#213145'
  inverse-on-surface: '#eaf1ff'
  outline: '#707881'
  outline-variant: '#bfc7d2'
  surface-tint: '#006398'
  primary: '#006194'
  on-primary: '#ffffff'
  primary-container: '#007bb9'
  on-primary-container: '#fdfcff'
  inverse-primary: '#93ccff'
  secondary: '#006399'
  on-secondary: '#ffffff'
  secondary-container: '#7bc2ff'
  on-secondary-container: '#004f7b'
  tertiary: '#545c72'
  on-tertiary: '#ffffff'
  tertiary-container: '#6c748b'
  on-tertiary-container: '#fefcff'
  error: '#ba1a1a'
  on-error: '#ffffff'
  error-container: '#ffdad6'
  on-error-container: '#93000a'
  primary-fixed: '#cce5ff'
  primary-fixed-dim: '#93ccff'
  on-primary-fixed: '#001d31'
  on-primary-fixed-variant: '#004b73'
  secondary-fixed: '#cde5ff'
  secondary-fixed-dim: '#94ccff'
  on-secondary-fixed: '#001d32'
  on-secondary-fixed-variant: '#004b74'
  tertiary-fixed: '#dae2fd'
  tertiary-fixed-dim: '#bec6e0'
  on-tertiary-fixed: '#131b2e'
  on-tertiary-fixed-variant: '#3f465c'
  background: '#f8f9ff'
  on-background: '#0b1c30'
  surface-variant: '#d3e4fe'
typography:
  display-lg:
    fontFamily: Inter
    fontSize: 32px
    fontWeight: '600'
    lineHeight: 40px
    letterSpacing: -0.02em
  headline-lg:
    fontFamily: Inter
    fontSize: 24px
    fontWeight: '600'
    lineHeight: 32px
    letterSpacing: -0.015em
  headline-md:
    fontFamily: Inter
    fontSize: 20px
    fontWeight: '600'
    lineHeight: 28px
    letterSpacing: -0.01em
  headline-sm:
    fontFamily: Inter
    fontSize: 16px
    fontWeight: '600'
    lineHeight: 24px
    letterSpacing: -0.005em
  body-lg:
    fontFamily: Inter
    fontSize: 15px
    fontWeight: '400'
    lineHeight: 24px
    letterSpacing: '0'
  body-md:
    fontFamily: Inter
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: '0'
  body-sm:
    fontFamily: Inter
    fontSize: 12px
    fontWeight: '400'
    lineHeight: 18px
    letterSpacing: 0.005em
  code-md:
    fontFamily: JetBrains Mono
    fontSize: 13px
    fontWeight: '400'
    lineHeight: 20px
    letterSpacing: -0.01em
  code-sm:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '400'
    lineHeight: 16px
    letterSpacing: '0'
  label-caps:
    fontFamily: Inter
    fontSize: 11px
    fontWeight: '600'
    lineHeight: 16px
    letterSpacing: 0.04em
  label-mono:
    fontFamily: JetBrains Mono
    fontSize: 11px
    fontWeight: '500'
    lineHeight: 14px
    letterSpacing: 0.02em
rounded:
  sm: 0.125rem
  DEFAULT: 0.25rem
  md: 0.375rem
  lg: 0.5rem
  xl: 0.75rem
  full: 9999px
spacing:
  gutter: 1rem
  gutter-dense: 0.5rem
  margin: 1.5rem
  margin-compact: 1rem
  space-xs: 0.25rem
  space-sm: 0.5rem
  space-md: 0.75rem
  space-lg: 1rem
  space-xl: 1.5rem
  space-2xl: 2rem
---

## Brand & Style

This design system establishes a clinical, high-precision engineering workspace tailored for security architects, cryptographic researchers, and systems engineers migrating mission-critical architecture to post-quantum standards.

The visual style is rooted in **Modern Technical Minimalism** combined with structured, high-density data visualization. The interface prioritizes clarity, structural order, and immediate information extraction over decorative ornamentation. Surfaces are crisp, daylight-calibrated, and engineered to prevent fatigue during extended audits of complex dependency graphs, cryptographic primitives, and deep code inspections.

Subtle hairline dividers and tonal shifts provide clear structural hierarchy, ensuring that high-stakes security signals—such as quantum-vulnerable key exchanges or validated post-quantum signature schemes—stand out decisively without visual clutter.

## Colors

The palette operates on calibrated cool slate and daylight-balanced neutrals, anchored by a vibrant yet authoritative electric sky blue for active operations and primary interactive focal points.

### Palette Architecture
- **Canvas & Surfaces:**
  - Base App Canvas: `#f8fafc` (Slate 50)
  - Card & Data Pane Background: `#ffffff` (Pure White)
  - Secondary/Sidebar/Header Surface: `#f1f5f9` (Slate 100)
  - Elevated Popovers/Drawers: `#ffffff`
- **Text & Foreground:**
  - Primary Hierarchy: `#0f172a` (Slate 900) - Headers, active cryptographic paths, high-contrast values.
  - Secondary Hierarchy: `#475569` (Slate 600) - Labels, descriptive metadata, table headers.
  - Muted Hierarchy: `#64748b` (Slate 500) - Timestamps, non-interactive annotations, empty states.
- **Structural Dividers:**
  - Hairline Border: `#e2e8f0` (Slate 200) - Standard container borders, table rows.
  - Strong Border: `#cbd5e1` (Slate 300) - Active splitters, emphasized container boundaries, input field borders.
- **Telemetry & Cryptographic Status:**
  - *Resilient / PQC-Ready / Verified:* `#059669` (Text/Icon), `#ecfdf5` (Surface Tint), `#a7f3d0` (Border Tint).
  - *Warning / Transition / Pending Deprecation:* `#d97706` (Text/Icon), `#fffbeb` (Surface Tint), `#fde68a` (Border Tint).
  - *Critical / Quantum Vulnerable / Deprecated (RSA/ECC):* `#e11d48` (Text/Icon), `#fff1f2` (Surface Tint), `#fecdd3` (Border Tint).
  - *Neutral / Unknown Primitive:* `#475569` (Text/Icon), `#f1f5f9` (Surface Tint), `#cbd5e1` (Border Tint).

## Typography

Typography balances typographic utility with extreme legibility for data-dense software.

- **Primary Typeface (`Inter`):** Handles application UI, administrative workflows, contextual analysis, and interactive controls. Features tight tracking on headings to maintain an engineered, compact feel.
- **Monospace Engine (`JetBrains Mono`):** Applied systematically to all cryptographic identifiers (e.g., `ML-KEM-768`, `ECDH-secp256r1`, `SP 800-208`), object identifiers (OIDs), hash manifests, file paths, and memory addresses.
- **Numeric Data:** Tabular numerals (`tnum`) and slashed zeros (`zero`) are globally enabled for data grids, byte counts, and migration percentage indicators to prevent horizontal jitter during live telemetry ingestion.

## Layout & Spacing

The workspace uses a full-bleed, fluid panel layout structured around a multi-pane split model common to high-throughput IDEs and observability consoles.

### Spatial Architecture
- **Application Shell:** Three-tier vertical hierarchy: Header (48px fixed height), primary multi-column body (flexible left navigation, central discovery table/dependency tree, collapsible right-side telemetry inspector), and an optional bottom audit dock.
- **Grid Structure:** Fluid 12-column sub-grid inside the primary central pane with a default `1rem` (16px) gutter. For high-density telemetry dashboards, collapse to `gutter-dense` (8px).
- **Density Scaling:**
  - *Standard Spacing (`space-lg`, `space-xl`):* Applied to settings, onboarding workflows, and policy configuration screens.
  - *Compact Spacing (`space-xs`, `space-sm`, `space-md`):* Applied to inventory tables, dependency DAG nodes, and certificate detail views to maximize vertical real estate.

## Elevation & Depth

This system avoids heavy drop shadows and fuzzy ambient lighting, relying instead on **low-contrast hairline outlines and tonal layering** to represent stack levels.

### Depth Hierarchy
1. **Level 0 (Canvas Base):** Surface `#f8fafc`. Houses the outer workspace frame and inactive viewports.
2. **Level 1 (Structural Panels & Cards):** Surface `#ffffff` bounded by a 1px solid `#e2e8f0` border. No drop shadow. Data tables and cryptographic inventory grids live at this level.
3. **Level 2 (Inspectors & Dropdowns):** Surface `#ffffff` bounded by a 1px solid `#cbd5e1` border with a subtle technical shadow (`0 2px 4px -1px rgba(15, 23, 42, 0.04), 0 4px 6px -1px rgba(15, 23, 42, 0.02)`).
4. **Level 3 (Modal Dialogs & Command Palettes):** Surface `#ffffff` with a crisp 1px solid `#94a3b8` border, accompanied by an engineered boundary shadow (`0 10px 15px -3px rgba(15, 23, 42, 0.08), 0 4px 6px -4px rgba(15, 23, 42, 0.04)`). The backdrop uses `#0f172a` tinted to 20% opacity.

## Shapes

The interface embraces a precise, calibrated **Soft (Level 1)** geometric standard.

- **Micro Components (0.25rem / 4px):** Checkboxes, status badges, algorithm tags, code snippet chips, input fields, and standard buttons. This crisp radius reinforces tool-like precision.
- **Containers & Panes (0.375rem / 6px to 0.5rem / 8px):** Primary view panels, inspector cards, and modal dialogs.
- **Pill Exceptions:** Rounded-full geometry is strictly prohibited across operational controls, but permitted exclusively on binary toggle switches and live streaming state indicators (e.g., pulsing ping indicators).

## Components

### Buttons & Interactive Controls
- **Primary Button:** Background `#0284c7`, text `#ffffff`, border none. Hover: `#0369a1`. Active: `#075985`. Focus ring: 2px offset with `#38bdf8`.
- **Secondary Button:** Background `#ffffff`, text `#0f172a`, border 1px solid `#cbd5e1`. Hover: `#f8fafc` with border `#94a3b8`.
- **Destructive Button:** Background `#ffffff`, text `#e11d48`, border 1px solid `#fecdd3`. Hover: `#fff1f2` with border `#fda4af`.
- **Dimensions:** Compact standard height of 32px for workspace actions; 28px for dense table-row utilities.

### Status Chips & Badges
- **Algorithm & Protocol Badges:** Monospace font (`JetBrains Mono`, 11px), 20px fixed height, padding `2px 6px`, border-radius 4px.
  - *Classical / Vulnerable (RSA-2048, ECDSA):* `#fff1f2` background, `#e11d48` text, `#fecdd3` border.
  - *Post-Quantum Transition (Hybrid Kyber/X25519):* `#fffbeb` background, `#d97706` text, `#fde68a` border.
  - *Quantum-Resilient (ML-KEM-1024, Falcon-512):* `#ecfdf5` background, `#059669` text, `#a7f3d0` border.

### Input Fields & Search Filters
- **Default State:** Background `#ffffff`, border 1px solid `#cbd5e1`, placeholder `#94a3b8`, text `#0f172a`. Height: 32px.
- **Focus State:** Border 1px solid `#0284c7`, shadow `0 0 0 1px #0284c7`.
- **Query Filter Input:** Integrates leading filter key chips (e.g., `algo:`, `cve:`, `status:`) directly inside the input container using `#f1f5f9` backgrounds with subtle `#cbd5e1` divider borders.

### Cryptographic Inventory Tables
- **Header:** Height 32px, background `#f8fafc`, uppercase text (`label-caps`), color `#475569`, border-bottom 1px solid `#cbd5e1`.
- **Rows:** Alternating subtle banding optional; default `#ffffff`, hover row background `#f1f5f9` with zero lag transition. Height: 36px (dense) to 44px (standard). Border-bottom 1px solid `#e2e8f0`.
- **Cell Alignment:** Checkboxes and numeric metrics aligned strictly left/right respectively; cryptographic strings formatted in `code-sm`.

### Code & Trace Inspectors
- **Container:** Background `#f8fafc`, border 1px solid `#e2e8f0`.
- **Syntax Display:** Crisp monochrome tokens with status-colored keyword highlights for keys, signatures, and cryptographic parameters.