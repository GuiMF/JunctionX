# Asset scoring policy v1

The score is a project quantum-exposure heuristic between 0 and 100; higher means
more exposure. It is not a NIST score, attack probability, compliance verdict, or
measure of whole-application safety. Classical and operational issues remain
separate counts.

For each unique asset ID, take its worst known challenge tier across non-offered
findings: `critical = 100`, `medium = 50`, `resilient = 0`. Average these values
with equal asset weights and round to two decimals. No packet-level averaging or
guessed business criticality is used. Rules classify tiers; the score does not
read filenames, owners, or missing business context.

Unknown-only, offered-only, and not-applicable-only assets are excluded from the
denominator and reported separately. With no assessed assets, the score is `null`,
not zero. Adding unknown assets cannot improve the number. If an asset has both
known and unknown findings, its worst known value is used and it is also counted
under `assets_with_unknowns`. A hybrid connection with unknown authentication can
therefore have a low known-exposure score with explicit incomplete assessment;
the UI must show those unknowns alongside the number.

Example: one RSA asset (100) and one AES-256 asset (0) yield 50. Twenty sightings
of the RSA asset still yield 50. Adding an unknown asset still yields 50, with
`unknown_assets = 1`. A separate AES-128 asset (50) makes three assessed assets
whose score remains 50. AES-128's tier is project policy, not a practical quantum
break claim; see [assessment policy](assessment.md).

The output includes the exact weights, denominator explanation, assessed and total
asset counts, unknown/offer/N/A counts, assets with unknowns, vulnerable/hybrid
counts, classical/posture issue asset counts, and asset counts by evidence kind.
Evidence-kind counts overlap when an asset has multiple kinds and must not be
summed as a unique total. Raw input coverage remains in `ScanResult.coverage`.
