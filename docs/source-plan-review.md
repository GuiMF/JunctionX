# Source discovery plan review

Reviewed before implementation against board 02 (S1–S5), `docs/contract.md`,
`core/models.py`, and the existing registry and identity helpers.

The scope meets the board. Proceed after making the following implementation
contracts explicit; no contract schema change or third-party runtime dependency
is needed.

## Clarifications required before parallel work

1. **Freeze the parser boundary.** Publish `Detection`, canonical algorithm
   spellings, parameter representation, supported usage values, and parser error
   behavior before agents edit. Java and Go need separate entry points or an
   explicit language argument: `detect(text)` alone cannot dispatch both. Include
   a stable occurrence slot when one call yields multiple facts. Preserve scanner
   rule identity in evidence, since core assessment overwrites `Finding.rule_id`.
2. **Define conservative binding rules.** Resolve constants and imports within
   lexical scope and in source order; invalidate values on reassignment. Function
   arguments, local declarations, and assignments can shadow imported APIs.
   Do not infer an earlier call's parameters from a later assignment, or share a
   receiver's state across unrelated methods. If robust resolution is unavailable,
   drop the unsupported parameter or API match and document the gap. Add focused
   regression cases for these boundaries.
3. **Specify tokenizer limits.** Exclude strings from call matching while retaining
   their decoded value for supported arguments (including Java text blocks and
   Go raw strings), and retain original offsets for line evidence. Detect lexical
   failures and unbalanced delimiters; a bounded tokenizer cannot claim full Java
   or Go syntax validation. Document that distinction. Give bounded-language
   findings conservative detection confidence without lowering confidence merely
   because a parameter is unknown.
4. **Resolve API/usage meaning.** RSA key generation alone does not establish
   signing or key-establishment usage. A bare Go AES block factory has unknown
   mode; only explicit mode construction establishes GCM/ECB. A supported factory
   with a dynamic algorithm can yield `algorithm="unknown"` and a known usage,
   whereas an arbitrary lookalike call must not create an unknown crypto asset.
   Explicitly define whether nested hash factories produce separate hash findings
   alongside PBKDF2/HMAC/signature findings, and use that policy in all labels.
5. **Respect every request bound.** CLI batching must enforce 16 inputs, 8 MiB
   per encoded input, and 16 MiB combined content, and report oversized/unreadable
   files without silently omitting them. Multiple batches need explicit output
   semantics; do not present per-batch scores as a combined repository score.

## Evaluation and integration improvements

- Keep occurrence detection TP/FP/FN separate from parameter correctness so one
  wrong key size does not obscure a correctly found call. Document exact versus
  subset parameter matching and duplicate-occurrence matching. Store independent
  expected labels and corpus hashes/commit; do not derive expectations from
  detector output. Include unsupported organizer constructs in reported recall
  and known gaps rather than silently excluding them from the denominator.
- Define successful file coverage as `assessed=1`, including zero findings and
  dynamic parameters; unknown assets are distinct from unknown file processing.
  Unsupported extension and decode/parse failure use disjoint counters. A partial
  adapter failure must preserve other inputs' findings.
- Verify the default registry change leaves explicitly supplied empty registries
  empty, and normalized fixture import behavior stays intact. Exercise raw source
  through the actual HTTP API and CycloneDX export, not only parser unit tests.
- Keep the proposed ownership split. The Java/Go agent has the heaviest load;
  start with the organizer APIs and shared lexical infrastructure, then add
  holdouts. The evaluation agent should receive the frozen occurrence policy but
  independently read source when assigning labels. The coordinator should create
  the common module before starting all three implementation agents.
- Record CryptoScan's selected version, actual trial outcome or setup blocker,
  and fallback decision. Documentation-only inspection should not be described
  as a successful corpus trial.

## Review disposition

Approved with the clarifications above incorporated into agent handoffs and
verification. The main risk is overconfident lexical/data-flow inference, not
transport or core assessment. Treat unsupported analysis explicitly rather than
expanding into whole-program parsing during this task.
