# Shared JSON Schemas

These draft contracts give each builder concrete payloads to work against before live providers are ready. They describe application data, not Composio vendor payloads. Every example is illustrative; no ID/hash/result represents a live run.

| Schema | Producer | Consumer |
|---|---|---|
| [AttackPlan](attack-plan.schema.json) | P1 red strategist/normalizer | P1 compiler/critic, P2 scenario tests |
| [RuleDocument](rule.schema.json) | P1 Blue through P2 compiler/validator | P3 GitHub publication, P2 merged-rule loader |
| [EvaluationResult](evaluation.schema.json) | P2 evaluation adapter | P1 supervisor, P3 completion, P4 UI |
| [VerifiedMerge](verified-merge.schema.json) | P3 authoritative merge verifier | P1 replay scheduler and P2 rule loader |

See [examples](contract-examples.json). Validate with a Draft 2020-12 JSON Schema validator and format checking enabled. P1 owns application schemas and P2/P3 review producer/consumer changes. P3 separately owns `contracts/vendor/composio/` in the future application repository.

## Application validation beyond JSON Schema

The schema is necessary but insufficient. Validate ownership, connected account identity, consent, state transitions, SHA correspondence to actual bytes, allowed repository paths, immutable source provenance, and event/rule semantic correctness in application code.

For AttackPlan, enforce template-specific fields, unique roles/step IDs, valid parent graph, nondecreasing timestamps, evidence requirements, and supported technique. The generic stored schema allows action-dependent attributes; for OpenAI strict output, derive an all-required/nullable model-facing Pydantic representation and normalize null attributes away before storage. Do not pass this generic schema unchanged as a strict API schema.

For rules, enforce maximum AST depth 4 and total node count 30, field-compatible literal types, integer port range, maximum serialized size 64 KiB, `required_fields` consistency, and exclusion of synthetic/ground-truth metadata from predicates. No schema can prove a detector is correct; require P2's actual evaluation report.

For evaluation, schema conditionals prevent an evasion with incomplete ingestion/query and a detected result with zero matched attack events. The evaluator must additionally prove the matched IDs belong to the frozen event set and the query completed without truncation. An error record is never converted to an evasion for display.

For VerifiedMerge, GitHub verification—not the schema—proves the merge occurred. Normalize and validate paths before use; a regex matching `detection-rules/` is not sufficient to prevent path traversal. File bytes must be read at the recorded merged commit.

## Contract-change procedure

1. Producer proposes the changed schema and positive/negative fixtures.
2. Consumers confirm mapping and failure behavior.
3. P1 updates the schema version and migration/compatibility handling where needed.
4. Merge contract/fixtures first, then producer and consumer implementations.
5. Run shared contract tests plus the affected live capability smoke test.

No builder locally renames IDs, stages, or enum values to suit a vendor SDK. Translation belongs inside the corresponding adapter.
