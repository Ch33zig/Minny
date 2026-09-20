# Elastic, CSE investigation, and detection correctness

Owner: P2. P1 owns agent reasoning and shared persistence.

## 1. Provision Elastic

1. Create an Elastic Cloud Hosted deployment using sponsor access. Choose one region reachable from the backend, and record the exact Elasticsearch version and endpoint in the deployment manifest. The endpoint is Elasticsearch, not the Kibana URL.
2. Bootstrap mappings and indices using an operator credential. Keep that credential out of the application runtime.
3. Create two restricted runtime keys: query key with `read` + `view_index_metadata` for the app's indices, and ingest key with `index` + `read` + `view_index_metadata` on those same indices. Precreate indices so runtime does not need index-management privileges.
4. Use HTTPS with normal certificate verification. Store encoded API-key credentials server-side. API key permissions cannot exceed their creator's privileges. [API-key reference](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-security-create-api-key).
5. Make authenticated `GET /` and a small `POST /_query` work from the worker runtime. Save version/build identifiers and test query result.
6. Set required ES|QL feature gates from actual responses. V1 only needs `FROM`, `WHERE`, `KEEP`, `SORT`, `LIMIT`, `STATS`; do not depend on cross-index joins or vector infrastructure for the core loop.

Logical index names per workspace UUID without hyphens:

- `minny-<workspacehex>-events-v1`: real normalized CSE events.
- `minny-<workspacehex>-lab-v1`: frozen synthetic experiment/background mixtures.
- `minny-<workspacehex>-stream-v1`: paced CSE replay records.

A newly created workspace remains `awaiting_operator_bootstrap` until its indices and baseline fixtures are provisioned. Operator-managed Elastic onboarding is deliberate in this MVP; creating a workspace does not grant index-administration privileges to the runtime. Create all three through `scripts/elastic/bootstrap.py`; store the actual names in workspace configuration. Query adapters receive the resolved name, not arbitrary input. Do not use `FROM *`.

The MVP runs ES|QL itself. It does not automatically create a Kibana Elastic Security scheduled detection rule or claim a native Security alert exists. If that feature is added, it needs a separate deployment adapter, privileges, rule-creation API, schedule, and alert verification test.

## 2. Mapping contract

Root mapping uses `dynamic: strict`; reject unknown normalized fields. Keep unparsed source text in `event.original`, indexed false. Unstructured extra source fields may be retained as a `flattened` `minny.raw_fields` object for display, not detector input. Define every optional field before ingest; omit unknown values rather than inventing them.

| Field | Elastic type | Meaning |
|---|---|---|
| `@timestamp` | date | Original event time / frozen synthetic time |
| `event.id`, `event.kind`, `event.category`, `event.type`, `event.action`, `event.outcome`, `event.dataset` | keyword | Stable identity and classification |
| `event.sequence` | long | Source/compiler order |
| `event.original` | keyword, index false, doc_values false | Original source line |
| `event.ingested` | date | Ingestion time |
| `host.id`, `host.name`, `user.id`, `user.name` | keyword | Entity identity |
| `process.entity_id`, `process.name`, `process.executable` | keyword | Process identity |
| `process.pid`, `process.parent.pid` | long | Process IDs |
| `process.parent.entity_id`, `process.parent.name` | keyword | Parent identity |
| `process.pe.original_file_name` | keyword | Optional PE identity, only when observed/synthetic template provides it |
| `source.ip`, `destination.ip` | ip | Valid IP values |
| `source.port`, `destination.port` | integer | Range checked 0-65535 |
| `network.transport`, `network.direction`, `related.user` | keyword | Network/entity information |
| `message` | text | Searchable description |
| `minny.raw_fields` | flattened | Unmapped source display metadata; not detector features |
| `minny.workspace_id`, `minny.dataset_id`, `minny.experiment_id`, `minny.variant_id` | keyword | Provenance and isolation |
| `minny.event_set_sha256`, `minny.source_sha256`, `minny.parser_version` | keyword | Reproducibility |
| `minny.provenance` | keyword | `cse`, `synthetic`, `fixture` |
| `minny.ground_truth` | keyword | `known_positive`, `known_benign`, `unclassified` |
| `minny.source_file` | keyword | Dataset-relative logical name |
| `minny.source_line` | long | One-based original record position |
| `minny.observed_at` | date | Arrival time during replay |

ECS category/type fields may be arrays. For the initial templates emit one category value per event and test ES|QL comparisons explicitly; add multivalue fixtures before supporting mixed categories. ECS compatibility must be checked field by field; the existing frontend's hard-coded “ECS 8.11” label is not proof of schema validation.

## 3. Ingestion and completeness

Use Bulk API NDJSON with final newline, deterministic `_id`, batches of at most 500 documents or 1 MiB, whichever comes first. `_id` = SHA-256 of workspace + source/event identity + event-set namespace. For lab events, include variant/event-set identity so experiments cannot overwrite each other. Use `index` actions for idempotent re-ingestion; verify every per-item status, not only top-level HTTP 200.

Batch lab ingestion with `refresh=wait_for`; only proceed once all expected IDs are readable and counts match the manifest. This waits for search visibility rather than forcing an immediate refresh. [Refresh semantics](https://www.elastic.co/docs/reference/elasticsearch/rest-apis/refresh-parameter). CSE batch import can omit per-batch waiting, but the final completeness barrier must finish before evaluation.

Record `expected_count`, `accepted_count`, `failed_ids`, `retrieved_count`, source hash, schema version, and queryable timestamp. A failed item, missing document, truncated query, or timeout is `error`, never `evaded`. Retry only rejected transient items; quarantine permanent mapping/parser errors with original record references.

## 4. CSE work is a real investigation

The dataset must be obtained from the event's CSE Discord channel or booth; its format and labels are not yet available. No parser can be claimed finished before inspection.

Required data profiling output `dataset-manifest.json`:

- Dataset title/source and acquisition timestamp; file names, byte sizes, SHA-256 hashes.
- Encoding, compression, delimiter/record structure, header fields, sample count.
- Record count, timestamp format, timezone assumptions, min/max time, duplicate rate.
- Null/malformed counts per required field, entity identifiers, source types, available outcomes.
- Any sponsor-provided labels and their meaning; otherwise all records begin `unclassified`.
- Original-field → ECS-field map, transformations, parser version, discarded/quarantined records.

Timestamp without timezone requires an explicitly recorded source assumption validated with sponsor context; never silently treat it as UTC. Preserve the original timestamp string. Mixed formats need separate parser adapters. Duplicate lines retain source references even when normalization deduplicates events.

Create `backend/data/profile.py`, `parsers/<actual_format>.py`, `normalize.py`, `provenance.py`, `investigate.py`, and `replay.py`. `profile` is read-only; `ingest` and `replay` are separate commands so a user can inspect the transformation first.

Investigation sequence:

1. Summarize counts by time, user, host, outcome, and available event type.
2. Inspect anomalies supported by available fields: repeated auth failures followed by success; unusual account/host combinations; unexpected destination patterns; temporal clusters.
3. Retrieve neighboring original events. Correlate only using fields actually present; a shared timestamp alone is not proof of common actor.
4. Write findings with who, what, when, how, evidence event IDs/source lines, alternative benign explanations, confidence label, and unresolved questions.
5. Ask sponsor hints where the data is ambiguous. Treat confirmed labels separately from model guesses.
6. Turn at least one supported finding into a tested detection rule and demonstrate incremental detection on paced replay.

Do not present the illustrative PowerShell scenario as a CSE finding unless the dataset contains the required evidence. If CSE contains only authentication/network logs, deliver a separate finding/rule in that domain and keep the synthetic process experiment clearly distinct.

### Streaming demonstration

Sort source records by original timestamp and stable source offset. Send one batch every second, at most 100 records/batch. Preserve original `@timestamp`; write current `minny.observed_at`. Persist a replay cursor only after successful ingestion. Advance an event-time watermark, use a 5-minute overlapping detection window, and deduplicate findings by rule + entity + sorted evidence IDs. Restart continues from the saved cursor. Late arrivals within the overlap are reevaluated; later records are flagged for a backfill job. Label this “dataset replay,” not a live corporate feed.

## 5. Detection rule document

Store one JSON document per rule under `detection-rules/<technique>/<rule_id>.json`:

```json
{
  "schema_version": 1,
  "rule_id": "office-interpreter",
  "title": "Interpreter launched by a document application",
  "technique_ids": ["T1059.001"],
  "engine": "esql_predicate_v1",
  "predicate": {
    "all": [
      {"field":"event.category","op":"eq","value":"process"},
      {"field":"process.parent.name","op":"eq","value":"winword.exe"},
      {"field":"process.pe.original_file_name","op":"eq","value":"PowerShell.EXE"}
    ]
  },
  "severity": "medium",
  "description": "Investigate this parent/child combination; it is not proof of compromise.",
  "false_positive_notes": ["Authorized document automation may launch interpreters."],
  "required_fields": ["event.category","process.parent.name","process.pe.original_file_name"],
  "compiler_version": "esql_predicate_v1"
}
```

Store compiled ES|QL in the validation report/PR body; derive it again from the predicate after merge. A submitted compiled query never overrides the canonical predicate. Reject unknown fields/operators, nonfinite values, excessive AST depth, metadata-label predicates, extra query commands, and paths outside the selected rule prefix. Rule maximum size: 64 KiB.

## 6. Controlled baseline/variant demo

For the illustrative T1059.001 template, baseline rule checks `process.name == "powershell.exe"` and document-app parent. A variant changes displayed name while retaining PE identity and behavior evidence. The candidate checks the preserved identity and parent. No command or payload is executed.

Generated ES|QL shape:

```text
FROM minny-<workspacehex>-lab-v1
| WHERE event.category == "process"
    AND process.parent.name == "winword.exe"
    AND process.pe.original_file_name == "PowerShell.EXE"
| KEEP event.id, @timestamp, host.id, user.id, process.entity_id
| SORT @timestamp, event.id
| LIMIT 1000
```

The index token is replaced only by the server's validated index name. Use typed literal serialization/parameters, never string concatenation from raw model output. The request's Query DSL `filter` restricts workspace and frozen event set. The rule does not filter by ground truth. POST `/_query?format=json&allow_partial_results=false`; parse `columns` with `values`, fail on `is_partial`, warnings indicating invalid evaluation, or missing evidence columns. [ES|QL API](https://www.elastic.co/docs/api/doc/elasticsearch/v8/operation/operation-esql-query).

V1 lab set cap: 200 synthetic + 500 background = 700 events. With row-preserving predicates and a 1000-row limit, this is below result truncation. Larger CSE queries need counts/partitioning and explicit completeness checks; never infer “missed” from a limited sample.

## 7. Detection and validation semantics

`detected` requires a successful complete query with at least one matched event ID belonging to the frozen synthetic attack set and satisfying the supported rule's evidence requirements. Matching only background events does not count. `evaded` requires full successful ingestion, readable expected IDs, all baseline rules evaluated successfully, and zero attack evidence matches. Any failure yields `error`.

For v1, use row-preserving rules. Multi-event sequence detectors require a separate evidence-producing evaluator; do not claim that a single-row `WHERE` clause proves ancestry/network temporal correlation. The compiler's ancestry validation is separate from detector capability.

Candidate validation matrix:

| Corpus | Required outcome |
|---|---|
| Missed variant | Detected |
| Original known-positive template | Still detected |
| Prior known-positive variants | No regressions |
| Known-benign fixture set | Zero matches for automatic validation |
| Unclassified CSE slice | Report match count/examples; do not call these false positives |

Report numerator and denominator, corpus hash, rule hash, and limits. “0/40 known-benign fixtures matched” is defensible; “0% false positives” across real traffic is not. Rule logic must not depend on exact synthetic host/user IDs or synthetic labels. Known-benign tests include legitimate interpreter starts from non-document parents, normal document starts, normal outbound connections, and benign missing-field records.

## 8. Merge loading, activation, and replay

P3 supplies a verified merge and retrieves the actual rule file bytes at its commit. P2 validates JSON/schema/predicate, recomputes content hash, compiles ES|QL, and records a `rule_revision`. Re-evaluate the original immutable event set against that revision. If the human changed the proposed rule, validate and test the actual merged content, not the cached proposal.

Candidate/merged tests are isolated from current active rules. After successful replay and regression checks, activate the revision transactionally. Serialize activation per workspace/repository/rule. If another newer merged revision is already active, do not overwrite it with an older completion; mark the result historical and enqueue a current-revision regression. A replay failure keeps the previous active rule and the gap open, with the merged-but-failing status visible.

This “activation” updates Minny's ES|QL evaluator. It does not silently deploy a scheduled rule into a customer's production SIEM.

## 9. Required tests and outputs

- Mapping/type fixture test for every emitted field; bad IP/time quarantined.
- Bulk HTTP 200 with one item failure → evaluation error.
- Search visibility delay → wait, not evasion.
- Background-only match → evaded if attack events miss and evaluation is complete.
- Invalid ES|QL/partial result → error.
- Baseline detects template but misses variant; improved predicate catches both.
- Known-benign matches force revise/review.
- CSE finding evidence resolves back to exact source file/hash/line.
- Dataset replay resumes without duplicate findings.
- Merged file differs from proposal → actual file tested.
- Concurrent merges do not activate an older rule after a newer rule.

Deliver `dataset-manifest.json`, field mapping, `docs/cse-findings.md`, mappings/bootstrap script, baseline/candidate fixtures, evaluation adapter, evidence retrieval tools, and one live evidence-backed before/after run.
