# Agents, OpenAI, Huawei, and synthetic telemetry

Owner: P1. Detection tools are implemented by P2; outbound workflow tools by P3.

## 1. Model and SDK setup

Create an OpenAI API project for Minny, enable API billing/credits, and create a project-scoped server key. Put it in `OPENAI_API_KEY` on the worker only. ChatGPT/Codex access is not used as an API credential. Set `OPENAI_MODEL=gpt-5-mini` for the initial integration; confirm account access with a real structured-output smoke test before freezing the model in configuration. This is a concrete starting choice, not a claim that it is the newest or optimal model. Its documented capabilities include function calling and structured outputs. [Model reference](https://developers.openai.com/api/docs/models/gpt-5-mini).

Use the `openai` Python SDK and the Responses API directly. No second agent framework is required for the first working build. Install compatible stable packages, execute the contract smoke tests, then commit exact resolved versions in a lockfile. Do not invent version pins before they are tested together.

Request strict structured outputs for plans and proposals. Pydantic models use `extra="forbid"`; optional values are explicit nullable fields. Reject a refusal, incomplete response, invalid JSON, or failed local validation as a typed stage error. Structured output constrains shape, not truth. [Structured outputs](https://developers.openai.com/api/docs/guides/structured-outputs).

Illustrative call shape, to validate against the locked SDK:

```python
response = await openai_client.responses.parse(
    model=settings.openai_model,
    input=[
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": serialized_authorized_context},
    ],
    text_format=AttackPlan,
    max_output_tokens=6000,
    store=False,
)
plan = response.output_parsed
if plan is None:
    raise ModelOutputError("No validated attack plan returned")
```

`AttackPlan` is the application Pydantic type specified below. Persist the approved structured output, model identifier, API request/response identifiers, usage, and concise decision summary. Do not request or display hidden chain-of-thought. Store no key or connection secrets in agent context.

## 2. Agents and real collaboration

| Component | Inputs | Authorized actions | Output |
|---|---|---|---|
| Supervisor | technique, persona, finding reference, experiment budgets | Dispatch specialists, route typed feedback, stop or ask for review | State transitions and task assignments |
| Red strategist | technique definition, persona constraints, prior detection feedback | Read supported templates; propose/revise plan | `AttackPlan` |
| Critic | plan, compiled telemetry summary, technique requirements | Deterministic checks; semantic review; request specific revisions | `Critique` |
| Blue analyst | missed variant, baseline rule, retrieved evidence | Retrieve related evidence; propose predicate; request candidate evaluation | `RuleProposal` |
| Workflow executor | validated proposal and approved destination | Publish the fixed workflow through P3 | Artifact references/status |

The supervisor is deterministic application code; the specialists use LLM reasoning. The workflow executor can be deterministic because permissions and artifact ordering are not decisions to improvise. Demonstrate genuine collaboration by persisting typed requests such as “missing parent process evidence” or “candidate matches known benign fixture B4,” then showing how the specialist revises its output. Do not count the telemetry compiler or arbitrary prompt stages as independent intelligent agents.

Messages: `id`, `experiment_id`, `sequence`, `sender`, `recipient`, `kind`, `reply_to`, `summary`, `evidence_refs`, `structured_payload`. `kind` is one of `task`, `proposal`, `critique`, `tool_request`, `tool_result`, `revision`, `decision`. Store messages before dependent work starts.

Huawei scope is the openJiuwen multi-agent challenge under the supplied rules. The project must show task decomposition, messages, tool use, and feedback-driven coordination. Framework usage is optional under those rules. A later JiuwenSwarm adapter must implement the same `run_specialist(role, task, tools, budget)` interface and pass the same tests; do not add a second orchestration system during core integration. JiuwenSwarm documents leader/teammate coordination and OpenAI-compatible model support, but embedding it into this custom API remains additional engineering. [JiuwenSwarm](https://github.com/openJiuwen-ai/jiuwenswarm).

## 3. Bounded tool calling

Blue tools, exposed as strict function schemas:

| Tool | Allowed input | Output and bound |
|---|---|---|
| `get_baseline_rule` | rule_id | Current immutable rule document |
| `get_variant_evidence` | variant_id | At most 200 authorized events |
| `search_related_events` | host_id/user_id, start/end UTC, event category | At most 100 events, maximum 24-hour interval, references included |
| `summarize_event_counts` | known dataset ID, interval, group field enum | Counts from Elastic, at most 100 groups |
| `evaluate_candidate` | allowed predicate AST + rationale | P2 `CandidateReport` |
| `request_review` | reason, evidence_refs | Persist `needs_review`; no publication |

The worker binds workspace, principal, variant, and permissible datasets. Models cannot specify account IDs, repository URLs, destination channels, API keys, shell commands, or arbitrary HTTP endpoints. Tool schemas are the API contract; execute each approved function and return a `function_call_output` correlated to its `call_id` before continuing. Save the response output items needed to continue the documented Responses tool loop. [Function calling](https://developers.openai.com/api/docs/guides/function-calling).

Application budgets per experiment: max 3 red proposals, 2 semantic critic revisions, 3 Blue proposals, 12 total LLM calls, 20 total read/evaluation tool calls, 60,000 total tokens across calls, and 10 minutes active execution. These are design limits, not provider quotas. Stop with `BUDGET_EXHAUSTED` before exceeding the next-call allowance; record actual usage. Start with `max_output_tokens=6000` per call, capped by remaining budget. No automatic infinite mutation. Default follow-up generation limit is one.

## 4. AttackPlan contract

```json
{
  "schema_version": 1,
  "technique_id": "T1059.001",
  "persona": "stealth",
  "objective": "Test whether process identity changes bypass a name-based rule",
  "hypothesis": "The baseline depends on the displayed process name",
  "template_id": "office_interpreter_v1",
  "host_role": "workstation",
  "user_role": "employee",
  "steps": [
    {"step_id":"s1","action":"process_start","role":"document_app","parent_role":null,"delay_ms":0,"attributes":{"identity":"word"}},
    {"step_id":"s2","action":"process_start","role":"interpreter","parent_role":"document_app","delay_ms":1000,"attributes":{"identity":"powershell","display_variant":"renamed"}},
    {"step_id":"s3","action":"network_connection","role":"interpreter","parent_role":null,"delay_ms":2000,"attributes":{"destination_class":"external_test"}}
  ],
  "expected_evidence": ["interpreter process identity", "document-app parent", "network event linked to interpreter"],
  "mutation_of_variant_id": null
}
```

This is an illustrative synthetic scenario, not a finding in the CSE data. P2 owns verification of the technique label and required telemetry. Initial personas: `stealth`, `opportunistic`; attributes are a template-specific enum, not arbitrary strings that become executable commands. Delay range 0-300,000 ms; max 20 steps; all step IDs unique. An unsupported template/technique/action returns validation error, not generic logs mislabeled with that technique.

Supported compiler actions in v1: `process_start`, `network_connection`, `authentication`. Only enable templates whose field requirements and validator exist. File/DNS/cloud events require an additional tested compiler path before being selectable.

## 5. Deterministic compiler

`compile_plan(plan, variant_id, seed, base_time, compiler_version) -> EventSet`:

1. Validate the full plan against the selected template and allowed attributes.
2. Allocate stable `host.id`, `user.id`, `process.entity_id` values using UUIDv5 with a project namespace and variant/role key. PIDs are unique within host and process lifetime; allocate deterministically from a reserved fixture range.
3. Assign UTC event times from frozen `base_time + delay_ms`. Ordering is `(timestamp, step order, event ID)`; simultaneous events retain step order.
4. Build parent references from role→process mappings. Parent must exist before child; root's parent fields are absent. Repeated process instances require separate roles, never reuse an entity ID after process termination.
5. Copy relevant process identity onto network events from the same process role. Never invent a different user/host for a linked event.
6. Use documentation-only addresses `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` and domains under `.example` for synthetic external endpoints. No network requests to these destinations are executed.
7. Assign stable `event.id` from variant + step ID + event kind, and monotonic `event.sequence`.
8. Build ECS-shaped events and explicit Minny provenance. Persist canonical JSON and SHA-256 before indexing.
9. Recompiling the same version/plan/seed/time must produce the same canonical content. Rule replay uses stored events, not a new model call or fresh timestamps.

Use canonical UTF-8 JSON with sorted keys, compact separators, no NaN/Infinity, and stable list order for hashing. Save the exact algorithm version as `canonical_json_v1`.

Never give the detector synthetic labels as behavioral features. `minny.provenance`, variant IDs, event IDs, and ground-truth labels may restrict evaluation or attribute evidence, but cannot make a rule detect an attack by construction.

## 6. Validation

Deterministic rejection conditions:

- Missing required mapped field, invalid type/IP/time, unsupported enum, duplicate event ID.
- Child parent does not exist, child precedes parent, cyclic ancestry, process entity collision.
- Network event refers to absent process or contradictory host/user/process identity.
- Declared technique evidence absent, no causal behavior difference from its parent variant, too many events, or body exceeds size limit.
- Unexpected executable fields, arbitrary model-provided commands/scripts, or executable artifact content.

Semantic critic returns `valid/revise/unsupported`, plus finite issue codes and evidence references. It may reject a technically well-formed plan that does not represent the technique. It cannot override a deterministic failure. `unsupported` stops the experiment with an honest explanation.

Mutation preserves the template's causal behavior and evidence requirements; allowed axes are timing, process display identity, parent identity within template constraints, and volume. Persist `mutation_dimensions` and a diff. Changing only timestamps or event IDs does not count as a meaningful new strategy in the demo.

## 7. Blue proposals

`RuleProposal`: rule_id, technique_ids, title, failure_reason, evidence_refs, predicate AST, explanation, expected_benign_cases, limitations. P2 compiles AST into ES|QL and evaluates it. Blue receives the actual result and chooses revise/pass/request_review. It cannot self-certify detection.

Initial restricted AST supports `all`, `any`, `not`, and leaves `eq`, `in`, `exists` over an allowlist of real event fields. Limits: max depth 4, max 30 nodes, max 10 literals per `in`, max 256 chars per string. No raw query fragments. This makes ES|QL proposals reproducible and prevents a model from switching index targets or querying metadata labels. A raw ES|QL editor can be added later with a stronger parser and authorization model.

Publication includes the compiled ES|QL plus the predicate and validation report. If tests fail or evidence is unclassified, Blue may create a draft proposal for review, but the application cannot call it validated/remediated.

## 8. Files and tests

P1 files: `backend/agents/openai_client.py`, `supervisor.py`, `red.py`, `critic.py`, `blue.py`, `tools.py`, `messages.py`; `backend/simulation/compiler.py`, `templates.py`, `validator.py`, `canonical.py`; prompt templates under `backend/agents/prompts/`.

Required tests:

- Recompile fixture twice → identical hash and parent links.
- Delete parent event → validation failure; zero Elastic/Composio calls.
- Invalid structured model response/refusal → typed failure; no fabricated fallback result.
- Critic revision request → different valid proposal and persisted reply relationship.
- Blue candidate hits benign fixture → feedback revision before publication.
- Model tool call for another workspace/unknown tool → denied, audited, no provider call.
- Agent budget exhausted → stable terminal state, no new job loop.
- Worker restart after saved plan → resumes compilation/evaluation without regenerating plan.
- Live OpenAI smoke test → structured plan + one real tool-result continuation, with request IDs.

OpenAI judging evidence: record the actual runtime API calls powering the product and one Codex contribution with a concrete artifact/test/commit. Huawei evidence: show the critic/Blue feedback loop and tool results in the agent timeline, not merely agent names.
