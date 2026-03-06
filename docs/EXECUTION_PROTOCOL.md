# Execution Protocol v1

## Persona-Led Entry Points

- `grabby task "<request>"`:
  - requires a complete ticket (`Who / What / Why / Definition of Done`) before contract generation
  - interviews the developer
  - selects a persona
  - writes a populated contract and a developer brief
  - can optionally emit a machine-readable session artifact
- `grabby orchestrate "<request>"`:
  - requires a complete ticket (`Who / What / Why / Definition of Done`) before orchestration continues
  - runs the interview
  - writes the populated contract
  - validates the contract
  - hands off across Archie -> Val -> Sage -> Dev -> Iris
  - emits plan, backlog, execution, and audit artifacts in one CLI session

## Non-Interactive Mode

For wrappers, CI, or future IDE integrations:
- pass `--output console|file|both` to control where generated content is written
- pass ticket fields with `--ticket-id`, `--who`, `--what`, `--why`, and `--dod`
- pass task inputs with flags such as `--objective`, `--scope`, `--done-when`, and `--testing`
- use `--yes` or `--non-interactive` to skip prompts
- use `--session-format json|yaml` to emit a machine-readable session artifact
- use `--session-output <path>` to control where that artifact is written
- use `grabby session <file>` to inspect or regenerate those artifacts later
- use `grabby session <file> --check` for CI-friendly validation
- use `grabby session <file> --regenerate --format json|yaml` to rebuild a session artifact from an existing contract and its related files
- use `grabby session <file> --regenerate --output-path <path>` to write the regenerated artifact somewhere else
- use `grabby session --check-all` to validate every session artifact under `contracts/`
- `.grabbyignore` accepts glob patterns and negation (`!pattern`) for ignored artifact paths

## Orchestrated Handoff

1. `Archie` shapes the request into a bounded contract.
2. `Val` validates that the generated contract is structurally safe.
3. `Sage` generates the backlog and execution plan.
4. `Dev` prepares the execution brief.
5. `Iris` prepares the audit checklist.


## Ticket-Aware IDs and Naming

- Work item IDs are ticket-aware: `KEY-123` (`FC-123`, `TT-123`, `JIRA-123`, etc.).
- Grabby normalizes key casing to uppercase.
- Canonical ID resolution order is deterministic:
  1. `**ID:** <ID>` in contract content
  2. Contract filename
  3. Jira key during import
- Canonical artifact filenames:
  - `contracts/<ID>.fc.md`
  - `contracts/<ID>.plan.yaml`
  - `contracts/<ID>.audit.md`
  - `.grabby/metrics/<ID>.metrics.json`
- Validation guards (`validate`, `plan`, `approve`) enforce ID-vs-filename matching and fail fast with rename/edit guidance.
- Branch naming via `grabby start <contract-file> [--type feat|fix|chore]`:
  - `<type>/<ID>-<slug>`
  - slug is lowercase, hyphenated, max 8 words.
- PR/MR template generation via `grabby pr-template <contract-file>`:
  - Title: `<ID>: <Title>`
  - Includes ticket ID, contract path, derived plan/audit paths, and Done-When excerpt.

## Artifact Flow

0. `grabby ticket "<request>"` prints a deterministic markdown ticket draft and does not write a temporary ticket file.

1. `grabby task "<request>"` writes:
   - `contracts/<name>.fc.md`
   - `contracts/<name>.brief.md`
   - optional `contracts/<name>.session.json|yaml`
2. `grabby orchestrate "<request>"` additionally writes:
   - `contracts/<name>.plan.yaml`
   - `contracts/<name>.backlog.yaml`
   - `contracts/<name>.execute.md`
   - `contracts/<name>.audit.md`
3. `grabby prompt <file>` writes:
   - `contracts/<name>.prompt.md`

## Feature Close

- `grabby feature:close <ID>` is the archive flow for completed work.
- `grabby feature gc list` surfaces hanging active contracts that need a developer disposition.
- `grabby feature gc check` is the non-interactive enforcement mode for CI.
- `grabby feature gc keep <ID> <reason>` records an explicit decision to keep a hanging story active.
- Closing a feature writes `contracts/archive/<YEAR>/<ID>.bundle.md`.
- The bundle keeps ticket data, directory rules, context refs, planned file paths, audit summary, validation summary, and branch/PR metadata when available.
- After bundling, active `contracts/active/<ID>.fc.md`, `contracts/active/<ID>.plan.yaml`, and `contracts/active/<ID>.audit.md` artifacts should no longer remain in the active set.
- `.grabby/features.index.json` remains the searchable metadata source and stores the archive pointer plus close date after archival.
- Garbage-collector keep decisions are also persisted in `.grabby/features.index.json` so stale contracts are not silently left hanging.

## Init Output

`grabby init` bootstraps the current repo with:
- `contracts/`
- `.grabby/config.json`
- `.grabbyignore`
- `docs/ARCHITECTURE_INDEX.md`
- `docs/RULESET_CORE.md`
- `docs/ENV_STACK.md`
- `docs/EXECUTION_PROTOCOL.md`
- `.clinerules/00-grabby-core.md` (router rules for Cline)
- `.continue/rules/00-grabby-core.md` (router rules for Continue)
- `.codex/prompts/router.md` (router rules for Codex)

## Method Router

The method router ensures that LLM agents follow the Grabby lifecycle automatically. Router rules are installed for Cline, Continue, and Codex during `grabby init`.

### Routing Logic

1. **Feature request detection**
   - If a request mentions `contracts/<ID>.fc.md` or a valid contract ID, use that contract.
   - Otherwise, route to ticket intake before proceeding.

2. **Ticket intake**
   - Collect required fields: Who, What, Why, Definition of Done.
   - Validate ticket ID format: `[A-Z][A-Z0-9]+-\d+`.
   - Create `contracts/<ID>.fc.md` as draft.

3. **Plan phase (no code changes)**
   - Generate `contracts/<ID>.plan.yaml`.
   - No implementation file modifications allowed.

4. **Approval gate**
   - Execution is blocked until `approval_token: Approved` is present.
   - Explicit user approval required.

5. **Execute phase (scoped changes only)**
   - Modify only files listed in the plan.
   - Stay within allowed directories.
   - Never touch restricted directories.

### Recovery from Failures

If blocked:
1. Report the specific blocker to the user.
2. Do not attempt workarounds that bypass governance.
3. Wait for user guidance or contract amendment.

If plan phase fails:
1. Fix the contract or plan file.
2. Re-run `grabby plan <ID>`.

If execution scope violation detected:
1. Revert out-of-scope changes.
2. Amend the plan if scope expansion is justified.
3. Re-run `grabby approve <ID>` after plan amendment.

### CI/Policy Enforcement

- `grabby guard <contract>` verifies scope compliance before commit.
- CI jobs fail when policy-triggered changes lack a contract, plan, or stay outside approved scope.
- Initial rollout supports allow-failure mode before required enforcement.

## Contract Tracking Mode

Grabby supports two contract tracking modes via `contracts.trackingMode` in `grabby.config.json`:

### tracked (default)
- Contracts are canonical repo artifacts stored in `contracts/`
- Feature indexing includes all contracts in `.grabby/features.index.json`
- Contracts should be committed to the repository

### local-only
- Contracts are disposable local files stored in `.grabby/contracts/`
- Feature indexing excludes local-only contracts from canonical reporting
- Use this mode when external tracking (Jira, etc.) is the source of truth

**Cleanup before check-in:**
- Run `grabby contracts:clean-local` to remove local-only artifacts
- Or manually delete `.grabby/contracts/` before commit
- Add `.grabby/contracts/` to `.gitignore` when using local-only mode

**Recommended .gitignore for local-only mode:**
```
.grabby/contracts/
```

## Two-Phase Execution

### Phase 1: PLAN
- Output: files, rules, risks
- No file edits allowed
- Must be approved before Phase 2

### Phase 2: EXECUTE
- Only modify approved files
- No scope expansion
- Follow `RULESET_CORE` patterns
- Before commit, run `grabby guard <contract.fc.md>` to verify plan/contract scope alignment


## Execution Guard and Pre-Commit Enforcement

- `grabby guard <contract.fc.md>` loads the approved plan and checks current git changes against plan files and contract directory scope.
- `grabby execute <contract.fc.md>` runs execution output, then automatically enforces the same guard before completion.
- If violations exist, execution exits non-zero and prints actionable remediation steps.

## Pre-Execution Validation
```
OK Files in allowed directories
OK No restricted directories
OK Dependencies in allowed list
OK Contract status = approved
```

## Post-Execution Audit
```
OK Files changed as specified
OK Rules compliance
OK Lint passes
OK Build succeeds
```

## Context Envelope
```
@context ARCH_INDEX_v1 section frontend
@context RULESET_CORE_v1 section hooks
@context ENV_STACK_v1
```

## Ticket Shape

Canonical intake format:

```markdown
Who: <actor>
What: <requested change>
Why: <business or developer reason>

Definition of Done
- <criterion>
- <criterion>
```

Legacy `What System:` tickets may be mapped forward during intake, but Grabby now treats contracts in `contracts/<ID>.fc.md` as the canonical repo artifact and warns on deprecated standalone ticket markdown such as `TT-123.md`, `JIRA-123.md`, or `tickets/*.md`.

## Contract Tracking Mode

Grabby supports:
- `contracts.trackingMode=tracked`
- `contracts.trackingMode=local-only`

Behavior:
- `tracked`: contract artifacts are written to `contracts/` and are part of canonical repo history
- `local-only`: working artifacts are written to `.grabby/contracts/`, local activity is logged to `.grabby/feature-log.json`, and canonical repo feature reporting continues to use `contracts/*.fc.md`

Use `local-only` when Jira or another external system is canonical and Grabby should assist locally without duplicating committed tracking artifacts.
