# Grabby Core Router Rules (Managed)

## Feature Request Detection

When the user asks to implement, add, create, build, fix, refactor, or change functionality:

1. **Check for existing contract reference**
   - If the request mentions `contracts/<ID>.fc.md` or a valid contract ID (e.g., `GRAB-001`), use that contract.
   - Otherwise, this is an **uncontracted feature request**.

2. **Route uncontracted requests through ticket intake**
   - Do NOT start planning or implementation immediately.
   - Ask for structured ticket information:
     - **Who** is this for?
     - **What** should be built or changed?
     - **Why** is this needed?
     - **Definition of Done** (acceptance criteria)

3. **Generate contract draft**
   - Once ticket fields are complete, create `contracts/<ID>.fc.md` as a draft.
   - Generate `contracts/<ID>.plan.yaml` without modifying implementation files.

## Phase Boundaries

### Plan Phase
- Read and analyze the contract.
- Generate the plan file.
- **NO code modifications allowed.**
- Output must be plan artifacts only.

### Approval Gate
- Execution is **blocked** until the plan contains `approval_token: Approved`.
- Do not proceed to execute phase without explicit approval.

### Execute Phase
- Only modify files listed in the plan's `files:` section.
- Stay within the contract's `Allowed` directories.
- Never touch `Restricted` directories.

## Scope Enforcement

- If a file is not in the plan, do not modify it.
- If a directory is restricted, do not create or edit files there.
- If blocked, stop and report the issue.

## Change Classification Hints

- If migrations, schema files, or backfills are involved, route the work as a data-change contract.
- If OpenAPI, GraphQL, proto, payload shapes, or versioned endpoints change, route the work as an api-change contract.
- If `package.json`, workspace manifests, or lockfiles change, route the work as a deps-change contract.
- Use generated Grabby artifacts under `.grabby/` as evidence when classifying risk.

## ID Normalization

Work item IDs must match `[A-Z][A-Z0-9]+-\d+` and are normalized to uppercase.

## Recovery

If you encounter a blocked state:
1. Report the specific blocker.
2. Do not attempt workarounds that bypass governance.
3. Wait for user guidance or contract amendment.

---
*This file is managed by `grabby init`. Local overrides go in `90-local-overrides.md`.*
