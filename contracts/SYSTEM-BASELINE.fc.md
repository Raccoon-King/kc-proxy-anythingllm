# Feature Contract: Grabby System Baseline
**ID:** SYSTEM-BASELINE | **Status:** draft
CONTRACT_TYPE: FEATURE_CONTRACT
ARCH_VERSION: v1
RULESET_VERSION: v1
ENV_VERSION: v1

## Objective
Establish the baseline Grabby governance contract for `keycloak-proxy-anythingllm` so initialization, planning, approval, execution, and audit flows start from a consistent contract-aware foundation.

## Scope
- Define the repository-wide expectation that feature work enters through Grabby contracts
- Preserve the phase gate between plan, approve, execute, and audit
- Record baseline contract artifacts generated during `grabby init`
- Capture the initial system understanding for the detected `Node.js project`

## Non-Goals
- Replace detailed per-feature implementation contracts
- Grant blanket approval for future work
- Persist secrets, credentials, or user-specific environment values

## Directories
**Allowed:** `contracts/`, `.grabby/`, `docs/`
**Restricted:** `node_modules/`, `.git/`, `.env*`

## Files
| Action | Path | Reason |
|--------|------|--------|
| create | `contracts/SYSTEM-BASELINE.fc.md` | Establish repository-level Grabby governance baseline |
| create | `contracts/PROJECT-BASELINE.fc.md` | Seed project-specific baseline planning context |
| modify | `contracts/README.md` | Document baseline contract generation for initialized repositories |

## Security Considerations
- [ ] Generated baseline artifacts exclude secrets and environment-specific values
- [ ] Repository restrictions remain enforced before any execution phase
- [ ] Human review is required before baselines are treated as approved implementation scope

## Done When
- [ ] `grabby init` creates this system baseline when it is missing
- [ ] Future work can reference this file for repository governance defaults
- [ ] The generated baseline summary matches the initialized repository at a high level
- [ ] Baseline artifact creation does not overwrite existing contracts

## Testing
- Validate generated contracts with `grabby validate`
- Review generated baseline content after `grabby init`

## Context Refs
- ARCH: stack@v1
- RULESET: imports@v1
- ENV: test-runner@v1

## Status Notes
- Initial assessment summary: Node.js project detected from local repository structure. Primary working areas should be refined after initialization. Testing signals are present in the repository.
