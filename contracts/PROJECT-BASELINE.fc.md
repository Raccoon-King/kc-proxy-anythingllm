# Feature Contract: Project Baseline for Node.js project
**ID:** PROJECT-BASELINE | **Status:** approved
CONTRACT_TYPE: FEATURE_CONTRACT
ARCH_VERSION: v1
RULESET_VERSION: v1
ENV_VERSION: v1

## Objective
Capture the repository baseline for this node.js project so future feature contracts can stay aligned with the detected structure and tooling.

## Scope
- Record the detected stack and primary project directories for planning context
- Establish default implementation areas for feature contracts in this repository
- Document testing and validation expectations inferred from current tooling
- Preserve the generated baseline as a starting point for future contract refinement

## Non-Goals
- Approve or execute work automatically from this baseline
- Replace detailed architecture docs or project README content
- Infer secrets, credentials, or private runtime values from the local environment

## Directories
**Allowed:** `src/`, `lib/`, `tests/`
**Restricted:** `node_modules/`, `.git/`, `.env*`, `coverage/`

## Files
| Action | Path | Reason |
|--------|------|--------|
| create | `contracts/PROJECT-BASELINE.fc.md` | Record the detected repository baseline |
| modify | `contracts/PROJECT-BASELINE.fc.md` | Refine the generated baseline after manual review |
| modify | `contracts/README.md` | Keep contract usage aligned with baseline generation |

## Dependencies
- Detected stack: go, node
- Package/Application: `keycloak-proxy-anythingllm`
- Primary dependency signals: existing repository dependencies

## Security Considerations
- [ ] Baseline content reviewed to ensure no secrets or environment values were captured
- [ ] Allowed and restricted directories match the repository's intended governance boundaries
- [ ] Follow-up contracts refine security-sensitive areas before implementation work begins

## Done When
- [ ] The repository stack baseline matches the current project structure
- [ ] Default contract directories reflect the repository's working areas
- [ ] Testing expectations align with existing scripts or test directories
- [ ] Future contracts can use this file as a project-specific starting point
- [ ] Manual review confirms the baseline contains no sensitive information

## Testing
- Manual review of generated baseline content against the repository layout
- Validate future contracts against this baseline before execution

## Context Refs
- ARCH: stack@v1
- RULESET: imports@v1
- ENV: test-runner@v1

## Status Notes
- Assessment summary: Node.js project detected from local repository structure. Primary working areas should be refined after initialization. Testing signals are present in the repository.
- Root signals considered: `AGENTS.md`, `argocd/`, `certs/`, `contracts/`, `data/`, `docker-compose.test.yml`, `docker-compose.yml`, `docs/`
