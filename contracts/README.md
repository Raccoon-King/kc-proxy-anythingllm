# Feature Contracts

This directory contains feature contracts for AI-assisted development.

## Commands

```bash
grabby task "request"          # Interview-driven task breakdown
grabby orchestrate "request"   # Full persona handoff
grabby create "feature-name"   # Create new contract
grabby validate file.fc.md     # Validate contract
grabby plan file.fc.md         # Generate plan (Phase 1)
grabby backlog file.fc.md      # Generate Agile backlog
grabby prompt file.fc.md       # Render LLM bundle
grabby session file.fc.md      # Inspect/regenerate session artifact
grabby approve file.fc.md      # Approve for execution
grabby execute file.fc.md      # Execute (Phase 2)
grabby audit file.fc.md        # Post-execution audit
grabby list                    # List all contracts
```

## Workflow

1. Break down work: `grabby task "my-feature"`
2. Orchestrate end-to-end: `grabby orchestrate "my-feature"`
3. Validate: `grabby validate my-feature.fc.md`
4. Generate plan/backlog: `grabby plan my-feature.fc.md` and `grabby backlog my-feature.fc.md`
5. Approve: `grabby approve my-feature.fc.md`
6. Execute: `grabby execute my-feature.fc.md`
7. Audit: `grabby audit my-feature.fc.md`

## Baseline Contracts

`grabby init` can seed baseline contracts for the repository:

- `SYSTEM-BASELINE.fc.md` captures Grabby governance defaults for the project
- `PROJECT-BASELINE.fc.md` captures the detected local stack and directory layout

Review generated baseline contracts before using them as implementation scope.
