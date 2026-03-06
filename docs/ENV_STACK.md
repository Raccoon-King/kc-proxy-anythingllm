# ENV_STACK_v1

## Runtime
- Node: 18+
- Package Manager: npm

## Commands
| Task | Command |
|------|---------|
| Dev | `npm run dev` |
| Build | `npm run build` |
| Lint | `npm run lint` |
| Test | `npm run test` |
| E2E | `npm run test:e2e` |

## Checks
| Profile | Lint | Test | Build |
|---------|------|------|-------|
| `web-ui` | `npm run lint` | `npm run test` | `npm run build` |
| `api-service` | `npm run lint` | `npm run test` | `npm run build` |
| `fullstack` | `npm run lint` | `npm run test` | `npm run build` |

## Git Commands
| Task | Command |
|------|---------|
| Status | `grabby git:status` |
| Sync | `grabby git:sync` |
| Start Branch | `grabby git:start <contract>` |
| Update Branch | `grabby git:update` |
| Preflight | `grabby git:preflight [contract]` |

## Key Paths
- Config: `vite.config.ts`, `tsconfig.json`
- Types: `src/types.ts`
- Tests: `src/tests/`, `e2e/`
