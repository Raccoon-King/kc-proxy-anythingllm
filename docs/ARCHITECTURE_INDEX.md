# ARCH_INDEX_v1

## Stack
- Frontend: React + TypeScript + Vite
- Backend: Go + PostgreSQL
- Tests: Jest + Playwright
- Contracts: Grabby CLI

## Contract Management
```bash
grabby task "feature"        # Create contract
grabby validate <file>       # Validate
grabby plan <file>           # Generate plan
grabby execute <file>        # Execute
grabby audit <file>          # Audit
```

## Module Map

### §frontend
```
src/
├── components/     # React components by feature
├── hooks/          # Custom React hooks
├── services/       # API layer
├── utils/          # Pure utility functions
├── types.ts        # Shared TypeScript types
└── constants.ts    # App constants
```

### §backend
```
backend/
├── handlers/       # Request handlers
├── models/         # Data structures
├── repository/     # Database operations
└── validators/     # Input validation
```

### §api
- Base: `/api/v2/`
- Methods: GET, POST, PUT, DELETE
- Format: JSON

### §patterns
- Components: Functional only, typed props
- State: Custom hooks, no Redux
- API: Services wrap fetch
- Errors: try/catch + user messages

### §boundaries
- Frontend ↔ Backend: JSON/HTTP
- No direct DOM manipulation
- No inline styles
- No class components
