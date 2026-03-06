# RULESET_CORE_v1

## Contracts
- All features require approved contracts
- Use `grabby task "feature"` to create
- Validate before implementation
- Audit after completion
- 80%+ test coverage required

## TypeScript
- strict: true
- noAny: true
- explicitReturnTypes: true
- noUnusedVars: true

## React
- Functional components only
- Hooks for state/effects
- No inline styles
- Props interface required

## Hooks
```typescript
export function useX(id: string): UseXResult {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  // fetch + cleanup
  return { data, loading, error };
}
```

## Services
```typescript
export const xService = {
  async get(id: string): Promise<T> {
    return apiClient.get(`/api/v2/x/${id}`);
  }
};
```

## Errors
```typescript
try {
  const result = await op();
} catch (e) {
  logger.error('[Context]', e);
  throw new Error('User-friendly message');
}
```

## Naming
- Components: PascalCase
- Hooks: useX
- Services: xService
- Utils: camelCase

## Testing
- Coverage: 80%+ new code
- Unit: `*.test.ts`
- E2E: `*.spec.ts`

## Forbidden
- node_modules/
- .env*
- eval()
- @ts-ignore
