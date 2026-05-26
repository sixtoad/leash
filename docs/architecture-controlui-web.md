# Architecture — controlui-web (Next.js)

The Control UI is a single-page Next.js 16 app served at `http://localhost:18080` by the Go daemon. Built with `pnpm build` and embedded into the binary via `//go:embed dist/**`. There are no runtime API routes in Next — everything goes to the daemon at `/api/*`.

> **Adjacent docs:** [`api-contracts-leash-core.md`](api-contracts-leash-core.md) (daemon endpoints this UI calls) · [`component-inventory-controlui-web.md`](component-inventory-controlui-web.md) (full component list) · [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md) (Cedar editor round-trip).

## 1. Toolchain

| Concern | Choice |
|---|---|
| Framework | Next.js 16 (App Router), `output: "export"` |
| Runtime | React 19.2 |
| Language | TypeScript 5 |
| Styling | Tailwind v4 (`@tailwindcss/postcss`), `tw-animate-css` |
| UI primitives | shadcn/ui scaffolding on top of `@radix-ui/*` |
| Editor | `monaco-editor` + `@monaco-editor/react` (Cedar language registered client-side) |
| Server-state | `@tanstack/react-query` v5 (single `QueryClient` in `policy-query-provider.tsx`) |
| Virtualization | `@tanstack/react-virtual` |
| Graphs | `@xyflow/react` + `reactflow` (instance flow) |
| Icons | `lucide-react` |
| Motion | `framer-motion` |
| Fixtures | `@faker-js/faker` (sim mode) |
| Tests | Vitest + Testing Library + jsdom |
| Package manager | pnpm 10 (corepack-pinned in CI) |

## 2. Routing

The App Router has effectively one page:

| Route | File | What it does |
|---|---|---|
| `/` | `src/app/page.tsx` | Mounts the operator console: `DataSourceControls` (sim/live + status), `CedarEditorCollapsible` (Monaco), `ActionsStream` (event table), `PolicyBlocksProvider` (sidebar of policy cards), `SingleHeader` (mode switch), `PromptBanner` (action-based suggestions). |
| `*` (layout) | `src/app/layout.tsx` | Geist sans/mono fonts, dark theme, root providers. |

`next.config.ts` sets `output: "export"`, so the build emits a static asset tree that `internal/ui/handler.go` (`SPAHandler`) serves with appropriate cache headers. No SSR, no API routes, no middleware.

## 3. State architecture

```
┌────────────────────────────────────────────────────────────┐
│              src/app/layout.tsx (server boundary)          │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  PolicyQueryProvider  (TanStack QueryClient)         │  │
│  │  ┌────────────────────────────────────────────────┐  │  │
│  │  │  PolicyBlocksProvider  (server cache + UI fsm) │  │  │
│  │  │  ┌──────────────────────────────────────────┐  │  │  │
│  │  │  │  SingleProvider     (local mode/profile) │  │  │  │
│  │  │  │  ┌─────────────────────────────────────┐ │  │  │  │
│  │  │  │  │  SimulationProvider (dev sim mode) │ │  │  │  │
│  │  │  │  │  ... page.tsx subtree ...          │ │  │  │  │
│  │  │  │  └─────────────────────────────────────┘ │  │  │  │
│  │  │  └──────────────────────────────────────────┘  │  │  │
│  │  └────────────────────────────────────────────────┘  │  │
│  └──────────────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────────────┘
```

| Layer | File | Responsibility |
|---|---|---|
| **PolicyQueryProvider** | `src/lib/policy/policy-query-provider.tsx` | One `QueryClient`. Defaults: `staleTime: 3s`, `retry: 1` (queries), `retry: 0` (mutations). |
| **PolicyBlocksContext** | `src/lib/policy/policy-blocks-context.tsx` | Merges server data (via `policyKeys.detail()`) with a local UI reducer (`editorDraft`, `editorOpen`, `notice`). Exposes ~30 derived selectors and mutation triggers. |
| **PolicyUI reducer** | `src/lib/policy/policy-ui-reducer.ts` | Pure-FSM: `editorDraft`, `editorOpen`, `notice` only. |
| **Mutations** | `src/lib/policy/use-policy-query.ts` | `usePersistCedarMutation`, `usePermitAllMutation`, `useEnforceMutation`, `usePatchPoliciesMutation`. On success they `queryClient.setQueryData(policyKeys.detail(), …)` for optimistic refresh. |
| **SingleContext** | `src/lib/single/store.tsx` | Local mode (`record`/`shadow`/`enforce`/permissive), paused, profile, prompt. |
| **SimulationContext** | `src/lib/mock/sim.tsx` | Dev-only: synthesizes `recentActions`, `instances`, `totals` for the last 60s. Exposes `useSimulation`, `useLatestPolicySnapshot`, `useDataSource` (sim vs live toggle). |

No Zustand, no Redux. All long-term state is server-owned and cached via React Query.

## 4. Daemon API consumption

Every daemon call lives in `src/lib/policy/api.ts`. Base URL resolves to `http://localhost:18080` or `NEXT_PUBLIC_LEASH_API_BASE_URL`. Full request/response shapes are in [`api-contracts-leash-core.md`](api-contracts-leash-core.md); here's the function map:

| Function | Endpoint | Used by |
|---|---|---|
| `fetchPolicyBlocks` | `GET /api/policies` | `usePolicyQuery` (cached query) |
| `fetchPolicyLines` | `GET /api/policies/lines` | `PolicyBlocksProvider` sidebar |
| `fetchPolicyCompletions` | `POST /api/policies/complete` | Monaco completion provider |
| `validateCedarPolicy` | `POST /api/policies/validate` | CedarEditor (500ms debounce) |
| `persistCedarPolicy` | `POST /api/policies/persist?force=1` | `usePersistCedarMutation` |
| `patchPolicies` | `PATCH /api/policies` | `usePatchPoliciesMutation` |
| `setPermitAllMode` | `POST /api/policies/permit-all` | `usePermitAllMutation` |
| `applyEnforceMode` | `POST /api/policies/enforce-apply` | `useEnforceMutation` |
| `addCedarPolicy` | `POST /api/policies/add` | Sidebar quick-add |
| `addPolicyFromAction` | `POST /api/policies/add-from-action` | Per-event add-policy button in ActionsStream |
| `deletePolicyLine` | `POST /api/policies/delete` | Per-line trash button |

Error handling is centralised in `parseErrorPayload()` — it extracts `error.message` plus `error.detail` (`{ line, column, code, suggestion }`) and attaches `detail` to the thrown `Error` so Monaco can display markers inline.

### WebSocket consumption

`src/lib/mock/sim.tsx` synthesizes events for dev mode. The live event stream (`/api`) is not currently consumed by a dedicated React hook in this branch — verify by searching for `new WebSocket` if you need to add a real-time subscriber.

## 5. Cedar editor (Monaco)

Implemented in `src/components/policy/cedar-editor.tsx` + `cedar-language.ts`. Round-trip:

```
keystroke
  └─ Monaco fires onDidChangeContent
       └─ debounce(500ms) → validateCedarPolicy(cedar)
                             └─ POST /api/policies/validate
                                  └─ setModelMarkers(issues)

trigger char (" : . / ( , = !)
  └─ Monaco asks completion provider
       └─ fetchPolicyCompletions({ cedar, cursor })
            └─ POST /api/policies/complete
                 └─ map items → Monaco CompletionItem[]
                      └─ display + render top item in help panel
```

Editor-side language (`cedar-language.ts`):
- Custom language ID `cedar`, Monarch tokenizer (keywords, `Action::`, `File::`, `Dir::`, `Host::`, `MCP::Server::`, `MCP::Tool::`, `Net::DnsZone::`).
- Auto-close pairs, brackets, line + block comments.

Persist flow:
- Ctrl/Cmd-S → `usePersistCedarMutation`. If `enforcementMode === "enforce"`, the editor follows up with `useEnforceMutation` so the persisted source is also applied at runtime.
- Validation errors block persist with a confirmation dialog.

The completion engine on the daemon side is documented in [`design/AUTOCOMPLETE.md`](design/AUTOCOMPLETE.md); the same Mermaid diagrams there show this UI→Go→engine path end-to-end.

## 6. Components by area

Full list in [`component-inventory-controlui-web.md`](component-inventory-controlui-web.md). High-level grouping:

| Area | Path | What's there |
|---|---|---|
| **shadcn primitives** | `src/components/ui/` | avatar, badge, button, card, dropdown-menu, input, label, navigation-menu, scroll-area, separator, table, tabs, tooltip |
| **Policy** | `src/components/policy/` | CedarEditor + Collapsible wrapper, PolicyBlockCard, policy-blocks-grid |
| **Actions stream** | `src/components/actions/` | ActionsStream — virtualised event table with per-row add-policy button |
| **Graph** | `src/components/graph/` | InstancesFlow (xyflow) — agent instance topology with status pulses |
| **Nav** | `src/components/nav/` | Header, DataSourceControls (sim/live toggle) |
| **Single** | `src/components/single/` | SingleHeader (mode tabs), PromptBanner |

## 7. Build pipeline

```
controlui/web/                     ← source
  └─ pnpm install --frozen-lockfile (CI: corepack-pinned pnpm@10.x)
  └─ node scripts/build-if-changed.mjs --out ../../internal/ui/dist
       └─ next build (only if input hash changed)
            └─ static export → internal/ui/dist/
                 └─ //go:embed dist/** (via internal/ui/embed.go)
                      └─ shipped inside the leash binary
```

`make build-ui` runs locally with pnpm or falls back to `make docker-ui` (a `node:22-bookworm` build container) — see [`development-guide.md`](development-guide.md) for the operational details. The Docker variant uses three named volumes for pnpm/corepack/Next caches to keep cold builds tolerable.

## 8. Testing

| File | Coverage |
|---|---|
| `src/components/actions/stream.test.tsx` | Event ingestion, repeat-coalescing, summary totals |
| `src/components/policy/cedar-editor.test.tsx` | Monaco mocking, completion provider, validation marker injection, save flow |
| `src/components/policy/cedar-editor-collapsible.test.tsx` | Open/close, Ctrl+E shortcut, file download button |
| `src/lib/mock/sim.test.ts` | Simulation reducer (ingest, fold repeats, totals, time bucketing) |

Run via `pnpm -C controlui/web test` (uses Vitest). The root Makefile's `make test-web` does the install + run dance.

## 9. Linting & convention notes

- `eslint.config.mjs` extends `next/core-web-vitals` + `next/typescript`. Two rules are turned off for React 19 compatibility: `react-hooks/set-state-in-effect`, `react-hooks/globals`.
- shadcn config (`components.json`) is committed; new components added via shadcn CLI land in `src/components/ui/`.
- All daemon URLs go through `api.ts`; do not call `fetch()` directly in components — it bypasses error normalisation and the env-var base URL.
- Server-state lives in React Query. Local UI flags live in the `policy-ui-reducer`. Do not duplicate.
