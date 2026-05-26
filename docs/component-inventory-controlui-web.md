# Component Inventory — controlui-web

Generated from a code-survey of `controlui/web/src/components/**`. Components are grouped by directory; props lists call out only the non-obvious entries.

## ui/ — shadcn primitives

These are stock shadcn/ui components scaffolded on top of `@radix-ui/*`. Added/removed via the shadcn CLI; configuration in `components.json`. No project-specific logic.

`Avatar`, `Badge`, `Button`, `Card`, `Dropdown-Menu`, `Input`, `Label`, `Navigation-Menu`, `Scroll-Area`, `Separator`, `Table`, `Tabs`, `Tooltip`

## policy/ — Cedar editor and policy display

| Component | File | Purpose |
|---|---|---|
| `CedarEditor` | `src/components/policy/cedar-editor.tsx` | Monaco editor wired to the daemon's completion and validation APIs. Registers `cedar` language, completion provider, and on-change validator (500ms debounce). Ctrl/Cmd-S persists. Props: `showHeader?: boolean`. |
| `CedarEditorCollapsible` | `src/components/policy/cedar-editor-collapsible.tsx` | Collapsible wrapper. Ctrl+E toggles, footer has copy/download buttons. Props: `defaultOpen?: boolean`. |
| `cedar-language.ts` | `src/components/policy/cedar-language.ts` | Monaco language definition (keywords, entity-type tokenizers, comment/bracket pairs). Not a React component — registered on editor mount. |
| `PolicyBlockCard` | `src/components/policy/policy-block-card.tsx` | Single policy line: effect icon, humanized description, copy + delete buttons. Props: `line: PolicyLine`, `onRemoved?`. |
| `policy-blocks-grid` | `src/components/policy/policy-blocks-grid.tsx` | Sidebar grid of `PolicyBlockCard`s, sourced from `GET /api/policies/lines`. |

## actions/ — event stream

| Component | File | Purpose |
|---|---|---|
| `ActionsStream` | `src/components/actions/stream.tsx` | The main live-event table. Virtualised (`@tanstack/react-virtual`). Columns: timestamp, type (file.open / connect / proc.exec / mcp.*), subject, decision, instance. Filter chips, repeat-coalescing badges, per-row "Add policy" buttons that fire `addPolicyFromAction`. Props: `instanceId?`, `onPolicyMutated?`. |

## graph/ — visualisations

| Component | File | Purpose |
|---|---|---|
| `InstancesFlow` | `src/components/graph/instances-flow.tsx` | `@xyflow/react` diagram of agent instances. Cyberpunk-styled gradient nodes per agent type (Claude Code / Codex / Cursor / Other), animated edges representing simulated data flow, pulsing online indicator. Hover tooltip shows recent activity breakdown. Includes MiniMap with `nodeColor` mapping and zoom/pan controls. Currently mounted in the sim path only. |

## nav/

| Component | File | Purpose |
|---|---|---|
| `Header` | `src/components/nav/header.tsx` | Page chrome — logo, branding. |
| `DataSourceControls` | `src/components/nav/data-source-controls.tsx` | Sim/live mode toggle + connection status badge. Drives `useDataSource()`. |

## single/

| Component | File | Purpose |
|---|---|---|
| `SingleHeader` | `src/components/single/header.tsx` | Enforcement-mode tab strip (Permissive / Enforcing). Fires `usePermitAllMutation` / `useEnforceMutation`. |
| `PromptBanner` | `src/components/single/prompt-banner.tsx` | Action-based policy suggestion banner. Surfaces when ActionsStream emits a candidate. |

## Hooks worth knowing

| Hook | File | Purpose |
|---|---|---|
| `usePolicyQuery` | `src/lib/policy/use-policy-query.ts` | TanStack Query wrapper around `GET /api/policies`. Key: `policyKeys.detail()`. |
| `usePersistCedarMutation` | same | `POST /api/policies/persist?force=1`. |
| `usePatchPoliciesMutation` | same | `PATCH /api/policies`. |
| `usePermitAllMutation` | same | `POST /api/policies/permit-all`. |
| `useEnforceMutation` | same | `POST /api/policies/enforce-apply`. |
| `useSimulation` | `src/lib/mock/sim.tsx` | Sim-mode actions + instances + totals. |
| `useLatestPolicySnapshot` | same | Reads most recent `policy.snapshot` from sim/live. |
| `useDataSource` | same | Sim vs live toggle. |
| `useSingle` | `src/lib/single/store.tsx` | Local mode + profile + paused state. |

## Lib modules (non-component)

| Module | File | Role |
|---|---|---|
| API client | `src/lib/policy/api.ts` | All daemon HTTP calls. The single source of truth for endpoint URLs and response shapes. |
| Query keys | `src/lib/policy/policy-keys.ts` | TanStack Query key factories. |
| Policy context | `src/lib/policy/policy-blocks-context.tsx` | Merge of server data + UI reducer (`editorDraft`, `editorOpen`, `notice`). |
| UI reducer | `src/lib/policy/policy-ui-reducer.ts` | Pure FSM for editor UI state. |
| Simulation | `src/lib/mock/sim.tsx` | Dev-mode synthetic event stream. |
| Single store | `src/lib/single/store.tsx` | Local mode/profile/paused state. |
| Utilities | `src/lib/utils.ts` (typical shadcn) | `cn()` classname merger (Tailwind-merge + clsx). |

## Public assets

| File | Status |
|---|---|
| `public/logo.svg` | Active — recoloured at render time via CSS filter. |
| `public/next.svg`, `vercel.svg`, `globe.svg`, `file.svg`, `window.svg` | Stock Next starter assets — unused; safe to remove. |
