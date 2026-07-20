# Page dependency trees

The application uses a single authenticated shell. Every routed page is selected by `ActivePage` in `src/app/App.jsx`.

## Shared shell for every authenticated route

- `src/main.jsx`
  - `src/app/App.jsx`
    - `src/features/auth/AuthGate.jsx`
      - `src/api/client.js`
        - `src/diagnostics.js`
    - `src/app/AppDataContext.jsx`
      - `src/app/useAppData.js`
        - `src/api/client.js`
          - `src/diagnostics.js`
    - `src/app/router.js`
      - `src/app/navigation.js`
      - `src/diagnostics.js`
    - `src/app/layout.jsx`
      - `src/app/navigation.js`
  - `src/app/providers.jsx`
  - `src/diagnostics.js`
  - `src/styles/index.css`
    - `src/styles/tokens.css`
    - `src/styles/base.css`
    - `src/styles.css`
    - `src/styles/automations.css`
    - `src/styles/asset-query.css`
    - `src/styles/assets.css`
    - `src/styles/vulnerabilities.css`
    - `src/styles/remediation.css`
    - `src/styles/auth.css`
    - `src/styles/vm.css`

The unauthenticated entry branch renders `LoginForm` inside `src/features/auth/AuthGate.jsx` with `src/styles/auth.css`; the authenticated branch renders the shared shell above.

## `/vm` — VM Management

Entry: `src/pages/VmManagementPage.jsx`

- `src/pages/VmManagementPage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`
  - `src/shared/ui.jsx`

Renders the operational home/overview: KPI strip, five-stage workflow, start-scan controls, active workflows, remediation campaigns, and workflow/campaign drawers.

## `/connection` — MP VM connection

Entry: `src/pages/ConnectionPage.jsx`

- `src/pages/ConnectionPage.jsx`
  - `src/features/connection/index.jsx`
    - `src/panels.jsx`
      - `src/api/client.js`
        - `src/diagnostics.js`
      - `src/diagnostics.js`
      - `src/shared/format.js`
      - `src/shared/ui.jsx`
      - `src/shared/table.jsx`

Renders endpoint and credential controls, connection status, lookup synchronization, and guarded connection actions.

## `/tasks` — scanner tasks

Entry: `src/pages/TasksPage.jsx`

- `src/pages/TasksPage.jsx`
  - `src/features/tasks/index.jsx`
    - `src/panels.jsx`
      - `src/api/client.js`
        - `src/diagnostics.js`
      - `src/diagnostics.js`
      - `src/shared/format.js`
      - `src/shared/ui.jsx`
      - `src/shared/table.jsx`

Renders task-building controls, task inventory, status/actions, precheck configuration, and post-processing progress.

## `/operations` — operations center

Entry: `src/pages/OperationsPage.jsx`

- `src/pages/OperationsPage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`
  - `src/shared/ui.jsx`
  - `src/shared/table.jsx`

Renders operation KPIs, saved filters, sortable paged operations, health/staleness feedback, and a portal-backed operation detail drawer.

## `/vulnerabilities` — vulnerability dashboard

Entry: `src/pages/VulnerabilitiesPage.jsx`

- `src/pages/VulnerabilitiesPage.jsx`
  - `src/features/vulnerabilities/index.jsx`
    - `src/features/vulnerabilities/VulnerabilitiesDashboard.jsx`
      - `src/api/client.js`
        - `src/diagnostics.js`
      - `src/panels.jsx`
        - `src/api/client.js`
        - `src/diagnostics.js`
        - `src/shared/format.js`
        - `src/shared/ui.jsx`
        - `src/shared/table.jsx`
      - `src/shared/format.js`
      - `src/shared/table.jsx`
      - `src/shared/ui.jsx`
      - `src/features/vulnerabilities/useVulnerabilityDashboard.js`
        - `src/api/client.js`

Renders filters, metric glossary, risk trend visualization, KPI grid, severity distribution, top vulnerabilities/hosts, paged findings, and host/passport drill-down.

## `/remediation` — remediation workspace

Entry: `src/pages/RemediationPage.jsx`

- `src/pages/RemediationPage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`

Renders remediation KPIs, case queue, case editor, verification actions, risk-exception workspace, and SLA policy editor.

## `/coverage` — scan coverage

Entry: `src/pages/CoveragePage.jsx`

- `src/pages/CoveragePage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`

Renders coverage metrics and the actionable list of missing, stale, truncated, or failed asset cards with refresh controls.

## `/asset-query` — asset selection builder

Entry: `src/pages/AssetQueryPage.jsx`

- `src/pages/AssetQueryPage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`
  - `src/shared/table.jsx`
  - `src/shared/ui.jsx`

Renders field indexing status, nested AND/OR rule groups, same-entity matching, result-column controls, sortable results, evidence, pagination, saved views, and CSV export.

## `/automations` — automation builder

Entry: `src/pages/AutomationsPage.jsx`

- `src/pages/AutomationsPage.jsx`
  - `src/api/client.js`
    - `src/diagnostics.js`
  - `src/features/automations/StepEditor.jsx`
    - `src/shared/ui.jsx`
  - `src/shared/ui.jsx`

Renders runbook, schedule, history, and notification tabs; step-based workflow editing; publication confirmation; and run details.

## `/asset-cards` — asset card workspace

Entry: `src/pages/AssetCardsPage.jsx`

- `src/pages/AssetCardsPage.jsx`
  - `src/features/asset-cards/index.jsx`
    - `src/panels.jsx`
      - `src/api/client.js`
        - `src/diagnostics.js`
      - `src/diagnostics.js`
      - `src/shared/format.js`
      - `src/shared/ui.jsx`
      - `src/shared/table.jsx`

Renders searchable local asset cards, asynchronous build/refresh jobs, asset summaries, vulnerabilities, configuration trees, passports, and destructive-action dialogs.

