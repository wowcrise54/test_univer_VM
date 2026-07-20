# MP VM Client design system

## Product context

MP VM Client is a Russian-language operational workspace that connects to MP VM over REST, persists normalized security data in PostgreSQL, and guides a security team through a continuous workflow:

1. establish and validate the MP VM connection;
2. configure and run scanner tasks;
3. monitor long-running operations and post-processing;
4. review vulnerabilities, assets, passports, and scan coverage;
5. assign remediation work, manage SLA/risk decisions, and verify fixes;
6. export evidence and automate repeatable runbooks.

Primary users are vulnerability-management operators, security analysts, and administrators. The interface should communicate control, system health, traceability, and safe execution. It should feel like a serious security operations product, not a generic consumer SaaS site.

## Language and content

- Primary UI language: Russian.
- Product and protocol terms may remain in English where the application already uses them: MP VM, REST API, PostgreSQL, PDQL, CSV, SLA, CVE, Docker.
- Headlines should be concise and operational.
- Supporting copy should describe observable outcomes and workflow continuity.
- Avoid fear-based security marketing, vague “AI-powered” claims, and unsupported performance claims.
- Calls to action should use concrete verbs such as “Открыть приложение”, “Посмотреть возможности”, or “Настроить подключение”.

## Core visual character

- Light, precise, operational, and trustworthy.
- Pale blue-gray environment with clean white surfaces.
- Dark navy anchors for product identity and navigation.
- Royal blue for primary actions, teal/green for verified/success states, orange for warnings, and red only for destructive or critical states.
- Soft elevation, restrained gradients, thin blue-gray borders, and rounded geometry.
- Dense information is acceptable when hierarchy remains strong and controls stay readable.

## Color tokens

Use only these colors and derived translucent variants already present in the application.

| Role | Token/value | Usage |
| --- | --- | --- |
| Workspace background | `#eef3f8` / `--bg` | Main page background |
| Soft background | `#f7fafc` / `--bg-soft` | Subtle sections and grouped controls |
| Panel | `#ffffff` / `--panel` | Cards, panels, mock product surfaces |
| Muted panel | `#f8fbff` / `--panel-muted` | Secondary surfaces |
| Primary text | `#102033` / `--text` | Headlines and body copy |
| Muted text | `#64748b` / `--muted` | Supporting copy and metadata |
| Border | `#d9e4f0` / `--line` | Default separators |
| Strong border | `#c7d5e6` / `--line-strong` | Active/structured separators |
| Navy | `#0b1f35` / `--navy` | Strong brand surfaces |
| Navy secondary | `#12304d` / `--navy-2` | Navy gradients and secondary dark surfaces |
| Primary blue | `#2563eb` / `--blue` | Primary actions and active states |
| Blue soft | `#e6f0ff` / `--blue-soft` | Active backgrounds and highlights |
| Teal | `#0d9488` / `--teal` | Progress, verified workflow accents |
| Success green | `#15803d` / `--green` | Success and completion |
| Warning orange | `#b45309` / `--orange` | Degraded and attention states |
| Danger red | `#dc2626` / `--red` | Destructive actions and critical failures |
| Brand highlight | `#7dd3fc` to `#99f6e4` | Existing MP mark and limited accent use |

Do not introduce purple, magenta, neon, black-heavy, or unrelated gradient palettes.

## Typography

- Font stack: `Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif`.
- Display headings: bold to black, tight tracking (`-0.03em` to `-0.05em`), compact line height.
- Body: 14–16 px, 1.45–1.6 line height.
- Eyebrows and metadata: 10–12 px, 800–900 weight, uppercase when used as section markers, restrained tracking.
- Numeric KPIs: 24–40 px, bold, tabular clarity.
- Technical identifiers may use the system monospace stack.

## Spacing and grid

Use a 4 px base rhythm.

- Micro gaps: 4, 6, 8 px.
- Control gaps: 10, 12, 14 px.
- Card padding: 16, 18, 20, 23, or 24 px.
- Section gaps: 20, 22, 24, or 30 px.
- Landing content max width: approximately 1180–1240 px with 24–32 px desktop gutters.
- Prefer 12-column or simple two-column layouts. Product visuals may occupy 52–60% of a hero.
- Keep primary page sections visually distinct without excessive whitespace.

## Shape, borders, and shadows

- Radius medium: 12 px.
- Radius large: 18 px.
- Radius extra-large: 24 px.
- Pill controls: 999 px.
- Default border: 1 px `#d9e4f0`.
- Primary panel shadow: `0 22px 60px rgba(15, 35, 56, 0.11)`.
- Lighter card shadow: `0 18px 48px rgba(15, 35, 56, 0.085)`.
- Primary action shadow: `0 11px 24px rgba(37, 99, 235, 0.20)`.
- Dark/navigation surfaces may use subtle cyan/teal glows, never strong neon effects.

## Components

### Product mark

- Existing mark is a rounded square containing “MP”.
- Use the established cyan-to-mint highlight gradient over a dark/navy context, or white “MP” over primary blue on a light auth surface.
- Do not replace it with a generic shield, lock, or third-party logo.

### Buttons

- Primary: royal blue background, white text, 13 px radius, medium shadow.
- Secondary: blue-soft background and dark blue text, no shadow.
- Dark contextual action: navy background, white text, cyan arrow/accent.
- Danger: red background and white text.
- Hover may lift by 1 px and strengthen the shadow.
- Focus-visible uses a 3 px translucent blue outline with 2 px offset.
- Labels are action-specific and use 800–850 weight.

### Panels and cards

- White or slightly translucent white surface.
- 1 px blue-gray border.
- 18–24 px radius depending on scale.
- Header uses clear title, short supporting copy, and an optional action.
- Internal groups can use soft blue-gray backgrounds and 12–18 px radii.
- Avoid excessive card nesting; use borders and background shifts to show hierarchy.

### Status and KPI elements

- Status chips are compact pills with a dot or compact icon.
- Success uses green on pale green; warnings use orange/brown on pale amber; failures use red on pale red.
- KPIs pair a strong number with a muted short label.
- Use real workflow/status examples from the product rather than vanity metrics.

### Application shell

- Preserve the compact MP mark and dark navy navigation as the strongest brand anchor.
- Reduce visual competition between the global topbar, workflow rail, page header, and page panels. A user should understand current location, system state, and primary next action in one scan.
- Keep grouped routes but make active state, group hierarchy, collapsed/compact behavior, and long-label handling clearer.
- Treat connection health, database health, active operations, and the current user as persistent system context rather than oversized page content.
- Use the five-stage workflow rail as secondary navigation. It must not consume more vertical space than the page content it supports.
- Preserve permission-based route visibility and current Russian labels.

## Application improvement direction

The redesign is evolutionary: keep the current MP visual identity and interaction model while improving information architecture, density, hierarchy, and responsive behavior.

For the `/vm` operational home:

1. Make the most important operating questions answerable above the fold: what is running, what is overdue, what requires attention, and what action should happen next.
2. Consolidate duplicate framing between the global topbar and the first page panel.
3. Keep the six source-backed KPIs, but group and prioritize them by operational meaning instead of presenting equal visual weight.
4. Keep the five-stage process navigation, while reducing its height and making active/completed/next states easier to scan.
5. Make “Запустить полный цикл” the clear primary task without overpowering risk and attention information.
6. Present attention items as an actionable queue with severity, asset, deadline, and destination.
7. Present recent workflows as compact, readable rows with status, progress, identity, time, and a clear drill-down affordance.
8. Present remediation campaigns as comparable cards or rows with owner, deadline, verified count, overdue count, and status.
9. Preserve the workflow and campaign drawers, with clear header context, sticky actions where useful, and safe destructive controls.
10. Avoid inventing new features, metrics, statuses, integrations, or content not present in the supplied source.

## Responsive behavior

- Desktop: persistent sidebar with a fluid workspace and a compact, stable topbar.
- Tablet: allow the sidebar to become compact or off-canvas; keep page actions and system status accessible.
- Mobile: use a single-column workspace, horizontally scroll only data tables when unavoidable, and keep primary actions reachable without depending on hover.
- Minimum touch target: 42 px.
- Maintain strong focus states and semantic heading order.
- Do not hide essential value propositions on small screens.

## Motion

- Default interaction duration: 160 ms ease.
- Hover: no more than 1–2 px lift.
- Entrance motion, if used, should be subtle fade/translate and respect `prefers-reduced-motion`.
- Workflow/progress animation should communicate state, not decorate.
- Avoid parallax, looping glow, autoplay video, or distracting background motion.

## Accessibility

- Meet WCAG AA contrast for body text and controls.
- Use visible keyboard focus.
- Preserve semantic landmarks, labels, and heading hierarchy.
- Do not use color alone to communicate severity/status.
- Decorative effects must not reduce copy or table legibility.
