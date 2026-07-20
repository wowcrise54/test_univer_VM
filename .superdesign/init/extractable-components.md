# Extractable Superdesign components

## Sidebar

- Source: `src/app/layout.jsx`
- Category: layout
- Description: Persistent navy product navigation with grouped routes, MP brand mark, active-operation badge, session status, and database warning.
- Extractable props: `activePath` (string, default: "/vm"), `activeOperations` (number, default: 0), `showDatabaseWarning` (boolean, default: false), `isConnected` (boolean, default: true)
- Hardcoded: MP mark, product name, navigation group labels, route labels/icons, layout classes, colors, and status copy.

## Topbar

- Source: `src/app/layout.jsx`
- Category: layout
- Description: Route-aware page heading with eyebrow, description, user/role chip, connection status, contextual next action, and logout.
- Extractable props: `activeRoute` (string, default: "vm"), `isConnected` (boolean, default: true), `showNextAction` (boolean, default: true)
- Hardcoded: Product eyebrow, route titles/descriptions, role labels, arrow icon, typography, spacing, and button styles.

## WorkflowRail

- Source: `src/app/layout.jsx`
- Category: layout
- Description: Five-step horizontal workflow rail spanning overview, scan, findings, remediation, and reporting.
- Extractable props: `activeStep` (string, default: "overview")
- Hardcoded: Step names, hints, paths, number/check icons, and all CSS classes.

## SystemBanner

- Source: `src/app/layout.jsx`
- Category: layout
- Description: Conditional system health banner for degraded/down services and stale operation data.
- Extractable props: `state` (string, default: "degraded"), `showConnectionAction` (boolean, default: true), `showOperationsAction` (boolean, default: false)
- Hardcoded: Status copy, trace label, action labels, and severity styling.

## AlertStack

- Source: `src/app/layout.jsx`
- Category: layout
- Description: Live-region stack for success, informational, and error notifications.
- Extractable props: `showAlert` (boolean, default: true), `alertType` (string, default: "success")
- Hardcoded: Alert structure and type-based CSS.

## LoginSurface

- Source: `src/features/auth/AuthGate.jsx`
- Category: layout
- Description: Full-page authentication surface with product context and username/password form.
- Extractable props: `showConfigurationWarning` (boolean, default: false), `isBusy` (boolean, default: false)
- Hardcoded: Form labels, product copy, input types, button label, and authentication styling.

## Panel

- Source: `src/shared/ui.jsx`
- Category: basic
- Description: Standard white workspace panel with optional eyebrow, heading, description, action region, and body slot.
- Extractable props: `showEyebrow` (boolean, default: true), `showAction` (boolean, default: true)
- Hardcoded: Element hierarchy, panel/header classes, and typography.

## Button

- Source: `src/shared/ui.jsx`
- Category: basic
- Description: Primary, secondary, and danger action button with busy and disabled states.
- Extractable props: `variant` (string, default: "primary"), `isBusy` (boolean, default: false), `isDisabled` (boolean, default: false)
- Hardcoded: Element type, busy label, button classes, and interaction styling.

## Field

- Source: `src/shared/ui.jsx`
- Category: basic
- Description: Labeled form-field wrapper with optional full-width layout.
- Extractable props: `isWide` (boolean, default: false)
- Hardcoded: Label structure and field classes.

## Toggle

- Source: `src/shared/ui.jsx`
- Category: basic
- Description: Checkbox-backed labeled toggle control.
- Extractable props: `isChecked` (boolean, default: false)
- Hardcoded: Input type and toggle classes.

## ConfirmDialog

- Source: `src/shared/ui.jsx`
- Category: basic
- Description: Accessible destructive-action confirmation modal with impact list and optional typed confirmation.
- Extractable props: `isOpen` (boolean, default: true), `requiresTypedConfirmation` (boolean, default: false), `isBusy` (boolean, default: false)
- Hardcoded: Dialog hierarchy, confirmation eyebrow, action styling, overlay, and focus behavior.

## SortableHeader

- Source: `src/shared/table.jsx`
- Category: basic
- Description: Table header control showing inactive, ascending, or descending sort state.
- Extractable props: `sortState` (string, default: "none")
- Hardcoded: Arrow glyphs, accessible control structure, and CSS classes.

