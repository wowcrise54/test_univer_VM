async (page) => {
  await page.unrouteAll({ behavior: "ignoreErrors" });
  const responses = {
    "/api/auth/bootstrap-status": { configured: true },
    "/api/auth/me": {
      user: {
        id: 1,
        username: "e2e",
        display_name: "Алексей Воронин",
        role: "admin",
        permissions: [
          "system.read",
          "connection.read",
          "tasks.read",
          "tasks.execute",
          "operations.read",
          "assets.read",
          "asset_cards.read",
          "passports.read",
          "imports_exports.read",
          "remediation.read",
          "remediation.manage",
          "risk.read",
          "risk.manage",
          "automations.read",
          "security.users.read",
        ],
      },
    },
    "/api/session": {
      connected: true,
      api_url: "https://mpvm-rest.corp",
      token_url: "https://mpvm-rest.corp/connect/token",
      verify_tls: true,
    },
    "/api/defaults": {
      client_id: "mpx",
      scope: "",
      utc_offset: "+05:00",
      asset_card_pdql: "",
      vulnerability_passport_pdql: "",
    },
    "/api/system/status": {
      state: "ok",
      components: { database: { state: "ok" }, mpvm: { state: "ok" } },
    },
    "/api/operations/summary": {
      active: 3,
      queued: 1,
      running: 2,
      failed: 0,
    },
    "/api/operations": { rows: [], total: 0 },
    "/api/vm/workflows/scan": { workflow_id: "wf-new", status: "queued" },
    "/api/vm/workflows/wf-new": {
      workflow_id: "wf-new",
      kind: "scan",
      status: "running",
      progress_percent: 48,
      can_cancel: true,
      can_retry: false,
      steps: [
        {
          position: 1,
          step_key: "validation",
          status: "completed",
          progress_percent: 100,
        },
        {
          position: 2,
          step_key: "scan",
          status: "completed",
          progress_percent: 100,
        },
        {
          position: 3,
          step_key: "postprocess",
          status: "running",
          progress_percent: 24,
          message: "Загрузка карточек",
        },
        {
          position: 4,
          step_key: "reconcile",
          status: "pending",
          progress_percent: 0,
        },
      ],
    },
    "/api/vm/overview": {
      active_workflows: 2,
      open_cases: 142,
      overdue_cases: 8,
      risk: { urgent: 14 },
      awaiting_verification: 12,
      coverage: { coverage_percent: 96 },
      attention: [
        {
          case_id: "case-1",
          severity: "critical",
          cve: "CVE-2026-9001",
          title: "Удалённое выполнение кода",
          asset_id: "srv-app-prod-01",
          due_at: "2026-07-20T14:00:00Z",
        },
        {
          case_id: "case-2",
          severity: "high",
          cve: "CVE-2026-7124",
          title: "Обход аутентификации",
          asset_id: "gateway-dmz-04",
          due_at: "2026-07-21T09:30:00Z",
        },
        {
          case_id: "case-3",
          severity: "medium",
          title: "Повышение привилегий агента",
          asset_id: "ws-office-12",
          due_at: "2026-07-24T18:00:00Z",
        },
      ],
      recent_workflows: [
        {
          workflow_id: "wf-1",
          kind: "scan",
          task_id: "0x992 Subnet A1",
          status: "running",
          progress_percent: 65,
          created_at: "2026-07-20T11:24:00Z",
        },
        {
          workflow_id: "wf-2",
          kind: "verification",
          campaign_id: "cmp-4422",
          status: "completed",
          progress_percent: 100,
          created_at: "2026-07-20T08:45:00Z",
        },
      ],
    },
    "/api/scanner-tasks": [
      { mp_task_id: "task-1", payload: { name: "Weekly Windows Scan" } },
      { mp_task_id: "task-2", payload: { name: "DMZ Priority Scan" } },
    ],
    "/api/remediation/campaigns": {
      rows: [
        {
          campaign_id: "cmp-4422",
          status: "active",
          name: "Критические RCE · Q3",
          assignee: "А. Воронин",
          due_at: "2026-07-30T12:00:00Z",
          total: 28,
          resolved: 12,
          overdue: 0,
        },
        {
          campaign_id: "cmp-4423",
          status: "active",
          name: "Укрепление DMZ",
          assignee: "С. Петров",
          due_at: "2026-07-25T12:00:00Z",
          total: 52,
          resolved: 42,
          overdue: 4,
        },
        {
          campaign_id: "cmp-4420",
          status: "completed",
          name: "Обновление SSH",
          assignee: "В. Иванов",
          due_at: "2026-07-18T12:00:00Z",
          total: 15,
          resolved: 15,
          overdue: 0,
        },
      ],
      total: 3,
    },
  };

  await page.route("http://127.0.0.1:4173/api/**", async (route) => {
    const requestUrl = route.request().url();
    const path = `/${requestUrl.split("/").slice(3).join("/").split("?")[0]}`;
    await route.fulfill({ json: responses[path] ?? {} });
  });
  await page.reload();
  await page.waitForLoadState("networkidle");
}
