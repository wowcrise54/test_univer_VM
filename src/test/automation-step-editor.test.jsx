import { describe, expect, it } from "vitest";
import {
  automationStepFromApi,
  automationStepToApi,
  createAutomationStep,
  validateAutomationSteps,
} from "../features/automations/StepEditor.jsx";

describe("automation step model", () => {
  it("keeps PDQL export non-destructive unless explicitly enabled", () => {
    const created = createAutomationStep("pdql_export");
    const legacy = automationStepFromApi({
      step_id: "export",
      type: "pdql_export",
      config: {},
    });
    const destructive = automationStepFromApi({
      step_id: "export",
      type: "pdql_export",
      config: { delete_assets_after_export: true },
    });

    expect(created.config.delete_assets_after_export).toBe(false);
    expect(legacy.config.delete_assets_after_export).toBe(false);
    expect(destructive.config.delete_assets_after_export).toBe(true);
  });

  it("defaults batch asset-card refreshes to three parallel workers", () => {
    const step = createAutomationStep("asset_card_build");
    expect(step.config.parallelism).toBe(3);
  });

  it("serializes typed condition values without JSON text", () => {
    const step = createAutomationStep("notification");
    step.config = {
      level: "warning",
      title: "Done",
      message: "",
      optional: "",
    };
    step.condition = {
      step_id: "scan",
      field: "failed_count",
      operator: "gt",
      value: "2",
    };
    step.conditionValueType = "number";

    expect(automationStepToApi(step)).toMatchObject({
      config: { level: "warning", title: "Done" },
      condition: {
        step_id: "scan",
        field: "failed_count",
        operator: "gt",
        value: 2,
      },
    });
  });

  it("validates required fields before an API request", () => {
    const scan = createAutomationStep("scanner_task_start");
    expect(validateAutomationSteps([scan])).toContain("выберите задачу");

    scan.config.task_id = "task-1";
    expect(validateAutomationSteps([scan])).toBe("");
  });

  it("only allows conditions that reference a previous step", () => {
    const first = createAutomationStep("notification");
    first.config = { level: "info", title: "Start", message: "" };
    const second = createAutomationStep("notification");
    second.condition = {
      step_id: "missing-step",
      field: "notification_id",
      operator: "truthy",
      value: "",
    };

    expect(validateAutomationSteps([first, second])).toContain(
      "предыдущий шаг",
    );
    second.condition.step_id = first.step_id;
    expect(validateAutomationSteps([first, second])).toBe("");
  });
});
