import { useState } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  AutomationStepEditor,
  automationStepFromApi,
  automationStepToApi,
  createAutomationStep,
  validateAutomationSteps,
} from "../features/automations/StepEditor.jsx";

let move, remove;
beforeEach(() => {
  move = vi.fn();
  remove = vi.fn();
});
const catalog = [
  { field_path: "asset.hostname", field_name: "Hostname", value_type: "text" },
  { field_path: "asset.count", value_type: "number" },
  { field_path: "asset.flag", value_type: "boolean" },
];
function Harness({
  type = "scanner_task_start",
  initial,
  previous = [],
  following = [],
}) {
  const [step, setStep] = useState(initial || createAutomationStep(type));
  return (
    <>
      <AutomationStepEditor
        step={step}
        index={previous.length}
        steps={[...previous, step, ...following]}
        scannerTasks={[
          { mp_task_id: "scan-1", name: "Daily scan" },
          { mp_task_id: "scan-2" },
        ]}
        fieldCatalog={catalog}
        onChange={setStep}
        onMove={move}
        onRemove={remove}
      />
      <output data-testid="serialized">
        {JSON.stringify(automationStepToApi(step))}
      </output>
    </>
  );
}
const value = () => JSON.parse(screen.getByTestId("serialized").textContent);
const change = (label, input) =>
  fireEvent.change(screen.getByLabelText(label), { target: { value: input } });
const click = (label) => fireEvent.click(screen.getByLabelText(label));

describe("interactive automation steps", () => {
  it("edits a scan and its advanced options while keeping numeric units correct", () => {
    render(<Harness />);
    change("Задача сканирования", "scan-1");
    change("Ждать не более, минут", "30");
    click("Дождаться завершения обработки");
    fireEvent.click(screen.getByText("Дополнительные параметры запуска"));
    click("Сначала проверить доступность целей");
    change("Профиль предварительной проверки", "profile");
    change("Таймаут задачи, минут", "45");
    click("Считать предупреждения ошибкой");
    fireEvent.click(screen.getByText("Поведение при ошибке"));
    change("Если шаг завершился ошибкой", "continue");
    change("Повторить попытку", "2");
    expect(value()).toMatchObject({
      on_error: "continue",
      max_retries: 2,
      config: {
        task_id: "scan-1",
        wait: false,
        timeout_seconds: 1800,
        options: {
          precheck_enabled: true,
          precheck_profile_id: "profile",
          task_timeout_minutes: 45,
          require_clean_jobs: true,
        },
      },
    });
    change("Ждать не более, минут", "");
    expect(value().config).not.toHaveProperty("timeout_seconds");
  });

  it("keeps step identity and retry policy when the action type changes", () => {
    const initial = createAutomationStep();
    initial.on_error = "continue";
    initial.max_retries = 2;
    render(<Harness initial={initial} />);
    expect(
      screen.getByRole("button", { name: "Переместить шаг выше" }),
    ).toBeDisabled();
    expect(screen.getByRole("button", { name: "Удалить шаг" })).toBeDisabled();
    change("Действие", "notification");
    change("Важность", "warning");
    change("Заголовок", "Scan done");
    change("Сообщение", "Review findings");
    expect(value()).toMatchObject({
      step_id: initial.step_id,
      type: "notification",
      on_error: "continue",
      max_retries: 2,
      config: {
        level: "warning",
        title: "Scan done",
        message: "Review findings",
      },
    });
  });

  it("emits movement and removal actions for an intermediate step", () => {
    render(
      <Harness
        type="notification"
        previous={[createAutomationStep("notification")]}
        following={[createAutomationStep("notification")]}
      />,
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Переместить шаг выше" }),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Переместить шаг ниже" }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Удалить шаг" }));
    expect(move.mock.calls).toEqual([[-1], [1]]);
    expect(remove).toHaveBeenCalledTimes(1);
  });

  it("parses, deduplicates and removes target IDs without enabling destructive export", () => {
    render(<Harness type="pdql_export" />);
    change("PDQL-запрос (необязательно)", "select fixture");
    change("Часовой пояс", "+03:00");
    const groups = screen.getByPlaceholderText("Добавьте ID группы");
    fireEvent.change(groups, { target: { value: "group-a,group-b; group-a" } });
    fireEvent.keyDown(groups, { key: "Enter" });
    expect(value().config.group_ids).toEqual(["group-a", "group-b"]);
    fireEvent.change(groups, { target: { value: " " } });
    fireEvent.blur(groups);
    expect(value().config.group_ids).toEqual(["group-a", "group-b"]);
    fireEvent.click(screen.getByRole("button", { name: "group-a" }));
    expect(value().config.group_ids).toEqual(["group-b"]);
    const assets = screen.getByPlaceholderText("Добавьте ID актива");
    fireEvent.change(assets, { target: { value: "asset-a asset-b" } });
    fireEvent.keyDown(assets, { key: "a" });
    fireEvent.keyDown(assets, { key: "," });
    click("Включать вложенные группы");
    click("Сохранить результат в локальной базе");
    expect(value().config).toMatchObject({
      pdql: "select fixture",
      utc_offset: "+03:00",
      asset_ids: ["asset-a", "asset-b"],
      include_nested_groups: false,
      import_results: false,
      delete_assets_after_export: false,
    });
    click("Удалить выгруженные активы из MP VM после успешного сохранения");
    expect(screen.getByText(/Опасное действие/)).toBeInTheDocument();
    expect(value().config.delete_assets_after_export).toBe(true);
  });

  it("edits passport limits and explicitly disables detail loading", () => {
    render(<Harness type="passport_sync" />);
    change("PDQL-запрос (необязательно)", "passport fixture");
    change("Максимум паспортов", "25");
    change("Размер пакета", "10");
    click("Включать вложенные группы");
    click("Сохранять в локальной базе");
    click("Загружать подробности паспортов");
    fireEvent.change(screen.getByPlaceholderText("Добавьте ID актива"), {
      target: { value: "asset-a" },
    });
    fireEvent.blur(screen.getByPlaceholderText("Добавьте ID актива"));
    expect(value().config).toMatchObject({
      pdql: "passport fixture",
      limit: 25,
      batch_size: 10,
      include_nested_groups: false,
      save_to_db: false,
      load_details: false,
      asset_ids: ["asset-a"],
    });
  });

  it("switches a single-card refresh to a bounded batch and preserves nested scan options", () => {
    render(<Harness type="asset_card_build" />);
    change("Актив", "asset-a");
    expect(value().config.asset_id).toBe("asset-a");
    change("Какие карточки обновить", "stale");
    expect(screen.queryByLabelText("Актив")).not.toBeInTheDocument();
    change("Максимум карточек за запуск (необязательно)", "20");
    change("Параллельных обновлений", "3");
    change("Задача-шаблон MP VM (необязательно)", "scan-2");
    change("Ждать не более, минут", "60");
    change("Таймаут задачи MP VM, минут", "30");
    click("Сначала проверить доступность цели");
    click("Считать предупреждения сканирования ошибкой");
    expect(value().config).toMatchObject({
      selection: "stale",
      max_assets: 20,
      parallelism: 3,
      template_task_id: "scan-2",
      timeout_seconds: 3600,
      start_options: {
        task_timeout_minutes: 30,
        precheck_enabled: true,
        require_clean_jobs: true,
      },
    });
    change("Ждать не более, минут", "");
    expect(value().config).not.toHaveProperty("timeout_seconds");
  });

  it("uses catalog types for query operators, numeric values and conditions without values", () => {
    render(<Harness type="asset_query" />);
    change("Совпадение правил", "or");
    change("Сортировать по", "last_seen");
    change("Порядок", "desc");
    change("Поле правила 1", "asset.count");
    change("Сравнение", "gt");
    change("Значение", "10");
    expect(value().config).toMatchObject({
      sort_by: "last_seen",
      sort_dir: "desc",
      query: {
        combinator: "or",
        rules: [{ field_path: "asset.count", operator: "gt", value: 10 }],
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Добавить правило" }));
    change("Поле правила 2", "asset.flag");
    const rows = document.querySelectorAll(".automation-query-rule");
    expect(within(rows[1]).getByLabelText("Значение")).toBeDisabled();
    fireEvent.change(within(rows[1]).getByLabelText("Сравнение"), {
      target: { value: "is_false" },
    });
    fireEvent.click(within(rows[0]).getByRole("button", { name: "Удалить" }));
    expect(value().config.query.rules).toEqual([
      { field_path: "asset.flag", operator: "is_false" },
    ]);
    expect(screen.getByRole("button", { name: "Удалить" })).toBeDisabled();
    change("Поле правила 1", "asset.hostname");
    change("Сравнение", "contains");
    change("Значение", "server");
    expect(value().config.query.rules[0].value).toBe("server");
    change("Значение", "");
    expect(value().config.query.rules[0]).not.toHaveProperty("value");
  });

  it("supports conditions on previous results with text, number and boolean values", () => {
    const previous = [
      createAutomationStep("notification"),
      createAutomationStep("pdql_export"),
    ];
    render(<Harness type="notification" previous={previous} />);
    click("Выполнять этот шаг только при условии");
    expect(value().condition.step_id).toBe(previous[1].step_id);
    change("Результат шага", previous[0].step_id);
    change("Поле результата", "failed_count");
    change("Проверка", "gt");
    change("Тип значения", "number");
    change("Ожидаемое значение", "2");
    expect(value().condition).toEqual({
      step_id: previous[0].step_id,
      field: "failed_count",
      operator: "gt",
      value: 2,
    });
    change("Тип значения", "text");
    change("Ожидаемое значение", "completed");
    expect(value().condition.value).toBe("completed");
    change("Тип значения", "boolean");
    change("Ожидаемое значение", "false");
    expect(value().condition.value).toBe(false);
    click("Выполнять этот шаг только при условии");
    expect(value().condition).toBeNull();
  });

  it("removes an invalid legacy condition from the first step", () => {
    const initial = createAutomationStep("notification");
    initial.condition = { step_id: "old", field: "result", operator: "truthy" };
    render(<Harness initial={initial} />);
    expect(screen.getByText(/В старом черновике/)).toBeInTheDocument();
    fireEvent.click(
      screen.getByRole("button", { name: "Удалить старое условие" }),
    );
    expect(value().condition).toBeNull();
  });
});

describe("automation model boundaries", () => {
  it.each([true, 2, "text", null])(
    "restores and serializes typed condition value %s",
    (input) => {
      const step = automationStepFromApi({
        type: "notification",
        config: {
          nested: { empty: "", safe: false },
          items: [0, { safe: true, empty: null }],
        },
        condition: {
          step_id: "earlier",
          field: "result",
          operator: "eq",
          value: input,
        },
      });
      const payload = automationStepToApi(step);
      expect(payload.condition.value).toBe(input === null ? "" : input);
      expect(payload.config.nested).toEqual({ safe: false });
      expect(payload.config.items).toEqual([0, { safe: true }]);
    },
  );

  it("merges nested defaults without sharing mutable state and tolerates an unknown legacy type", () => {
    const unknown = automationStepFromApi({
      type: "legacy",
      config: { options: { precheck_enabled: true }, group_ids: ["a"] },
      condition: "invalid",
    });
    expect(unknown.type).toBe("scanner_task_start");
    expect(unknown.condition).toBeNull();
    expect(unknown.config.options).toMatchObject({
      precheck_enabled: true,
      task_timeout_minutes: 120,
    });
    const other = createAutomationStep();
    unknown.config.options.task_timeout_minutes = 1;
    expect(other.config.options.task_timeout_minutes).toBe(120);
    expect(automationStepToApi(createAutomationStep("legacy")).config).toEqual(
      {},
    );
  });

  it("validates missing IDs, duplicate IDs and empty queries before saving", () => {
    expect(validateAutomationSteps([])).toContain("хотя бы один шаг");
    const step = createAutomationStep("notification");
    expect(validateAutomationSteps([{ ...step, step_id: "" }])).toContain(
      "идентификатор",
    );
    expect(validateAutomationSteps([step, step])).toContain("уникальным");
    expect(
      validateAutomationSteps([createAutomationStep("asset_card_build")]),
    ).toContain("укажите актив");
    const query = createAutomationStep("asset_query");
    query.config.query = null;
    expect(validateAutomationSteps([query])).toContain("поле");
    query.config.query = {
      rules: [
        { rules: [{ field_path: "asset.hostname", operator: "exists" }] },
      ],
    };
    expect(validateAutomationSteps([query])).toBe("");
  });

  it.each([
    [{ field: "", operator: "truthy" }, "text", "поле результата"],
    [{ field: "result", operator: "invalid" }, "text", "поддерживаемую"],
    [{ field: "result", operator: "eq", value: "" }, "number", "число"],
  ])("rejects an invalid condition %s", (condition, type, message) => {
    const previous = createAutomationStep("notification");
    const step = createAutomationStep("notification");
    step.condition = { step_id: previous.step_id, ...condition };
    step.conditionValueType = type;
    expect(validateAutomationSteps([previous, step])).toContain(message);
  });
});
