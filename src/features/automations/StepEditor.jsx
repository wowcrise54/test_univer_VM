import { useMemo, useState } from "react";
import { Button, Field, Toggle } from "../../shared/ui.jsx";

export const STEP_TYPES = [
  ["scanner_task_start", "Запустить задачу сканирования"],
  ["pdql_export", "Экспортировать данные по PDQL"],
  ["passport_sync", "Синхронизировать паспорта"],
  ["asset_card_build", "Обновить карточку актива"],
  ["asset_query", "Сформировать выборку активов"],
  ["notification", "Отправить уведомление"],
];

const STEP_META = {
  scanner_task_start: {
    short: "Сканирование",
    description:
      "Запускает уже созданную задачу MP VM и при необходимости ждёт завершения обработки.",
    defaults: {
      task_id: "",
      wait: true,
      timeout_seconds: 7200,
      options: {
        precheck_enabled: false,
        task_timeout_minutes: 120,
        require_clean_jobs: false,
      },
    },
  },
  pdql_export: {
    short: "PDQL-экспорт",
    description:
      "Выгружает данные и сохраняет результат локально. Удаление активов всегда выключено по умолчанию.",
    defaults: {
      pdql: "",
      utc_offset: "+05:00",
      group_ids: [],
      asset_ids: [],
      include_nested_groups: true,
      import_results: true,
      delete_assets_after_export: false,
      delete_timeout_minutes: 30,
      delete_poll_seconds: 10,
    },
  },
  passport_sync: {
    short: "Паспорта",
    description:
      "Получает паспорта уязвимостей и, при необходимости, загружает подробности.",
    defaults: {
      pdql: "",
      utc_offset: "+05:00",
      group_ids: [],
      asset_ids: [],
      include_nested_groups: true,
      limit: "",
      batch_size: 5000,
      save_to_db: true,
      load_details: true,
    },
  },
  asset_card_build: {
    short: "Карточка актива",
    description:
      "Обновляет выбранную карточку или параллельно обрабатывает пачку карточек с заданным лимитом.",
    defaults: {
      selection: "asset",
      asset_id: "",
      max_assets: "",
      parallelism: 3,
      template_task_id: "",
      wait: true,
      timeout_seconds: 14400,
      start_options: {
        precheck_enabled: false,
        task_timeout_minutes: 120,
        require_clean_jobs: false,
      },
    },
  },
  asset_query: {
    short: "Выборка активов",
    description:
      "Отбирает локальные карточки по понятным правилам без обращения к MP VM.",
    defaults: {
      query: {
        combinator: "and",
        match_scope: "host",
        rules: [{ field_path: "", operator: "equals", value: "" }],
      },
      sort_by: "display_name",
      sort_dir: "asc",
      limit: 50,
      offset: 0,
    },
  },
  notification: {
    short: "Уведомление",
    description: "Добавляет понятное сообщение в центр уведомлений.",
    defaults: { level: "info", title: "", message: "" },
  },
};

const CONDITION_OPERATORS = new Set([
  "truthy",
  "eq",
  "ne",
  "gt",
  "gte",
  "lt",
  "lte",
]);

let stepCounter = 0;

export function createAutomationStep(type = "scanner_task_start") {
  stepCounter += 1;
  return {
    step_id: `${type.replaceAll("_", "-")}-${Date.now().toString(36)}-${stepCounter}`,
    type,
    config: clone(STEP_META[type]?.defaults || {}),
    on_error: "stop",
    max_retries: 0,
    condition: null,
    conditionValueType: "text",
  };
}

export function automationStepFromApi(step) {
  const type = STEP_META[step?.type] ? step.type : "scanner_task_start";
  const condition =
    step?.condition && typeof step.condition === "object"
      ? clone(step.condition)
      : null;
  return {
    ...createAutomationStep(type),
    ...step,
    type,
    config: mergeDeep(
      clone(STEP_META[type].defaults),
      clone(step?.config || {}),
    ),
    condition,
    conditionValueType: conditionValueType(condition?.value),
  };
}

export function automationStepToApi(step) {
  const condition = step.condition
    ? {
        step_id: step.condition.step_id,
        field: step.condition.field,
        operator: step.condition.operator,
        ...(step.condition.operator === "truthy"
          ? {}
          : {
              value: typedConditionValue(
                step.condition.value,
                step.conditionValueType,
              ),
            }),
      }
    : null;
  return {
    step_id: step.step_id,
    type: step.type,
    config: compactConfig(step.config),
    on_error: step.on_error,
    max_retries: Number(step.max_retries || 0),
    condition,
  };
}

export function validateAutomationSteps(steps) {
  if (!steps.length) return "Добавьте хотя бы один шаг.";
  const ids = new Set();
  for (let index = 0; index < steps.length; index += 1) {
    const step = steps[index];
    const label = `Шаг ${index + 1}`;
    if (!step.step_id?.trim())
      return `${label}: не удалось сформировать служебный идентификатор.`;
    if (ids.has(step.step_id))
      return `${label}: идентификатор шага должен быть уникальным.`;
    ids.add(step.step_id);
    if (step.type === "scanner_task_start" && !step.config?.task_id?.trim())
      return `${label}: выберите задачу сканирования.`;
    if (
      step.type === "asset_card_build" &&
      (step.config?.selection || "asset") === "asset" &&
      !step.config?.asset_id?.trim()
    )
      return `${label}: укажите актив.`;
    if (step.type === "asset_query") {
      const rules = collectQueryRules(step.config?.query);
      if (!rules.length || rules.some((rule) => !rule.field_path?.trim()))
        return `${label}: выберите поле для каждого правила выборки.`;
    }
    if (step.condition) {
      const previousIds = new Set(
        steps.slice(0, index).map((item) => item.step_id),
      );
      if (!previousIds.has(step.condition.step_id))
        return `${label}: условие должно ссылаться на предыдущий шаг.`;
      if (!step.condition.field?.trim())
        return `${label}: укажите поле результата для условия.`;
      if (!CONDITION_OPERATORS.has(step.condition.operator))
        return `${label}: выберите поддерживаемую проверку условия.`;
      if (
        step.condition.operator !== "truthy" &&
        step.conditionValueType === "number" &&
        step.condition.value === ""
      ) {
        return `${label}: укажите число для сравнения.`;
      }
    }
  }
  return "";
}

export function AutomationStepEditor({
  step,
  index,
  steps,
  scannerTasks = [],
  fieldCatalog = [],
  onChange,
  onMove,
  onRemove,
}) {
  const previousSteps = steps.slice(0, index);
  const meta = STEP_META[step.type];
  const changeType = (type) => {
    const next = createAutomationStep(type);
    onChange({
      ...next,
      step_id: step.step_id,
      on_error: step.on_error,
      max_retries: step.max_retries,
      condition: step.condition,
      conditionValueType: step.conditionValueType,
    });
  };
  const updateConfig = (path, value) =>
    onChange({ ...step, config: setAtPath(step.config, path, value) });
  return (
    <article className="automation-step">
      <div className="automation-step__header">
        <span className="automation-step__number">{index + 1}</span>
        <div>
          <strong>{meta.short}</strong>
          <p>{meta.description}</p>
        </div>
        <div
          className="automation-step__actions"
          aria-label={`Действия шага ${index + 1}`}
        >
          <button
            type="button"
            title="Переместить выше"
            aria-label="Переместить шаг выше"
            disabled={!index}
            onClick={() => onMove(-1)}
          >
            ↑
          </button>
          <button
            type="button"
            title="Переместить ниже"
            aria-label="Переместить шаг ниже"
            disabled={index === steps.length - 1}
            onClick={() => onMove(1)}
          >
            ↓
          </button>
          <button
            type="button"
            className="is-danger"
            title="Удалить шаг"
            aria-label="Удалить шаг"
            disabled={steps.length === 1}
            onClick={onRemove}
          >
            ×
          </button>
        </div>
      </div>

      <div className="automation-step__type-row">
        <Field label="Действие">
          <select
            value={step.type}
            onChange={(event) => changeType(event.target.value)}
          >
            {STEP_TYPES.map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </Field>
      </div>

      <StepConfigFields
        step={step}
        scannerTasks={scannerTasks}
        fieldCatalog={fieldCatalog}
        updateConfig={updateConfig}
      />

      <ConditionEditor
        step={step}
        index={index}
        previousSteps={previousSteps}
        onChange={onChange}
      />

      <details className="automation-step__behavior">
        <summary>Поведение при ошибке</summary>
        <div className="automation-step__behavior-grid">
          <Field label="Если шаг завершился ошибкой">
            <select
              value={step.on_error}
              onChange={(event) =>
                onChange({ ...step, on_error: event.target.value })
              }
            >
              <option value="stop">Остановить сценарий</option>
              <option value="continue">Продолжить со следующим шагом</option>
            </select>
          </Field>
          <Field label="Повторить попытку">
            <select
              value={String(step.max_retries)}
              onChange={(event) =>
                onChange({ ...step, max_retries: Number(event.target.value) })
              }
            >
              <option value="0">Не повторять</option>
              <option value="1">1 раз</option>
              <option value="2">2 раза</option>
              <option value="3">3 раза</option>
            </select>
          </Field>
        </div>
      </details>
    </article>
  );
}

function StepConfigFields({ step, scannerTasks, fieldCatalog, updateConfig }) {
  const config = step.config || {};
  if (step.type === "scanner_task_start") {
    return (
      <>
        <div className="automation-config-grid automation-config-grid--two">
          <Field label="Задача сканирования">
            <input
              list="automation-scanner-tasks"
              value={config.task_id || ""}
              onChange={(event) => updateConfig("task_id", event.target.value)}
              placeholder="Выберите задачу или вставьте ID"
            />
          </Field>
          <datalist id="automation-scanner-tasks">
            {scannerTasks.map((task) => (
              <option key={task.mp_task_id} value={task.mp_task_id}>
                {task.name || task.mp_task_id}
              </option>
            ))}
          </datalist>
          <NumberField
            label="Ждать не более, минут"
            value={secondsToMinutes(config.timeout_seconds)}
            min={1}
            onChange={(value) =>
              updateConfig("timeout_seconds", value === "" ? "" : value * 60)
            }
          />
          <Toggle
            label="Дождаться завершения обработки"
            checked={config.wait !== false}
            onChange={(value) => updateConfig("wait", value)}
          />
        </div>
        <details className="automation-config-advanced">
          <summary>Дополнительные параметры запуска</summary>
          <div className="automation-config-grid automation-config-grid--three">
            <Toggle
              label="Сначала проверить доступность целей"
              checked={Boolean(config.options?.precheck_enabled)}
              onChange={(value) =>
                updateConfig("options.precheck_enabled", value)
              }
            />
            <Field label="Профиль предварительной проверки">
              <input
                value={config.options?.precheck_profile_id || ""}
                onChange={(event) =>
                  updateConfig(
                    "options.precheck_profile_id",
                    event.target.value,
                  )
                }
                placeholder="Необязательно"
              />
            </Field>
            <NumberField
              label="Таймаут задачи, минут"
              value={config.options?.task_timeout_minutes ?? 120}
              min={1}
              onChange={(value) =>
                updateConfig("options.task_timeout_minutes", value)
              }
            />
            <Toggle
              label="Считать предупреждения ошибкой"
              checked={Boolean(config.options?.require_clean_jobs)}
              onChange={(value) =>
                updateConfig("options.require_clean_jobs", value)
              }
            />
          </div>
        </details>
      </>
    );
  }
  if (step.type === "pdql_export") {
    return (
      <>
        <div className="automation-config-grid automation-config-grid--two">
          <Field label="PDQL-запрос (необязательно)" wide>
            <textarea
              rows="3"
              value={config.pdql || ""}
              onChange={(event) => updateConfig("pdql", event.target.value)}
              placeholder="Оставьте пустым, чтобы использовать стандартную выборку ПО и уязвимостей"
            />
          </Field>
          <TokenListField
            label="Группы активов"
            values={config.group_ids || []}
            onChange={(value) => updateConfig("group_ids", value)}
            placeholder="Добавьте ID группы"
          />
          <TokenListField
            label="Отдельные активы"
            values={config.asset_ids || []}
            onChange={(value) => updateConfig("asset_ids", value)}
            placeholder="Добавьте ID актива"
          />
          <Field label="Часовой пояс">
            <input
              value={config.utc_offset || ""}
              onChange={(event) =>
                updateConfig("utc_offset", event.target.value)
              }
              placeholder="+05:00"
            />
          </Field>
          <div className="automation-toggle-stack">
            <Toggle
              label="Включать вложенные группы"
              checked={config.include_nested_groups !== false}
              onChange={(value) => updateConfig("include_nested_groups", value)}
            />
            <Toggle
              label="Сохранить результат в локальной базе"
              checked={config.import_results !== false}
              onChange={(value) => updateConfig("import_results", value)}
            />
          </div>
        </div>
        <div
          className={`automation-danger-option ${config.delete_assets_after_export ? "is-enabled" : ""}`}
        >
          <Toggle
            label="Удалить выгруженные активы из MP VM после успешного сохранения"
            checked={Boolean(config.delete_assets_after_export)}
            onChange={(value) =>
              updateConfig("delete_assets_after_export", value)
            }
          />
          <p>
            {config.delete_assets_after_export
              ? "Опасное действие. При публикации потребуется подтверждение имени сценария."
              : "Безопасный режим: активы в MP VM останутся без изменений."}
          </p>
        </div>
      </>
    );
  }
  if (step.type === "passport_sync") {
    return (
      <div className="automation-config-grid automation-config-grid--two">
        <Field label="PDQL-запрос (необязательно)" wide>
          <textarea
            rows="3"
            value={config.pdql || ""}
            onChange={(event) => updateConfig("pdql", event.target.value)}
            placeholder="Оставьте пустым для стандартного запроса паспортов"
          />
        </Field>
        <TokenListField
          label="Группы активов"
          values={config.group_ids || []}
          onChange={(value) => updateConfig("group_ids", value)}
          placeholder="Добавьте ID группы"
        />
        <TokenListField
          label="Отдельные активы"
          values={config.asset_ids || []}
          onChange={(value) => updateConfig("asset_ids", value)}
          placeholder="Добавьте ID актива"
        />
        <NumberField
          label="Максимум паспортов"
          value={config.limit ?? ""}
          min={1}
          placeholder="Без ограничения"
          onChange={(value) => updateConfig("limit", value)}
        />
        <NumberField
          label="Размер пакета"
          value={config.batch_size ?? 5000}
          min={1}
          max={10000}
          onChange={(value) => updateConfig("batch_size", value)}
        />
        <div className="automation-toggle-stack">
          <Toggle
            label="Включать вложенные группы"
            checked={config.include_nested_groups !== false}
            onChange={(value) => updateConfig("include_nested_groups", value)}
          />
          <Toggle
            label="Сохранять в локальной базе"
            checked={config.save_to_db !== false}
            onChange={(value) => updateConfig("save_to_db", value)}
          />
          <Toggle
            label="Загружать подробности паспортов"
            checked={config.load_details !== false}
            onChange={(value) => updateConfig("load_details", value)}
          />
        </div>
      </div>
    );
  }
  if (step.type === "asset_card_build") {
    const selection = config.selection || "asset";
    return (
      <div className="automation-config-grid automation-config-grid--two">
        <Field label="Какие карточки обновить">
          <select
            value={selection}
            onChange={(event) => updateConfig("selection", event.target.value)}
          >
            <option value="asset">Одну выбранную карточку</option>
            <option value="stale">Все устаревшие карточки</option>
            <option value="all">Все сохранённые карточки</option>
          </select>
        </Field>
        {selection === "asset" ? (
          <Field label="Актив">
            <input
              value={config.asset_id || ""}
              onChange={(event) => updateConfig("asset_id", event.target.value)}
              placeholder="Вставьте asset ID"
            />
          </Field>
        ) : (
          <>
            <NumberField
              label="Максимум карточек за запуск (необязательно)"
              value={config.max_assets ?? ""}
              min={1}
              placeholder="Без ограничения"
              onChange={(value) => updateConfig("max_assets", value)}
            />
            <NumberField
              label="Параллельных обновлений"
              value={config.parallelism ?? 3}
              min={1}
              max={4}
              onChange={(value) => updateConfig("parallelism", value)}
            />
          </>
        )}
        <Field label="Задача-шаблон MP VM (необязательно)">
          <input
            list="automation-scanner-tasks"
            value={config.template_task_id || ""}
            onChange={(event) =>
              updateConfig("template_task_id", event.target.value)
            }
            placeholder="Определится по последнему сканированию актива"
          />
        </Field>
        <datalist id="automation-scanner-tasks">
          {scannerTasks.map((task) => (
            <option key={task.mp_task_id} value={task.mp_task_id}>
              {task.name || task.mp_task_id}
            </option>
          ))}
        </datalist>
        <NumberField
          label="Ждать не более, минут"
          value={secondsToMinutes(config.timeout_seconds)}
          min={1}
          onChange={(value) =>
            updateConfig("timeout_seconds", value === "" ? "" : value * 60)
          }
        />
        <NumberField
          label="Таймаут задачи MP VM, минут"
          value={config.start_options?.task_timeout_minutes ?? 120}
          min={1}
          onChange={(value) =>
            updateConfig("start_options.task_timeout_minutes", value)
          }
        />
        <div className="automation-toggle-stack">
          <Toggle
            label="Сначала проверить доступность цели"
            checked={Boolean(config.start_options?.precheck_enabled)}
            onChange={(value) =>
              updateConfig("start_options.precheck_enabled", value)
            }
          />
          <Toggle
            label="Считать предупреждения сканирования ошибкой"
            checked={Boolean(config.start_options?.require_clean_jobs)}
            onChange={(value) =>
              updateConfig("start_options.require_clean_jobs", value)
            }
          />
        </div>
      </div>
    );
  }
  if (step.type === "asset_query") {
    return (
      <AssetQueryStepConfig
        config={config}
        fieldCatalog={fieldCatalog}
        updateConfig={updateConfig}
      />
    );
  }
  return (
    <div className="automation-config-grid automation-config-grid--two">
      <Field label="Важность">
        <select
          value={config.level || "info"}
          onChange={(event) => updateConfig("level", event.target.value)}
        >
          <option value="info">Информация</option>
          <option value="warning">Предупреждение</option>
          <option value="error">Ошибка</option>
        </select>
      </Field>
      <Field label="Заголовок">
        <input
          value={config.title || ""}
          onChange={(event) => updateConfig("title", event.target.value)}
          placeholder="Например: Сканирование завершено"
        />
      </Field>
      <Field label="Сообщение" wide>
        <textarea
          rows="3"
          value={config.message || ""}
          onChange={(event) => updateConfig("message", event.target.value)}
          placeholder="Что должен увидеть оператор"
        />
      </Field>
    </div>
  );
}

function AssetQueryStepConfig({ config, fieldCatalog, updateConfig }) {
  const query = config.query || STEP_META.asset_query.defaults.query;
  const rules = Array.isArray(query.rules)
    ? query.rules.filter((item) => item?.field_path !== undefined)
    : [];
  const fieldTypes = useMemo(
    () =>
      new Map(fieldCatalog.map((item) => [item.field_path, item.value_type])),
    [fieldCatalog],
  );
  const setRules = (next) =>
    updateConfig(
      "query.rules",
      next.length ? next : [{ field_path: "", operator: "equals", value: "" }],
    );
  return (
    <div className="automation-query-builder">
      <datalist id="automation-asset-query-fields">
        {fieldCatalog.map((item) => (
          <option
            key={`${item.field_path}-${item.value_type}`}
            value={item.field_path}
          >
            {item.field_name || item.field_path}
          </option>
        ))}
      </datalist>
      <div className="automation-config-grid automation-config-grid--three">
        <Field label="Совпадение правил">
          <select
            value={query.combinator || "and"}
            onChange={(event) =>
              updateConfig("query.combinator", event.target.value)
            }
          >
            <option value="and">Должны выполниться все</option>
            <option value="or">Достаточно любого</option>
          </select>
        </Field>
        <Field label="Сортировать по">
          <select
            value={config.sort_by || "display_name"}
            onChange={(event) => updateConfig("sort_by", event.target.value)}
          >
            <option value="display_name">Имени хоста</option>
            <option value="ip_address">IP-адресу</option>
            <option value="fqdn">FQDN</option>
            <option value="os_name">ОС</option>
            <option value="last_seen">Свежести</option>
          </select>
        </Field>
        <Field label="Порядок">
          <select
            value={config.sort_dir || "asc"}
            onChange={(event) => updateConfig("sort_dir", event.target.value)}
          >
            <option value="asc">По возрастанию</option>
            <option value="desc">По убыванию</option>
          </select>
        </Field>
      </div>
      <div className="automation-query-rules">
        {rules.map((rule, ruleIndex) => {
          const type = fieldTypes.get(rule.field_path);
          const operators = queryOperators(type);
          const needsValue = ![
            "exists",
            "not_exists",
            "is_true",
            "is_false",
          ].includes(rule.operator);
          const updateRule = (patch) =>
            setRules(
              rules.map((item, index) =>
                index === ruleIndex ? { ...item, ...patch } : item,
              ),
            );
          return (
            <div className="automation-query-rule" key={ruleIndex}>
              <Field label={`Поле правила ${ruleIndex + 1}`}>
                <input
                  list="automation-asset-query-fields"
                  value={rule.field_path || ""}
                  onChange={(event) => {
                    const nextType = fieldTypes.get(event.target.value);
                    updateRule({
                      field_path: event.target.value,
                      operator: queryOperators(nextType)[0][0],
                      value: "",
                    });
                  }}
                  placeholder="Начните вводить название поля"
                />
              </Field>
              <Field label="Сравнение">
                <select
                  value={rule.operator || operators[0][0]}
                  onChange={(event) =>
                    updateRule({ operator: event.target.value, value: "" })
                  }
                >
                  {operators.map(([value, label]) => (
                    <option value={value} key={value}>
                      {label}
                    </option>
                  ))}
                </select>
              </Field>
              <Field label="Значение">
                <input
                  disabled={!needsValue}
                  type={type === "number" ? "number" : "text"}
                  value={needsValue ? (rule.value ?? "") : ""}
                  onChange={(event) =>
                    updateRule({
                      value:
                        type === "number" && event.target.value !== ""
                          ? Number(event.target.value)
                          : event.target.value,
                    })
                  }
                  placeholder="Что искать"
                />
              </Field>
              <Button
                variant="tiny-danger"
                disabled={rules.length === 1}
                onClick={() =>
                  setRules(rules.filter((_, index) => index !== ruleIndex))
                }
              >
                Удалить
              </Button>
            </div>
          );
        })}
      </div>
      <Button
        variant="tiny"
        onClick={() =>
          setRules([
            ...rules,
            { field_path: "", operator: "equals", value: "" },
          ])
        }
      >
        Добавить правило
      </Button>
    </div>
  );
}

function ConditionEditor({ step, index, previousSteps, onChange }) {
  const enabled = Boolean(step.condition);
  const enable = (checked) =>
    onChange({
      ...step,
      condition: checked
        ? {
            step_id: previousSteps.at(-1)?.step_id || "",
            field: "",
            operator: "truthy",
            value: "",
          }
        : null,
      conditionValueType: "text",
    });
  if (!index) {
    return (
      <section className="automation-condition">
        <strong>Условие запуска</strong>
        <p>
          {enabled
            ? "В старом черновике у первого шага найдено условие. Удалите его, чтобы сценарий можно было сохранить."
            : "Первый шаг всегда запускается без условий."}
        </p>
        {enabled ? (
          <Button
            variant="tiny-danger"
            onClick={() => onChange({ ...step, condition: null })}
          >
            Удалить старое условие
          </Button>
        ) : null}
      </section>
    );
  }
  return (
    <section className={`automation-condition ${enabled ? "is-enabled" : ""}`}>
      <Toggle
        label="Выполнять этот шаг только при условии"
        checked={enabled}
        onChange={enable}
      />
      {enabled ? (
        <div className="automation-condition__grid">
          <Field label="Результат шага">
            <select
              value={step.condition.step_id || ""}
              onChange={(event) =>
                onChange({
                  ...step,
                  condition: { ...step.condition, step_id: event.target.value },
                })
              }
            >
              {previousSteps.map((item, position) => (
                <option value={item.step_id} key={item.step_id}>
                  {position + 1}. {STEP_META[item.type]?.short || item.type}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Поле результата">
            <input
              value={step.condition.field || ""}
              onChange={(event) =>
                onChange({
                  ...step,
                  condition: { ...step.condition, field: event.target.value },
                })
              }
              placeholder="Например: failed_count"
            />
          </Field>
          <Field label="Проверка">
            <select
              value={step.condition.operator || "truthy"}
              onChange={(event) =>
                onChange({
                  ...step,
                  condition: {
                    ...step.condition,
                    operator: event.target.value,
                  },
                })
              }
            >
              <option value="truthy">Значение задано / истина</option>
              <option value="eq">Равно</option>
              <option value="ne">Не равно</option>
              <option value="gt">Больше</option>
              <option value="gte">Больше или равно</option>
              <option value="lt">Меньше</option>
              <option value="lte">Меньше или равно</option>
            </select>
          </Field>
          {step.condition.operator !== "truthy" ? (
            <>
              <Field label="Тип значения">
                <select
                  value={step.conditionValueType || "text"}
                  onChange={(event) =>
                    onChange({
                      ...step,
                      conditionValueType: event.target.value,
                      condition: {
                        ...step.condition,
                        value: event.target.value === "boolean" ? true : "",
                      },
                    })
                  }
                >
                  <option value="text">Текст</option>
                  <option value="number">Число</option>
                  <option value="boolean">Да / нет</option>
                </select>
              </Field>
              <ConditionValue step={step} onChange={onChange} />
            </>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function ConditionValue({ step, onChange }) {
  const setValue = (value) =>
    onChange({ ...step, condition: { ...step.condition, value } });
  if (step.conditionValueType === "boolean") {
    return (
      <Field label="Ожидаемое значение">
        <select
          value={String(step.condition.value ?? true)}
          onChange={(event) => setValue(event.target.value === "true")}
        >
          <option value="true">Да / истина</option>
          <option value="false">Нет / ложь</option>
        </select>
      </Field>
    );
  }
  return (
    <NumberField
      asText={step.conditionValueType !== "number"}
      label="Ожидаемое значение"
      value={step.condition.value ?? ""}
      onChange={setValue}
    />
  );
}

function NumberField({
  label,
  value,
  onChange,
  min,
  max,
  placeholder,
  asText = false,
}) {
  return (
    <Field label={label}>
      <input
        type={asText ? "text" : "number"}
        min={min}
        max={max}
        value={value}
        placeholder={placeholder}
        onChange={(event) =>
          onChange(
            event.target.value === "" || asText
              ? event.target.value
              : Number(event.target.value),
          )
        }
      />
    </Field>
  );
}

function TokenListField({ label, values, onChange, placeholder }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    const next = draft
      .split(/[\s,;]+/)
      .map((item) => item.trim())
      .filter(Boolean);
    if (next.length)
      onChange(Array.from(new Set([...(values || []), ...next])));
    setDraft("");
  };
  return (
    <div className="automation-token-field">
      <span>{label}</span>
      <div className="automation-token-field__control">
        {(values || []).map((value) => (
          <button
            type="button"
            key={value}
            title="Удалить"
            onClick={() => onChange(values.filter((item) => item !== value))}
          >
            {value}
            <b aria-hidden="true">×</b>
          </button>
        ))}
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          onBlur={add}
          onKeyDown={(event) => {
            if (["Enter", ","].includes(event.key)) {
              event.preventDefault();
              add();
            }
          }}
          placeholder={placeholder}
        />
      </div>
    </div>
  );
}

function setAtPath(source, path, value) {
  const [key, ...rest] = path.split(".");
  if (!rest.length) return { ...(source || {}), [key]: value };
  return {
    ...(source || {}),
    [key]: setAtPath(source?.[key] || {}, rest.join("."), value),
  };
}

function mergeDeep(base, override) {
  if (!base || typeof base !== "object" || Array.isArray(base))
    return override ?? base;
  const result = { ...base };
  for (const [key, value] of Object.entries(override || {})) {
    result[key] =
      value &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      base[key] &&
      typeof base[key] === "object" &&
      !Array.isArray(base[key])
        ? mergeDeep(base[key], value)
        : value;
  }
  return result;
}

function compactConfig(value) {
  if (Array.isArray(value)) return value.map(compactConfig);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).flatMap(([key, nested]) => {
      if (nested === "" || nested === undefined || nested === null) return [];
      return [[key, compactConfig(nested)]];
    }),
  );
}

function clone(value) {
  return value === undefined ? undefined : JSON.parse(JSON.stringify(value));
}

function conditionValueType(value) {
  if (typeof value === "boolean") return "boolean";
  if (typeof value === "number") return "number";
  return "text";
}

function typedConditionValue(value, type) {
  if (type === "boolean") return Boolean(value);
  if (type === "number") return Number(value);
  return String(value ?? "");
}

function secondsToMinutes(value) {
  if (value === "") return "";
  return Math.max(1, Math.round(Number(value || 7200) / 60));
}

function collectQueryRules(node) {
  if (!node || typeof node !== "object") return [];
  if (node.field_path !== undefined) return [node];
  return (node.rules || []).flatMap(collectQueryRules);
}

function queryOperators(type) {
  if (type === "number")
    return [
      ["equals", "Равно"],
      ["not_equals", "Не равно"],
      ["gt", "Больше"],
      ["gte", "Больше или равно"],
      ["lt", "Меньше"],
      ["lte", "Меньше или равно"],
      ["exists", "Поле заполнено"],
    ];
  if (type === "boolean")
    return [
      ["is_true", "Да / истина"],
      ["is_false", "Нет / ложь"],
      ["exists", "Поле заполнено"],
    ];
  return [
    ["equals", "Равно"],
    ["not_equals", "Не равно"],
    ["contains", "Содержит"],
    ["starts_with", "Начинается с"],
    ["in", "В списке"],
    ["exists", "Поле заполнено"],
    ["not_exists", "Поле отсутствует"],
  ];
}
