import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../../api/client.js";
import {
  Button,
  ConfirmDialog,
  Field,
  Panel,
  Toggle,
} from "../../shared/ui.jsx";
import {
  OS_LABELS,
  emptyPresetForm,
  formToPayload,
  presetFormProblems,
  presetToForm,
  templateDraftToForm,
} from "./presetForm.js";

const GROUP_RENDER_LIMIT = 200;

function nameById(items, id) {
  if (!id) return "—";
  return (items || []).find((item) => item.id === id)?.name || id;
}

export function TaskPresetsPage({ showAlert }) {
  const queryClient = useQueryClient();
  const [osFilter, setOsFilter] = useState("");
  const [showArchived, setShowArchived] = useState(false);
  const [form, setForm] = useState(null);
  const [archiveTarget, setArchiveTarget] = useState(null);

  const presetsQuery = useQuery({
    queryKey: ["task-presets", { archived: showArchived }],
    queryFn: () =>
      api(`/api/task-presets${showArchived ? "?include_archived=true" : ""}`),
  });
  const rolesQuery = useQuery({
    queryKey: ["auth-roles"],
    queryFn: () => api("/api/auth/roles"),
  });
  const lookupsQuery = useQuery({
    queryKey: ["task-presets", "lookups"],
    queryFn: () => api("/api/task-presets/lookups"),
    enabled: Boolean(form),
    staleTime: 60000,
  });
  const groupsQuery = useQuery({
    queryKey: ["task-presets", "asset-groups"],
    queryFn: () => api("/api/task-presets/asset-groups"),
    enabled: Boolean(form),
    staleTime: 60000,
  });
  const templatesQuery = useQuery({
    queryKey: ["task-preset-templates"],
    queryFn: () => api("/api/task-presets/templates"),
    staleTime: Infinity,
  });

  const roles = useMemo(() => rolesQuery.data?.rows || [], [rolesQuery.data]);
  const lookups = lookupsQuery.data || {};
  const presets = (presetsQuery.data?.rows || []).filter(
    (preset) => !osFilter || preset.os_family === osFilter,
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    const taskId = new URLSearchParams(window.location.search).get("from_task");
    if (!taskId) return;
    window.history.replaceState({}, "", window.location.pathname);
    api(`/api/task-presets/from-task/${encodeURIComponent(taskId)}`, {
      method: "POST",
    })
      .then((result) => {
        setForm(presetToForm(result.draft));
        showAlert(
          "Черновик пресета заполнен по задаче. Проверьте роли и группы.",
          "info",
        );
      })
      .catch((error) =>
        showAlert(error.operatorMessage || error.message, "error"),
      );
  }, [showAlert]);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ["task-presets"] });

  const saveMutation = useMutation({
    mutationFn: (value) => {
      const payload = formToPayload(value);
      return value.preset_id
        ? api(`/api/task-presets/${value.preset_id}`, {
            method: "PUT",
            body: JSON.stringify(payload),
          })
        : api("/api/task-presets", {
            method: "POST",
            body: JSON.stringify(payload),
          });
    },
    onSuccess: async (preset) => {
      showAlert(`Пресет «${preset.name}» сохранён.`, "success");
      setForm(null);
      await refresh();
    },
    onError: (error) =>
      showAlert(error.operatorMessage || error.message, "error"),
  });
  const templateMutation = useMutation({
    mutationFn: (templateId) =>
      api(`/api/task-presets/from-template/${encodeURIComponent(templateId)}`, {
        method: "POST",
      }),
    onSuccess: (result) => {
      const warned = Boolean(result.warnings?.length);
      setForm(templateDraftToForm(result));
      showAlert(
        warned
          ? "Черновик заполнен по шаблону. Проверьте предупреждения в форме."
          : "Черновик заполнен по шаблону. Проверьте параметры и выберите разрешённые группы.",
        warned ? "warning" : "info",
      );
    },
    onError: (error) =>
      showAlert(error.operatorMessage || error.message, "error"),
  });
  const archiveMutation = useMutation({
    mutationFn: (preset) =>
      api(`/api/task-presets/${preset.preset_id}/archive`, {
        method: "POST",
        body: JSON.stringify({ expected_version: preset.version }),
      }),
    onSuccess: async () => {
      showAlert("Пресет перенесён в архив.", "success");
      setArchiveTarget(null);
      await refresh();
    },
    onError: (error) =>
      showAlert(error.operatorMessage || error.message, "error"),
  });

  return (
    <div className="task-presets-page">
      <Panel
        title="Пресеты задач"
        description="Готовые наборы параметров сканирования для инженеров: профиль, учётная запись, область и разрешённые группы активов."
        action={
          <div className="action-row">
            <Button
              variant="secondary"
              busy={presetsQuery.isFetching}
              onClick={() => presetsQuery.refetch()}
            >
              Обновить
            </Button>
            <Button onClick={() => setForm(emptyPresetForm())}>
              + Новый пресет
            </Button>
          </div>
        }
      >
        <div className="preset-toolbar">
          <Field label="ОС">
            <select
              value={osFilter}
              onChange={(event) => setOsFilter(event.target.value)}
            >
              <option value="">Все</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
          </Field>
          <Toggle
            label="Показывать архив"
            checked={showArchived}
            onChange={setShowArchived}
          />
        </div>
        <div className="table-shell preset-table-scroll">
          <table>
            <thead>
              <tr>
                <th scope="col">Название</th>
                <th scope="col">ОС</th>
                <th scope="col">Группы</th>
                <th scope="col">Роли</th>
                <th scope="col">Лимиты</th>
                <th scope="col">Состояние</th>
                <th scope="col">
                  <span className="team-sr-only">Действия</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {presets.map((preset) => (
                <tr key={preset.preset_id}>
                  <td>
                    <strong>{preset.name}</strong>
                    {preset.description ? (
                      <small className="preset-muted">
                        {preset.description}
                      </small>
                    ) : null}
                  </td>
                  <td>{OS_LABELS[preset.os_family] || preset.os_family}</td>
                  <td>{(preset.allowed_asset_groups || []).length}</td>
                  <td>
                    {(preset.role_ids || [])
                      .map((id) => nameById(roles, id))
                      .join(", ") || "—"}
                  </td>
                  <td>
                    до {preset.max_groups_per_task} групп ·{" "}
                    {preset.max_active_tasks
                      ? `${preset.max_active_tasks} одновременно`
                      : "без лимита запусков"}
                  </td>
                  <td>
                    {preset.is_active ? "Активен" : "В архиве"} · v
                    {preset.version}
                  </td>
                  <td>
                    {preset.is_active ? (
                      <div className="row-actions">
                        <Button
                          variant="tiny"
                          onClick={() => setForm(presetToForm(preset))}
                        >
                          Изменить
                        </Button>
                        <Button
                          variant="tiny"
                          onClick={() => setArchiveTarget(preset)}
                        >
                          В архив
                        </Button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
              {!presetsQuery.isLoading && !presets.length ? (
                <tr>
                  <td colSpan={7} className="empty-cell">
                    Пресетов пока нет. Создайте пресет по шаблону ниже или
                    используйте «Сделать пресетом» в разделе задач.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </Panel>

      {form ? (
        <PresetEditor
          form={form}
          setForm={setForm}
          roles={roles}
          lookups={lookups}
          lookupsError={lookupsQuery.error}
          groups={groupsQuery.data?.rows || []}
          groupsLoading={groupsQuery.isLoading}
          groupsError={groupsQuery.error}
          templates={templatesQuery.data?.rows || []}
          saving={saveMutation.isPending}
          onSave={() => saveMutation.mutate(form)}
          onCancel={() => setForm(null)}
        />
      ) : (
        <PresetTemplates
          catalogue={templatesQuery.data}
          loading={templatesQuery.isLoading}
          error={templatesQuery.error}
          osFilter={osFilter}
          pendingId={
            templateMutation.isPending ? templateMutation.variables : null
          }
          onUse={(templateId) => templateMutation.mutate(templateId)}
        />
      )}

      <ConfirmDialog
        open={Boolean(archiveTarget)}
        title="Перенести пресет в архив?"
        description="Инженеры перестанут видеть пресет. Созданные по нему задачи останутся, но запустить их будет нельзя."
        confirmLabel="В архив"
        busy={archiveMutation.isPending}
        onConfirm={() => archiveMutation.mutate(archiveTarget)}
        onClose={() => setArchiveTarget(null)}
      />
    </div>
  );
}

function PresetTemplates({
  catalogue,
  loading,
  error,
  osFilter,
  pendingId,
  onUse,
}) {
  const templates = (catalogue?.rows || []).filter(
    (template) => !osFilter || template.os_family === osFilter,
  );
  return (
    <Panel
      title="Шаблоны по рекомендациям MP VM"
      description="Типовые задачи инженеров Windows и Linux. Шаблон подставит стандартный профиль MP VM, precheck, лимиты и роль команды; останется выбрать учётную запись и разрешённые группы."
    >
      {error ? (
        <p className="preset-error" role="alert">
          Не удалось загрузить шаблоны: {error.operatorMessage || error.message}
        </p>
      ) : null}
      {loading ? <p className="preset-muted">Загрузка…</p> : null}
      <div className="team-preset-grid">
        {templates.map((template) => (
          <article
            className="team-preset-card preset-template-card"
            key={template.template_id}
          >
            <span
              className={`team-os-badge team-os-badge--${template.os_family}`}
            >
              {OS_LABELS[template.os_family] || template.os_family}
            </span>
            <h3>{template.name}</h3>
            <p>{template.purpose}</p>
            <p className="preset-template-profile">
              {template.module} · <strong>{template.profile_names[0]}</strong>
            </p>
            <dl>
              <div>
                <dt>Учётная запись</dt>
                <dd>
                  {template.credential === "required" ? "Нужна" : "Не нужна"}
                </dd>
              </div>
              <div>
                <dt>Precheck</dt>
                <dd>{template.precheck_enabled ? "Включён" : "Выключен"}</dd>
              </div>
              <div>
                <dt>Групп в задаче</dt>
                <dd>до {template.max_groups_per_task}</dd>
              </div>
              <div>
                <dt>Запусков сразу</dt>
                <dd>
                  {template.max_active_tasks
                    ? `до ${template.max_active_tasks}`
                    : "без лимита"}
                </dd>
              </div>
            </dl>
            <Button
              variant="secondary"
              busy={pendingId === template.template_id}
              disabled={Boolean(pendingId)}
              aria-label={`Создать пресет по шаблону «${template.name}»`}
              onClick={() => onUse(template.template_id)}
            >
              Создать пресет
            </Button>
          </article>
        ))}
      </div>
      {catalogue?.avoid?.length ? (
        <div className="preset-template-avoid">
          <strong>Не стоит давать инженерам</strong>
          <ul>
            {catalogue.avoid.map((item) => (
              <li key={item.profile}>
                <b>{item.profile}</b> — {item.reason}
              </li>
            ))}
          </ul>
          {catalogue.docs_url ? (
            <a href={catalogue.docs_url} target="_blank" rel="noreferrer">
              Рекомендации PT по использованию профилей
            </a>
          ) : null}
        </div>
      ) : null}
    </Panel>
  );
}

function PresetEditor({
  form,
  setForm,
  roles,
  lookups,
  lookupsError,
  groups,
  groupsLoading,
  groupsError,
  templates,
  saving,
  onSave,
  onCancel,
}) {
  const [groupSearch, setGroupSearch] = useState("");
  const update = (patch) => setForm((current) => ({ ...current, ...patch }));
  const problems = presetFormProblems(form);
  const profiles = lookups.scanner_profiles || [];
  const template = templates.find(
    (item) => form.template_id && item.template_id === form.template_id,
  );
  const selectedIds = new Set(form.allowed_asset_groups.map((item) => item.id));
  const groupById = new Map(groups.map((group) => [group.id, group]));
  const query = groupSearch.trim().toLocaleLowerCase("ru-RU");
  const visibleGroups = groups
    .filter(
      (group) =>
        !query ||
        String(group.path || group.name)
          .toLocaleLowerCase("ru-RU")
          .includes(query),
    )
    .slice(0, GROUP_RENDER_LIMIT);

  const toggleGroup = (group) =>
    update({
      allowed_asset_groups: selectedIds.has(group.id)
        ? form.allowed_asset_groups.filter((item) => item.id !== group.id)
        : [...form.allowed_asset_groups, group],
    });
  const toggleList = (key, id) =>
    update({
      [key]: form[key].includes(id)
        ? form[key].filter((value) => value !== id)
        : [...form[key], id],
    });

  return (
    <Panel
      title={form.preset_id ? `Пресет «${form.name}»` : "Новый пресет"}
      description="Инженер выберет группы активов из разрешённых и/или впишет IP-адреса, подсети или FQDN. Остальные параметры задаются здесь и не меняются при создании задачи."
    >
      {lookupsError ? (
        <p className="preset-error" role="alert">
          Справочники MP VM недоступны:{" "}
          {lookupsError.operatorMessage || lookupsError.message}
        </p>
      ) : null}
      {template ? (
        <div
          className="preset-template-hint"
          role="note"
          aria-label="Рекомендации шаблона"
        >
          <p>
            <strong>Шаблон «{template.name}».</strong> Профиль MP VM:{" "}
            {template.profile_names.join(" или ")} (модуль {template.module}).
          </p>
          <p>Учётная запись: {template.credential_hint}</p>
          {form.template_warnings?.length ? (
            <ul className="preset-template-warnings">
              {form.template_warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          ) : null}
          <ul>
            {template.notes.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        </div>
      ) : null}
      <div className="form-grid form-grid--two">
        <Field label="Название">
          <input
            value={form.name}
            maxLength={120}
            autoFocus={Boolean(form.template_id)}
            onChange={(event) => update({ name: event.target.value })}
          />
        </Field>
        <Field label="ОС">
          <select
            value={form.os_family}
            onChange={(event) => update({ os_family: event.target.value })}
          >
            <option value="windows">Windows (WMI/RPC)</option>
            <option value="linux">Linux (SSH)</option>
          </select>
        </Field>
        <Field label="Описание для инженеров" wide>
          <input
            value={form.description}
            maxLength={2000}
            onChange={(event) => update({ description: event.target.value })}
          />
        </Field>
        <Field label="Область (scope)">
          <select
            value={form.scope_id}
            onChange={(event) => update({ scope_id: event.target.value })}
          >
            <option value="">Выберите область</option>
            {(lookups.scopes || []).map((item) => (
              <option value={item.id} key={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Профиль сканирования">
          <select
            value={form.profile_id}
            onChange={(event) => update({ profile_id: event.target.value })}
          >
            <option value="">Выберите профиль</option>
            {profiles.map((item) => (
              <option value={item.id} key={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Учётная запись">
          <select
            value={form.credential_id}
            onChange={(event) => update({ credential_id: event.target.value })}
          >
            <option value="">Без учётной записи (из профиля)</option>
            {(lookups.credentials || []).map((item) => (
              <option value={item.id} key={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Префикс имени задачи">
          <input
            value={form.name_prefix}
            maxLength={60}
            placeholder="[WIN]"
            onChange={(event) => update({ name_prefix: event.target.value })}
          />
        </Field>
        <Field label="Групп в одной задаче, не больше">
          <input
            type="number"
            min={1}
            max={100}
            value={form.max_groups_per_task}
            onChange={(event) =>
              update({ max_groups_per_task: event.target.value })
            }
          />
        </Field>
        <Field label="Одновременных запусков (пусто — без лимита)">
          <input
            type="number"
            min={1}
            max={100}
            value={form.max_active_tasks ?? ""}
            onChange={(event) =>
              update({ max_active_tasks: event.target.value })
            }
          />
        </Field>
        <Field label="Часовой пояс">
          <input
            value={form.time_zone}
            onChange={(event) => update({ time_zone: event.target.value })}
          />
        </Field>
      </div>

      <div className="preset-options">
        <Toggle
          label="Проверять доступность хостов (precheck) перед сканированием"
          checked={form.precheck_enabled}
          onChange={(value) => update({ precheck_enabled: value })}
        />
        {form.precheck_enabled ? (
          <Field label="Профиль precheck">
            <select
              value={form.precheck_profile_id}
              onChange={(event) =>
                update({ precheck_profile_id: event.target.value })
              }
            >
              <option value="">Профиль задачи</option>
              {profiles.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </Field>
        ) : null}
        <Toggle
          label="HostDiscovery"
          checked={form.host_discovery_enabled}
          onChange={(value) => update({ host_discovery_enabled: value })}
        />
        {form.host_discovery_enabled ? (
          <Field label="Профиль HostDiscovery">
            <select
              value={form.host_discovery_profile_id}
              onChange={(event) =>
                update({ host_discovery_profile_id: event.target.value })
              }
            >
              <option value="">Профиль по умолчанию</option>
              {profiles.map((item) => (
                <option value={item.id} key={item.id}>
                  {item.name}
                </option>
              ))}
            </select>
          </Field>
        ) : null}
        <Toggle
          label="Приоритет FQDN"
          checked={form.is_fqdn_priority}
          onChange={(value) => update({ is_fqdn_priority: value })}
        />
        {form.trigger_parameters ? (
          <div className="preset-schedule">
            <span>Расписание перенесено из исходной задачи.</span>
            <Button
              variant="tiny"
              onClick={() => update({ trigger_parameters: null })}
            >
              Сделать разовым
            </Button>
          </div>
        ) : null}
      </div>

      <fieldset className="preset-fieldset">
        <legend>Кому доступен пресет</legend>
        <div className="preset-checks">
          {roles.map((role) => (
            <label className="toggle" key={role.id}>
              <input
                type="checkbox"
                checked={form.role_ids.includes(role.id)}
                onChange={() => toggleList("role_ids", role.id)}
              />
              <span>{role.name}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {(lookups.agents || []).length ? (
        <fieldset className="preset-fieldset">
          <legend>Агенты (коллекторы)</legend>
          <div className="preset-checks">
            {lookups.agents.map((agent) => (
              <label className="toggle" key={agent.id}>
                <input
                  type="checkbox"
                  checked={form.agent_ids.includes(agent.id)}
                  onChange={() => toggleList("agent_ids", agent.id)}
                />
                <span>{agent.name}</span>
              </label>
            ))}
          </div>
        </fieldset>
      ) : null}

      <fieldset className="preset-fieldset">
        <legend>
          Разрешённые группы активов MP VM · выбрано{" "}
          {form.allowed_asset_groups.length}
        </legend>
        {form.allowed_asset_groups.length ? (
          <ul className="preset-chips" aria-label="Выбранные группы">
            {form.allowed_asset_groups.map((group) => (
              <li key={group.id}>
                <span>
                  {group.path ||
                    group.name ||
                    groupById.get(group.id)?.path ||
                    group.id}
                </span>
                <button
                  type="button"
                  aria-label={`Убрать группу ${group.name || group.id}`}
                  onClick={() => toggleGroup(group)}
                >
                  ×
                </button>
              </li>
            ))}
          </ul>
        ) : null}
        <input
          type="search"
          value={groupSearch}
          placeholder="Поиск группы по пути"
          aria-label="Поиск группы активов"
          onChange={(event) => setGroupSearch(event.target.value)}
        />
        {groupsError ? (
          <p className="preset-error" role="alert">
            Не удалось загрузить группы MP VM:{" "}
            {groupsError.operatorMessage || groupsError.message}
          </p>
        ) : null}
        <div className="preset-group-list">
          {groupsLoading ? <p className="preset-muted">Загрузка…</p> : null}
          {visibleGroups.map((group) => (
            <label className="toggle" key={group.id}>
              <input
                type="checkbox"
                checked={selectedIds.has(group.id)}
                onChange={() => toggleGroup(group)}
              />
              <span>{group.path || group.name}</span>
            </label>
          ))}
        </div>
      </fieldset>

      {problems.length ? (
        <ul className="preset-problems" aria-label="Что нужно заполнить">
          {problems.map((problem) => (
            <li key={problem}>{problem}</li>
          ))}
        </ul>
      ) : null}
      <div className="action-row">
        <Button variant="secondary" disabled={saving} onClick={onCancel}>
          Отмена
        </Button>
        <Button busy={saving} disabled={problems.length > 0} onClick={onSave}>
          Сохранить пресет
        </Button>
      </div>
    </Panel>
  );
}
