import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, createIdempotencyKey } from "../../api/client.js";
import { TaskBuilderPanel } from "../../panels.jsx";

const ALL_TASKS = "__all__";
const UNGROUPED_TASKS = "__ungrouped__";

export function TaskWorkspace(props) {
  const {
    busy = {},
    currentUser,
    defaults,
    error,
    loading = false,
    lookups,
    refreshTasks,
    runBusy = (_key, action) => action(),
    selectedTaskId,
    setSelectedTaskId,
    showAlert,
    session,
    systemStatus,
    tasks = [],
  } = props;
  const permissions = new Set(currentUser?.permissions || []);
  const canManage = permissions.has("tasks.manage");
  const canExecute = permissions.has("tasks.execute");
  const [view, setView] = useState("list");
  const [folderId, setFolderId] = useState(ALL_TASKS);
  const [query, setQuery] = useState("");
  const [folders, setFolders] = useState([]);
  const [folderError, setFolderError] = useState("");
  const [folderBusy, setFolderBusy] = useState(false);
  const [newFolderName, setNewFolderName] = useState(null);
  const [newFolderValue, setNewFolderValue] = useState("");
  const [moveTo, setMoveTo] = useState("");
  const [checkedTaskIds, setCheckedTaskIds] = useState([]);
  const [copyTask, setCopyTask] = useState(null);
  const [editorTaskId, setEditorTaskId] = useState(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [runsState, setRunsState] = useState(null);
  const [jobsState, setJobsState] = useState(null);
  const runsOffsetRef = useRef(0);

  const selectedTask =
    tasks.find((task) => task.mp_task_id === selectedTaskId) || null;
  const editorTask =
    tasks.find((task) => task.mp_task_id === editorTaskId) || null;
  const memberships = useMemo(() => {
    const result = new Map();
    for (const folder of folders) {
      for (const taskId of folder.task_ids || [])
        result.set(taskId, folder.folder_id);
    }
    return result;
  }, [folders]);
  const ungroupedCount = tasks.filter(
    (task) => !memberships.has(task.mp_task_id),
  ).length;
  const visibleTasks = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase();
    return tasks.filter((task) => {
      const assignedFolder = memberships.get(task.mp_task_id);
      if (folderId === UNGROUPED_TASKS && assignedFolder) return false;
      if (
        folderId !== ALL_TASKS &&
        folderId !== UNGROUPED_TASKS &&
        assignedFolder !== folderId
      )
        return false;
      if (!needle) return true;
      return `${task.name || ""} ${task.mp_task_id || ""}`
        .toLocaleLowerCase()
        .includes(needle);
    });
  }, [folderId, memberships, query, tasks]);

  const loadFolders = async () => {
    try {
      setFolderError("");
      const result = await api("/api/scanner-task-folders");
      setFolders(Array.isArray(result?.rows) ? result.rows : []);
    } catch (loadError) {
      setFolderError(loadError.message || "Не удалось загрузить папки задач.");
    }
  };

  useEffect(() => {
    void loadFolders();
  }, []);

  const openEditor = (task = null, copy = false) => {
    setEditorTaskId(task && !copy ? task.mp_task_id : null);
    setCopyTask(copy ? task : null);
    setView("editor");
  };

  const openDetails = (task) => {
    setSelectedTaskId(task.mp_task_id);
    runsOffsetRef.current = 0;
    setRunsState({ loading: true, error: null, items: [] });
    setJobsState(null);
    setView("detail");
  };

  const loadJobs = useCallback(
    async (runId) => {
      if (!selectedTaskId || !runId) return;
      setJobsState({ runId, loading: true, error: null, items: [] });
      try {
        const result = await api(
          `/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}/runs/${encodeURIComponent(runId)}/jobs`,
        );
        setJobsState({
          runId,
          loading: false,
          error: null,
          items: objectRecords(result?.items),
        });
      } catch (loadError) {
        setJobsState({
          runId,
          loading: false,
          error: loadError.message || "Не удалось загрузить задания запуска.",
          items: [],
        });
      }
    },
    [selectedTaskId],
  );

  const loadRuns = useCallback(
    async (append = false) => {
      if (!selectedTaskId) return;
      const offset = append ? runsOffsetRef.current : 0;
      setRunsState((current) => ({
        ...(current || {}),
        loading: true,
        error: null,
      }));
      try {
        const result = await api(
          `/api/scanner-tasks/${encodeURIComponent(selectedTaskId)}/runs?offset=${offset}&limit=50`,
        );
        const items = objectRecords(result?.items);
        runsOffsetRef.current = offset + items.length;
        setRunsState((current) => ({
          loading: false,
          error: null,
          items: append ? [...(current?.items || []), ...items] : items,
          hasMore: Boolean(result?.has_more),
        }));
        if (!append && items[0]?.id) void loadJobs(items[0].id);
      } catch (loadError) {
        setRunsState({
          loading: false,
          error: loadError.message || "Не удалось загрузить историю запусков.",
          items: [],
        });
      }
    },
    [loadJobs, selectedTaskId],
  );

  useEffect(() => {
    if (view === "detail" && selectedTaskId) void loadRuns();
  }, [loadRuns, selectedTaskId, view]);

  const createFolder = async (event) => {
    event.preventDefault();
    const name = newFolderValue.trim();
    if (!name) return;
    setFolderBusy(true);
    try {
      const folder = await api("/api/scanner-task-folders", {
        method: "POST",
        body: JSON.stringify({ name }),
      });
      setFolders((current) =>
        [...current, { ...folder, task_ids: [] }].sort((a, b) =>
          a.name.localeCompare(b.name),
        ),
      );
      setFolderId(folder.folder_id);
      setNewFolderName(null);
      setNewFolderValue("");
    } catch (saveError) {
      setFolderError(saveError.message || "Не удалось создать папку.");
    } finally {
      setFolderBusy(false);
    }
  };

  const renameFolder = async (folder) => {
    const name = window.prompt("Название папки", folder.name);
    if (name == null || !name.trim() || name.trim() === folder.name) return;
    try {
      const updated = await api(
        `/api/scanner-task-folders/${encodeURIComponent(folder.folder_id)}`,
        { method: "PATCH", body: JSON.stringify({ name }) },
      );
      setFolders((current) =>
        current
          .map((item) =>
            item.folder_id === folder.folder_id
              ? { ...item, ...updated }
              : item,
          )
          .sort((a, b) => a.name.localeCompare(b.name)),
      );
    } catch (saveError) {
      setFolderError(saveError.message || "Не удалось переименовать папку.");
    }
  };

  const deleteFolder = async (folder) => {
    if (
      !window.confirm(
        `Удалить папку «${folder.name}»? Задачи останутся без группы.`,
      )
    )
      return;
    try {
      await api(
        `/api/scanner-task-folders/${encodeURIComponent(folder.folder_id)}`,
        { method: "DELETE" },
      );
      setFolders((current) =>
        current.filter((item) => item.folder_id !== folder.folder_id),
      );
      if (folderId === folder.folder_id) setFolderId(ALL_TASKS);
    } catch (saveError) {
      setFolderError(saveError.message || "Не удалось удалить папку.");
    }
  };

  const assignTasks = async (taskIds, destination) => {
    if (!taskIds.length) return;
    try {
      await api("/api/scanner-task-folders/assignments", {
        method: "PUT",
        body: JSON.stringify({
          task_ids: taskIds,
          folder_id: destination || null,
        }),
      });
      await loadFolders();
      setCheckedTaskIds([]);
      setMoveTo("");
    } catch (saveError) {
      setFolderError(saveError.message || "Не удалось переместить задачи.");
    }
  };

  const taskAction = async (task, action) => {
    if (!task) return;
    try {
      const options = { method: "POST" };
      if (action === "start") {
        options.headers = {
          "X-Idempotency-Key": createIdempotencyKey("scan-start"),
        };
        options.body = JSON.stringify({});
      }
      const result = await runBusy(`${action}Task`, () =>
        api(
          `/api/scanner-tasks/${encodeURIComponent(task.mp_task_id)}/${action}`,
          options,
        ),
      );
      if (action === "validate")
        showAlert(
          result.valid
            ? "Проверка задачи пройдена."
            : `Проверка не пройдена: ${result.error || "ошибка"}`,
          result.valid ? "success" : "warning",
        );
      else
        showAlert(
          action === "start"
            ? "Запуск задачи отправлен."
            : "Остановка задачи отправлена.",
          "success",
        );
      await refreshTasks();
    } catch (actionError) {
      showAlert(actionError.message || String(actionError), "error");
    }
  };

  const deleteTask = async (task) => {
    try {
      await runBusy("deleteTask", () =>
        api(
          `/api/scanner-tasks/${encodeURIComponent(task.mp_task_id)}/delete`,
          {
            method: "POST",
            headers: {
              "X-Idempotency-Key": createIdempotencyKey("task-delete"),
            },
            body: JSON.stringify({ mode: "auto" }),
          },
        ),
      );
      if (selectedTaskId === task.mp_task_id) setSelectedTaskId(null);
      setConfirmDeleteId(null);
      await refreshTasks();
      await loadFolders();
      showAlert(`Задача удалена: ${task.name || task.mp_task_id}`, "success");
    } catch (actionError) {
      showAlert(actionError.message || String(actionError), "error");
    }
  };

  const toggleCheckedTask = (taskId) =>
    setCheckedTaskIds((current) =>
      current.includes(taskId)
        ? current.filter((value) => value !== taskId)
        : [...current, taskId],
    );
  if (view === "editor") {
    return (
      <main className="task-workspace task-editor-shell">
        <div className="task-view-heading">
          <button
            type="button"
            className="task-back-button"
            onClick={() => setView("list")}
          >
            ← К задачам
          </button>
          <span>
            {copyTask ? "НОВАЯ КОПИЯ" : editorTaskId ? "ИЗМЕНЕНИЕ" : "СОЗДАНИЕ"}
          </span>
        </div>
        <TaskBuilderPanel
          defaults={defaults}
          lookups={
            lookups || {
              scopes: [],
              scanner_profiles: [],
              credentials: [],
              agents: [],
            }
          }
          tasks={tasks}
          selectedTask={editorTask}
          selectedTaskId={editorTaskId}
          setSelectedTaskId={setSelectedTaskId}
          refreshTasks={refreshTasks}
          busy={busy}
          runBusy={runBusy}
          showAlert={showAlert}
          session={session}
          systemStatus={systemStatus}
          editorMode
          copyTask={copyTask}
          onCancel={() => setView("list")}
          onSaved={(task) => {
            if (task?.mp_task_id) setSelectedTaskId(task.mp_task_id);
            setEditorTaskId(null);
            setCopyTask(null);
            setView("list");
          }}
        />
      </main>
    );
  }

  if (view === "detail") {
    return (
      <main className="task-workspace task-detail-view">
        <div className="task-view-heading">
          <button
            type="button"
            className="task-back-button"
            onClick={() => setView("list")}
          >
            ← К задачам
          </button>
          <span>ИСТОРИЯ И РЕЗУЛЬТАТЫ</span>
        </div>
        <section className="task-detail-grid">
          <aside className="task-detail-summary">
            <TaskSummary
              task={selectedTask}
              folderName={
                folders.find(
                  (folder) =>
                    folder.folder_id ===
                    memberships.get(selectedTask?.mp_task_id),
                )?.name || "Без группы"
              }
            />
          </aside>
          <section
            className="task-history-panel"
            aria-labelledby="task-runs-title"
          >
            <header>
              <div>
                <h2 id="task-runs-title">Запуски</h2>
                <p>{runsState?.items?.length || 0} записей</p>
              </div>
              <button type="button" onClick={loadRuns}>
                Обновить
              </button>
            </header>
            {runsState?.loading ? (
              <p role="status">Загружаем историю…</p>
            ) : runsState?.error ? (
              <div className="task-inline-error" role="alert">
                <p>{runsState.error}</p>
                <button type="button" onClick={loadRuns}>
                  Повторить
                </button>
              </div>
            ) : !runsState?.items?.length ? (
              <p className="task-empty">У задачи пока нет запусков.</p>
            ) : (
              <div className="task-runs-list">
                {runsState.items.map((run, index) => (
                  <button
                    type="button"
                    key={run.id || index}
                    className={`task-run-item ${jobsState?.runId === run.id ? "is-active" : ""}`}
                    onClick={() => void loadJobs(run.id)}
                  >
                    <span className="task-run-item__status">
                      {displayText(run.status) || "Запуск"}
                    </span>
                    <strong>
                      {formatDate(run.startedAt || run.createdAt)}
                    </strong>
                    <small>
                      {displayText(run.initiator) ||
                        displayText(run.startedBy) ||
                        "Запуск MP VM"}
                    </small>
                    <span className="task-run-item__id">
                      {displayText(run.id)}
                    </span>
                  </button>
                ))}
                {runsState.hasMore ? (
                  <button
                    type="button"
                    className="task-history-more"
                    disabled={runsState.loading}
                    onClick={() => loadRuns(true)}
                  >
                    {runsState.loading ? "Загрузка…" : "Показать ещё"}
                  </button>
                ) : null}
              </div>
            )}
          </section>
          <section
            className="task-jobs-panel"
            aria-labelledby="task-jobs-title"
          >
            <header>
              <div>
                <h2 id="task-jobs-title">Задания запуска</h2>
                <p>{jobsState?.items?.length || 0} целей</p>
              </div>
            </header>
            {jobsState?.loading ? (
              <p role="status">Загружаем задания…</p>
            ) : jobsState?.error ? (
              <div className="task-inline-error" role="alert">
                <p>{jobsState.error}</p>
                <button type="button" onClick={() => loadJobs(jobsState.runId)}>
                  Повторить
                </button>
              </div>
            ) : !jobsState?.items?.length ? (
              <p className="task-empty">
                Выберите запуск, чтобы посмотреть задания по целям.
              </p>
            ) : (
              <div className="task-jobs-table-wrap">
                <table className="task-jobs-table">
                  <thead>
                    <tr>
                      <th>Статус</th>
                      <th>Начало</th>
                      <th>Окончание</th>
                      <th>Длительность</th>
                      <th>Коллектор</th>
                      <th>Цель</th>
                      <th>Профиль</th>
                    </tr>
                  </thead>
                  <tbody>
                    {jobsState.items.map((job, index) => (
                      <tr key={job.id || index}>
                        <td>
                          <StatusBadge
                            status={job.status}
                            result={job.errorStatus}
                          />
                        </td>
                        <td>{formatDate(job.startedAt)}</td>
                        <td>{formatDate(job.finishedAt)}</td>
                        <td>{formatDuration(job.startedAt, job.finishedAt)}</td>
                        <td>
                          {displayText(job.agent) ||
                            displayText(job.collector) ||
                            "—"}
                        </td>
                        <td>
                          {displayTargets(job.targets) ||
                            displayText(job.target) ||
                            "—"}
                        </td>
                        <td>{displayText(job.profile) || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {jobsState.items.some((job) => connectionChecks(job).length) ? (
                  <div className="task-connection-checks">
                    <h3>Проверки соединения</h3>
                    {jobsState.items.flatMap((job, index) =>
                      connectionChecks(job).map((check, checkIndex) => (
                        <p key={`${index}-${checkIndex}`}>
                          <strong>
                            {typeof check.transport === "string"
                              ? check.transport
                              : "Проверка"}
                            :
                          </strong>{" "}
                          {typeof check.status === "string"
                            ? check.status
                            : "неизвестно"}
                          {formatCheckErrors(check.errors)}
                        </p>
                      )),
                    )}
                  </div>
                ) : null}
              </div>
            )}
          </section>
        </section>
      </main>
    );
  }

  return (
    <main className="task-workspace">
      <header className="task-workspace-toolbar">
        <div>
          <p className="task-workspace-eyebrow">MP VM / СКАНИРОВАНИЕ</p>
          <h1>Задачи</h1>
        </div>
        <div className="task-workspace-toolbar__actions">
          <button type="button" onClick={() => refreshTasks()}>
            Обновить
          </button>
          {canManage ? (
            <button
              type="button"
              className="task-primary-action"
              onClick={() => openEditor()}
            >
              + Создать задачу
            </button>
          ) : null}
        </div>
      </header>
      <section className="task-list-workspace">
        <aside className="task-folder-rail" aria-label="Группы задач">
          <header>
            <h2>Папки</h2>
            {canManage ? (
              <button
                type="button"
                aria-label="Создать папку"
                title="Создать папку"
                onClick={() => setNewFolderName(true)}
              >
                +
              </button>
            ) : null}
          </header>
          {folderError ? (
            <div className="task-folder-error" role="alert">
              <span>{folderError}</span>
              <button type="button" onClick={loadFolders}>
                Повторить
              </button>
            </div>
          ) : null}
          <nav>
            <FolderButton
              label="Все задачи"
              count={tasks.length}
              active={folderId === ALL_TASKS}
              onClick={() => setFolderId(ALL_TASKS)}
            />
            {folders.map((folder) => (
              <FolderButton
                key={folder.folder_id}
                label={folder.name}
                count={(folder.task_ids || []).length}
                active={folderId === folder.folder_id}
                onClick={() => setFolderId(folder.folder_id)}
                manage={canManage}
                onRename={() => renameFolder(folder)}
                onDelete={() => deleteFolder(folder)}
              />
            ))}
            <FolderButton
              label="Без группы"
              count={ungroupedCount}
              active={folderId === UNGROUPED_TASKS}
              onClick={() => setFolderId(UNGROUPED_TASKS)}
            />
          </nav>
          {newFolderName ? (
            <form className="task-new-folder" onSubmit={createFolder}>
              <label htmlFor="new-task-folder">Название папки</label>
              <input
                id="new-task-folder"
                autoFocus
                value={newFolderValue}
                onChange={(event) => setNewFolderValue(event.target.value)}
                maxLength={120}
              />
              <div>
                <button
                  type="submit"
                  disabled={folderBusy || !newFolderValue.trim()}
                >
                  {folderBusy ? "Сохранение…" : "Создать"}
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setNewFolderName(null);
                    setNewFolderValue("");
                  }}
                >
                  Отмена
                </button>
              </div>
            </form>
          ) : null}
        </aside>
        <section className="task-list-center" aria-label="Список задач">
          <div className="task-search-row">
            <label className="task-search">
              <span aria-hidden="true">⌕</span>
              <input
                type="search"
                placeholder="Поиск по названию или ID"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                aria-label="Поиск по задачам"
              />
            </label>
            <span>{visibleTasks.length} задач</span>
          </div>
          {canManage && checkedTaskIds.length ? (
            <div className="task-bulk-actions">
              <span>Выбрано: {checkedTaskIds.length}</span>
              <select
                aria-label="Папка назначения"
                value={moveTo}
                onChange={(event) => setMoveTo(event.target.value)}
              >
                <option value="">Выбрать папку…</option>
                <option value="__none__">Без группы</option>
                {folders.map((folder) => (
                  <option key={folder.folder_id} value={folder.folder_id}>
                    {folder.name}
                  </option>
                ))}
              </select>
              <button
                type="button"
                disabled={!moveTo}
                onClick={() =>
                  assignTasks(
                    checkedTaskIds,
                    moveTo === "__none__" ? null : moveTo,
                  )
                }
              >
                Переместить
              </button>
            </div>
          ) : null}
          <div className="task-table-scroll">
            <table className="task-workspace-table">
              <thead>
                <tr>
                  {canManage ? <th aria-label="Выбрать" /> : null}
                  <th>Статус</th>
                  <th>Название</th>
                  <th>Цели</th>
                  <th>Профиль</th>
                  <th>Параметры сбора</th>
                  <th>Коллекторы</th>
                  <th>Учётная запись</th>
                  <th>Создана</th>
                  <th>Последний запуск</th>
                  <th>Следующий запуск</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr className="task-table-message-row">
                    <td
                      colSpan={canManage ? 11 : 10}
                      className="task-table-empty"
                      role="status"
                    >
                      Загружаем задачи…
                    </td>
                  </tr>
                ) : error ? (
                  <tr className="task-table-message-row">
                    <td
                      colSpan={canManage ? 11 : 10}
                      className="task-table-empty"
                      role="alert"
                    >
                      {error}
                    </td>
                  </tr>
                ) : !visibleTasks.length ? (
                  <tr className="task-table-message-row">
                    <td
                      colSpan={canManage ? 11 : 10}
                      className="task-table-empty"
                    >
                      {query
                        ? "Задачи по запросу не найдены."
                        : "В этой группе пока нет задач."}
                    </td>
                  </tr>
                ) : (
                  visibleTasks.map((task) => (
                    <tr
                      key={task.mp_task_id}
                      tabIndex={0}
                      aria-selected={task.mp_task_id === selectedTaskId}
                      className={
                        task.mp_task_id === selectedTaskId ? "is-selected" : ""
                      }
                      onClick={() => setSelectedTaskId(task.mp_task_id)}
                      onDoubleClick={() => openDetails(task)}
                      onKeyDown={(event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          setSelectedTaskId(task.mp_task_id);
                        }
                      }}
                    >
                      {canManage ? (
                        <td data-label="Выбрать">
                          <input
                            type="checkbox"
                            aria-label={`Выбрать ${task.name || task.mp_task_id} для перемещения`}
                            checked={checkedTaskIds.includes(task.mp_task_id)}
                            onClick={(event) => event.stopPropagation()}
                            onChange={() => toggleCheckedTask(task.mp_task_id)}
                          />
                        </td>
                      ) : null}
                      <td data-label="Статус">
                        <StatusBadge status={task.status} />
                      </td>
                      <td data-label="Название">
                        <strong>{task.name || task.mp_task_id}</strong>
                        <small>{task.mp_task_id}</small>
                      </td>
                      <td data-label="Цели">
                        {taskTargets(task).slice(0, 2).join(", ") || "—"}
                      </td>
                      <td data-label="Профиль">
                        {task.profile_name ||
                          task.profile_id ||
                          task.payload?.profile ||
                          "—"}
                      </td>
                      <td data-label="Параметры сбора">
                        {taskCollectionSummary(task)}
                      </td>
                      <td data-label="Коллекторы">
                        {taskAgents(task).slice(0, 2).join(", ") || "—"}
                      </td>
                      <td data-label="Учётная запись">
                        {taskAccount(task) || "—"}
                      </td>
                      <td data-label="Создана">
                        {formatDate(task.created_at)}
                      </td>
                      <td data-label="Последний запуск">
                        {formatDate(task.last_run_at || task.lastRunAt)}
                      </td>
                      <td data-label="Следующий запуск">
                        {formatDate(
                          task.next_run_at ||
                            task.payload?.triggerParameters?.nextRunAt,
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
        <aside
          className="task-inspector"
          aria-label="Информация и действия по задаче"
        >
          {selectedTask ? (
            <>
              <TaskSummary
                task={selectedTask}
                folderName={
                  folders.find(
                    (folder) =>
                      folder.folder_id ===
                      memberships.get(selectedTask.mp_task_id),
                  )?.name || "Без группы"
                }
              />
              <div className="task-inspector-actions">
                <button type="button" onClick={() => openDetails(selectedTask)}>
                  Открыть подробности
                </button>
                {canManage ? (
                  <>
                    <button
                      type="button"
                      onClick={() => openEditor(selectedTask)}
                    >
                      Изменить
                    </button>
                    <button
                      type="button"
                      onClick={() => openEditor(selectedTask, true)}
                    >
                      Копировать
                    </button>
                    <select
                      aria-label="Переместить задачу"
                      value=""
                      onChange={(event) =>
                        assignTasks(
                          [selectedTask.mp_task_id],
                          event.target.value === "__none__"
                            ? null
                            : event.target.value,
                        )
                      }
                    >
                      <option value="" disabled>
                        Переместить в…
                      </option>
                      <option value="__none__">Без группы</option>
                      {folders.map((folder) => (
                        <option value={folder.folder_id} key={folder.folder_id}>
                          {folder.name}
                        </option>
                      ))}
                    </select>
                    <button
                      type="button"
                      className="task-danger-action"
                      onClick={() =>
                        setConfirmDeleteId(selectedTask.mp_task_id)
                      }
                    >
                      Удалить
                    </button>
                  </>
                ) : null}
                {canExecute ? (
                  <>
                    <button
                      type="button"
                      onClick={() => taskAction(selectedTask, "validate")}
                    >
                      Проверить
                    </button>
                    <button
                      type="button"
                      className="task-primary-action"
                      onClick={() => taskAction(selectedTask, "start")}
                    >
                      Запустить
                    </button>
                    {["running", "in_progress", "started"].includes(
                      String(selectedTask.status).toLowerCase(),
                    ) ? (
                      <button
                        type="button"
                        onClick={() => taskAction(selectedTask, "stop")}
                      >
                        Остановить
                      </button>
                    ) : null}
                  </>
                ) : null}
              </div>
              {confirmDeleteId === selectedTask.mp_task_id ? (
                <div
                  className="task-delete-confirm"
                  role="alertdialog"
                  aria-label="Подтвердить удаление"
                >
                  <p>
                    Удалить задачу «
                    {selectedTask.name || selectedTask.mp_task_id}»?
                  </p>
                  <button
                    type="button"
                    onClick={() => deleteTask(selectedTask)}
                  >
                    Удалить
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(null)}
                  >
                    Отмена
                  </button>
                </div>
              ) : null}
            </>
          ) : (
            <div className="task-inspector-empty">
              <span aria-hidden="true">↖</span>
              <h2>Выберите задачу</h2>
              <p>
                Щёлкните строку, чтобы посмотреть её параметры и доступные
                действия.
              </p>
            </div>
          )}
        </aside>
      </section>
    </main>
  );
}

function FolderButton({
  label,
  count,
  active,
  onClick,
  manage = false,
  onRename,
  onDelete,
}) {
  return (
    <div className={`task-folder-item ${active ? "is-active" : ""}`}>
      <button
        type="button"
        className="task-folder-item__select"
        aria-current={active ? "page" : undefined}
        onClick={onClick}
      >
        <span aria-hidden="true">▱</span>
        <span>{label}</span>
        <small>{count}</small>
      </button>
      {manage && onRename ? (
        <details className="task-folder-menu">
          <summary aria-label={`Действия: ${label}`}>···</summary>
          <div>
            <button type="button" onClick={onRename}>
              Переименовать
            </button>
            <button type="button" onClick={onDelete}>
              Удалить
            </button>
          </div>
        </details>
      ) : null}
    </div>
  );
}

function TaskSummary({ task, folderName }) {
  if (!task) return null;
  const payload = task.payload || {};
  const enabled = payload.triggerParameters?.isEnabled;
  return (
    <div className="task-summary">
      <p className="task-summary-eyebrow">ВЫБРАННАЯ ЗАДАЧА</p>
      <h2>{task.name || task.mp_task_id}</h2>
      <code>{task.mp_task_id}</code>
      <dl>
        <div>
          <dt>Статус</dt>
          <dd>
            <StatusBadge status={task.status} />
          </dd>
        </div>
        <div>
          <dt>Создана</dt>
          <dd>{formatDate(task.created_at)}</dd>
        </div>
        <div>
          <dt>Последний запуск</dt>
          <dd>{formatDate(task.last_run_at || task.lastRunAt)}</dd>
        </div>
        <div>
          <dt>Следующий запуск</dt>
          <dd>
            {formatDate(
              task.next_run_at || payload.triggerParameters?.nextRunAt,
            )}
          </dd>
        </div>
        <div>
          <dt>Папка</dt>
          <dd>{folderName}</dd>
        </div>
        <div>
          <dt>Описание</dt>
          <dd>{payload.description || "—"}</dd>
        </div>
        <div>
          <dt>Профиль</dt>
          <dd>
            {task.profile_name || task.profile_id || payload.profile || "—"}
          </dd>
        </div>
        <div>
          <dt>Учётная запись</dt>
          <dd>{taskAccount(task) || "—"}</dd>
        </div>
        <div>
          <dt>Расписание</dt>
          <dd>
            {enabled
              ? `${scheduleLabel(payload.triggerParameters)} · ${payload.triggerParameters?.timeZone || "UTC"}`
              : "Отключено"}
          </dd>
        </div>
        <div>
          <dt>Включено</dt>
          <dd>{taskTargets(task).join(", ") || "—"}</dd>
        </div>
        <div>
          <dt>Исключено</dt>
          <dd>{taskExclusions(task).join(", ") || "—"}</dd>
        </div>
        <div>
          <dt>Коллекторы</dt>
          <dd>{taskAgents(task).join(", ") || "—"}</dd>
        </div>
      </dl>
    </div>
  );
}

function taskTargets(task) {
  const targets = task.payload?.include?.targets || task.include_targets;
  return Array.isArray(targets) ? targets : [];
}

function taskExclusions(task) {
  const targets = task.payload?.exclude?.targets || task.exclude_targets;
  return Array.isArray(targets) ? targets : [];
}

function taskAgents(task) {
  const agents =
    task.agent_names || task.payload?.agents?.agentIds || task.agent_ids;
  return Array.isArray(agents) ? agents : [];
}

function objectRecords(value) {
  return Array.isArray(value)
    ? value.filter(
        (item) => item && typeof item === "object" && !Array.isArray(item),
      )
    : [];
}

function displayText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  for (const field of [
    "name",
    "displayName",
    "userName",
    "login",
    "value",
    "id",
  ]) {
    const label = value[field];
    if (typeof label === "string" && label) return label;
    if (typeof label === "number" && Number.isFinite(label))
      return String(label);
  }
  return "";
}

function displayTargets(value) {
  return Array.isArray(value)
    ? value.map(displayText).filter(Boolean).join(", ")
    : displayText(value);
}

function connectionChecks(job) {
  return objectRecords(job?.connectionCheckResults);
}

function formatCheckErrors(errors) {
  if (Array.isArray(errors)) {
    const messages = errors.filter((item) => typeof item === "string");
    return messages.length ? ` · ${messages.join(", ")}` : "";
  }
  return typeof errors === "string" && errors ? ` · ${errors}` : "";
}

function taskAccount(task) {
  return (
    task.credential_name ||
    task.credential_id ||
    task.payload?.overrides?.transports?.terminal?.ssh?.connection?.auth
      ?.ref_value ||
    task.payload?.overrides?.transports?.windows?.wmi_and_rpc_and_re?.connection
      ?.auth?.ref_value ||
    ""
  );
}

function taskCollectionSummary(task) {
  const included =
    (task.payload?.include?.assets || []).length +
    (task.payload?.include?.assetsGroups || []).length;
  const targetCount = taskTargets(task).length;
  const pieces = [];
  if (targetCount) pieces.push(`${targetCount} целей`);
  if (included) pieces.push(`${included} групп/активов`);
  return pieces.join(" · ") || "—";
}

function StatusBadge({ status, result }) {
  const value = String(status || "unknown");
  const success =
    ["finished", "completed", "valid", "success"].includes(
      value.toLowerCase(),
    ) ||
    ["success", "ok", "succeeded"].includes(String(result || "").toLowerCase());
  const running = ["running", "in_progress", "started", "queued"].includes(
    value.toLowerCase(),
  );
  return (
    <span
      className={`task-status ${success ? "is-success" : running ? "is-running" : ""}`}
    >
      <i aria-hidden="true" />
      {success ? "Завершена" : value === "unknown" ? "Неизвестно" : value}
    </span>
  );
}

function scheduleLabel(trigger = {}) {
  return (
    {
      Daily: "Ежедневно",
      Periodic: "Периодически",
      RepeatableDaily: "Повторять в течение дня",
      Weekly: "Еженедельно",
      Fortnightly: "Раз в две недели",
      Monthly: "Ежемесячно",
      CronScheduler: "Cron",
    }[trigger.type] ||
    trigger.type ||
    "Активно"
  );
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : new Intl.DateTimeFormat("ru-RU", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

function formatDuration(start, finish) {
  if (!start || !finish) return "—";
  const seconds = Math.max(
    0,
    Math.round((new Date(finish).getTime() - new Date(start).getTime()) / 1000),
  );
  return seconds >= 60
    ? `${Math.floor(seconds / 60)} мин ${seconds % 60} с`
    : `${seconds} с`;
}
