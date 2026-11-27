import { messageLabel } from "../../shared/labels.js";
import { useCallback, useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatCount, splitTokens } from "../../shared/format.js";
import { SortableHeader, useTableSort } from "../../shared/table.jsx";
import {
  ActionMenu,
  Button,
  ConfirmDialog,
  Disclosure,
  Field,
  Panel,
  Toggle,
} from "../../shared/ui.jsx";
import { PassportCard, PassportModal } from "./PassportCard.jsx";
import { FreshnessBadge, Severity } from "../../shared/badges.jsx";
import { clampNumber } from "../../shared/values.js";

const ACTIVE_PASSPORT_JOB_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
]);

export function VulnerabilityPassportsPanel({
  defaults,
  busy,
  runBusy,
  showAlert,
  currentUser,
}) {
  const permissions = new Set(currentUser?.permissions || []);
  const canManagePassports = permissions.has("passports.manage");
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    passport_limit: "",
    batch_size: "5000",
    include_nested_groups: true,
    load_details: true,
  });
  const [rows, setRows] = useState([]);
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [queryRaw, setQueryRaw] = useState(null);
  const [passportSearch, setPassportSearch] = useState("");
  const [passportPage, setPassportPage] = useState(1);
  const [passportTotal, setPassportTotal] = useState(0);
  const [passportSourceToken, setPassportSourceToken] = useState(null);
  const [passportJob, setPassportJob] = useState(null);
  const [passportRefreshJob, setPassportRefreshJob] = useState(null);
  const [passportWindowOpen, setPassportWindowOpen] = useState(false);
  const [pendingPassportDelete, setPendingPassportDelete] = useState(null);
  const [passportSort, togglePassportSort] = useTableSort();
  const passportPageSize = 50;

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.vulnerability_passport_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const totalPages = Math.max(1, Math.ceil(passportTotal / passportPageSize));
  const safePage = Math.min(passportPage, totalPages);
  const pageRows = rows;

  const fetchPassportPage = useCallback(
    async (
      page,
      search = passportSearch,
      pdqlToken = passportSourceToken,
      sorting = passportSort,
    ) => {
      const safeRequestedPage = Math.max(1, page);
      const params = new URLSearchParams({
        limit: String(passportPageSize),
        offset: String((safeRequestedPage - 1) * passportPageSize),
      });
      if (search.trim()) params.set("q", search.trim());
      if (pdqlToken) params.set("pdql_token", pdqlToken);
      if (sorting.key) params.set("sort_by", sorting.key);
      if (sorting.key) params.set("sort_dir", sorting.direction);
      const result = await api(
        `/api/vulnerability-passports/local?${params.toString()}`,
      );
      setRows(result.rows || []);
      setPassportTotal(result.total || 0);
      setPassportPage(safeRequestedPage);
      return result;
    },
    [passportSearch, passportSort, passportSourceToken],
  );

  const changePassportSort = (key, initialDirection = "asc") => {
    const next = {
      key,
      direction:
        passportSort.key === key
          ? passportSort.direction === "asc"
            ? "desc"
            : "asc"
          : initialDirection,
    };
    togglePassportSort(key, initialDirection);
    runBusy("passportLocal", () =>
      fetchPassportPage(1, passportSearch, passportSourceToken, next),
    );
  };

  useEffect(() => {
    if (!passportWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setPassportWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [passportWindowOpen]);

  useEffect(() => {
    if (!canManagePassports) return undefined;
    let alive = true;
    api("/api/vulnerability-passports/refresh-jobs/latest")
      .then((result) => {
        if (alive) setPassportRefreshJob(result.job || null);
      })
      .catch((error) => {
        if (alive) showAlert(error.message || String(error), "error");
      });
    return () => {
      alive = false;
    };
  }, [canManagePassports, showAlert]);

  useEffect(() => {
    if (!passportRefreshJob?.operation_id || !ACTIVE_PASSPORT_JOB_STATUSES.has(passportRefreshJob.status))
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const next = await api(`/api/vulnerability-passports/refresh-jobs/${encodeURIComponent(passportRefreshJob.operation_id)}`);
        if (!alive) return;
        setPassportRefreshJob(next);
        if (ACTIVE_PASSPORT_JOB_STATUSES.has(next.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        if (next.status === "completed" || next.status === "completed_with_errors") {
          setPassportJob(next.result?.detail_job || null);
          await fetchPassportPage(1, "", null);
          setPassportSearch("");
          setPassportSourceToken(null);
          showAlert(`Обновление завершено: сохранено ${formatCount(next.result?.db?.saved || 0)} паспортов.${next.status === "completed_with_errors" ? " Тренды не обновлены." : ""}`, next.status === "completed_with_errors" ? "info" : "success");
        } else {
          showAlert(next.message || `Обновление: ${passportJobStatusLabel(next.status)}.`, next.status === "failed" ? "error" : "info");
        }
      } catch {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [passportRefreshJob?.operation_id, passportRefreshJob?.status, fetchPassportPage, showAlert]);

  useEffect(() => {
    if (!canManagePassports) return undefined;
    let alive = true;
    api("/api/vulnerability-passports/detail-jobs/active")
      .then((result) => {
        if (alive && result.job) setPassportJob(result.job);
      })
      .catch((error) => {
        if (alive) showAlert(error.message || String(error), "error");
      });
    return () => {
      alive = false;
    };
  }, [canManagePassports, showAlert]);

  useEffect(() => {
    if (
      !passportJob?.job_id ||
      !ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(
          `/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}`,
        );
        if (!alive) return;
        setPassportJob(nextJob);
        if (ACTIVE_PASSPORT_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        await fetchPassportPage(passportPage, passportSearch);
        const message =
          nextJob.status === "completed"
            ? `Детали паспортов загружены: ${formatCount(nextJob.loaded_count)}.`
            : `Синхронизация завершена со статусом «${passportJobStatusLabel(nextJob.status)}». Загружено: ${formatCount(nextJob.loaded_count)}, ошибок: ${formatCount(nextJob.failed_count)}.`;
        showAlert(message, nextJob.status === "completed" ? "success" : "info");
      } catch {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    fetchPassportPage,
    passportJob?.job_id,
    passportJob?.status,
    passportPage,
    passportSearch,
    showAlert,
  ]);

  const queryPassports = () =>
    runBusy("passportQuery", async () => {
      const requestedLimit = optionalPositiveInteger(
        form.passport_limit,
        "Лимит паспортов",
      );
      const requestedBatchSize = clampNumber(form.batch_size, 5000, 1, 10000);
      const result = await api("/api/vulnerability-passports/query", {
        method: "POST",
        body: JSON.stringify({
          pdql: form.pdql,
          utc_offset: form.utc_offset || null,
          group_ids: splitTokens(form.group_ids),
          asset_ids: splitTokens(form.asset_ids),
          include_nested_groups: form.include_nested_groups,
          limit: requestedLimit,
          batch_size: requestedBatchSize,
          save_to_db: true,
          load_details: form.load_details,
        }),
      });
      const records = result.records || [];
      setRows(records);
      setPassportTotal(result.total || 0);
      setPassportSourceToken(result.pdql_token || null);
      setPassportJob(result.detail_job || null);
      setPassportSearch("");
      setSelected(null);
      setDetail(null);
      setPassportPage(1);
      setPassportWindowOpen(false);
      setQueryRaw(result.raw || null);
      if (records.length) {
        const saved = result.db?.saved;
        const detailJob = result.detail_job;
        const detailsLine = detailJob
          ? `, деталей в очереди: ${formatCount(detailJob.eligible_count)}, свежих в кэше: ${formatCount(detailJob.skipped_fresh_count)}`
          : "";
        const trendSync = result.trend_sync;
        const trendsLine =
          trendSync?.status === "completed"
            ? `, трендовых: ${formatCount(trendSync.total)}`
            : trendSync?.status === "failed"
              ? ", тренды не обновлены"
              : "";
        showAlert(
          `Получено паспортов: ${formatCount(result.total)}${saved == null ? "" : `, сохранено в БД: ${formatCount(saved)}`}${detailsLine}${trendsLine}.`,
          trendSync?.status === "failed" ? "info" : "success",
        );
      } else {
        showAlert(
          "Паспорта не найдены в ответе /assets_grid/data. Raw-ответ показан под таблицей.",
          "info",
        );
      }
    });

  const refreshAllPassports = () =>
    runBusy("passportRefresh", async () => {
      const result = await api("/api/vulnerability-passports/refresh-jobs", { method: "POST" });
      setPassportRefreshJob(result.job);
      showAlert("Обновление паспортов запущено. Прогресс показан под кнопкой.", "info");
    });

  const cancelPassportRefresh = () => {
    if (!passportRefreshJob?.operation_id) return;
    runBusy("passportRefreshCancel", async () => {
      const result = await api(`/api/vulnerability-passports/refresh-jobs/${encodeURIComponent(passportRefreshJob.operation_id)}/cancel`, { method: "POST" });
      setPassportRefreshJob(result);
    });
  };

  const loadLocalPassports = (
    page = 1,
    announce = true,
    pdqlToken = passportSourceToken,
  ) =>
    runBusy("passportLocal", async () => {
      const result = await fetchPassportPage(page, passportSearch, pdqlToken);
      setSelected(null);
      setDetail(null);
      setPassportWindowOpen(false);
      setQueryRaw(null);
      if (announce) {
        showAlert(
          `Загружено из локальной БД: ${formatCount(result.rows?.length || 0)} из ${formatCount(result.total)}.`,
          "success",
        );
      }
    });

  const loadAllLocalPassports = () => {
    setPassportSourceToken(null);
    loadLocalPassports(1, true, null);
  };

  const cancelPassportJob = () => {
    if (!passportJob?.job_id) return;
    runBusy("passportJobCancel", async () => {
      const result = await api(
        `/api/vulnerability-passports/detail-jobs/${encodeURIComponent(passportJob.job_id)}/cancel`,
        {
          method: "POST",
        },
      );
      setPassportJob(result);
      showAlert("Остановка фоновой загрузки запрошена.", "info");
    });
  };

  const openPassport = (row) =>
    runBusy("passportDetail", async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      setSelected(row);
      setPassportWindowOpen(true);
      if (row.raw_detail) {
        setDetail(row.raw_detail);
        return;
      }
      setDetail(null);
      const result = await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
      );
      const nextRow = result.passport || {
        ...row,
        raw_detail: result.raw || null,
        has_detail: Boolean(result.raw),
      };
      setRows((items) =>
        items.map((item) =>
          item.internal_id === row.internal_id ? nextRow : item,
        ),
      );
      setSelected(nextRow);
      setDetail(result.raw || nextRow.raw_detail || {});
    });

  useEffect(() => {
    const passportId =
      typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("passport");
    if (!passportId) return;
    api(`/api/vulnerability-passports/${encodeURIComponent(passportId)}`)
      .then((result) => {
        const row = result.passport || {
          internal_id: passportId,
          raw_detail: result.raw || null,
        };
        setSelected(row);
        setDetail(result.raw || row.raw_detail || {});
        setPassportWindowOpen(true);
      })
      .catch((error) =>
        showAlert(error.operatorMessage || error.message, "error"),
      );
  }, [showAlert]);

  const updatePassport = (row) =>
    runBusy(`passportUpdate:${row.internal_id}`, async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      const result = await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
        {
          method: "PUT",
        },
      );
      const nextRow = result.passport || {
        ...row,
        raw_detail: result.raw || null,
        has_detail: Boolean(result.raw),
      };
      setRows((items) =>
        items.map((item) =>
          item.internal_id === row.internal_id ? nextRow : item,
        ),
      );
      if (selected?.internal_id === row.internal_id) {
        setSelected(nextRow);
        setDetail(result.raw || nextRow.raw_detail || {});
      }
      showAlert(
        `Паспорт ${row.external_id || row.internal_id} обновлён.`,
        "success",
      );
    });

  const deletePassport = (row) => {
    const label = row.external_id || row.name || row.internal_id;
    runBusy(`passportDelete:${row.internal_id}`, async () => {
      if (!row.internal_id)
        throw new Error("У записи нет @VulnerPassport.internalId.");
      await api(
        `/api/vulnerability-passports/${encodeURIComponent(row.internal_id)}`,
        { method: "DELETE" },
      );
      setRows((items) =>
        items.filter((item) => item.internal_id !== row.internal_id),
      );
      setPassportTotal((value) => Math.max(0, value - 1));
      if (selected?.internal_id === row.internal_id) {
        setSelected(null);
        setDetail(null);
        setPassportWindowOpen(false);
      }
      showAlert(`Паспорт ${label} удалён.`, "success");
      setPendingPassportDelete(null);
    });
  };

  const passportJobProgress = passportJob?.eligible_count
    ? Math.min(
        100,
        Math.round(
          (passportJob.processed_count / passportJob.eligible_count) * 100,
        ),
      )
    : 100;
  const passportRefreshActive = Boolean(passportRefreshJob && ACTIVE_PASSPORT_JOB_STATUSES.has(passportRefreshJob.status));
  const passportRefreshPercent = Math.max(0, Math.min(100, Number(passportRefreshJob?.progress_percent || 0)));

  return (
    <Panel id="passports">
      {canManagePassports ? (
        <>
          <Disclosure
            title="Загрузить из MP VM"
            meta={form.load_details ? "С деталями" : null}
          >
            <Field label="PDQL запрос">
              <textarea
                className="code-input"
                rows={6}
                value={form.pdql}
                onChange={(event) => update("pdql", event.target.value)}
              />
            </Field>
            <div className="form-grid form-grid--four">
              <Field label="Часовой пояс">
                <input
                  value={form.utc_offset}
                  onChange={(event) => update("utc_offset", event.target.value)}
                />
              </Field>
              <Field label="Группы">
                <input
                  value={form.group_ids}
                  onChange={(event) => update("group_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Активы">
                <input
                  value={form.asset_ids}
                  onChange={(event) => update("asset_ids", event.target.value)}
                  placeholder="ID через запятую"
                />
              </Field>
              <Field label="Сколько загрузить">
                <input
                  value={form.passport_limit}
                  onChange={(event) =>
                    update("passport_limit", event.target.value)
                  }
                  type="number"
                  min="1"
                  placeholder="Без лимита"
                />
              </Field>
              <Field label="Размер пачки">
                <input
                  value={form.batch_size}
                  onChange={(event) => update("batch_size", event.target.value)}
                  type="number"
                  min="1"
                  max="10000"
                />
              </Field>
              <Toggle
                label="Включая вложенные группы"
                checked={form.include_nested_groups}
                onChange={(value) => update("include_nested_groups", value)}
              />
              <Toggle
                label="Сразу загрузить детали"
                checked={form.load_details}
                onChange={(value) => update("load_details", value)}
              />
            </div>
          </Disclosure>
        </>
      ) : null}
      <div className="action-row">
        {canManagePassports ? (
          <>
            <Button
              busy={busy.passportRefresh}
              disabled={passportRefreshActive || ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob?.status)}
              onClick={refreshAllPassports}
            >
              Обновить
            </Button>
            <Button busy={busy.passportQuery} disabled={passportRefreshActive} onClick={queryPassports}>
              Выполнить PDQL
            </Button>
          </>
        ) : null}
        <Button
          variant="secondary"
          busy={busy.passportLocal}
          onClick={loadAllLocalPassports}
        >
          Сохранённые
        </Button>
        <div className="inline-metric">
          На странице: <span>{formatCount(rows.length)}</span> · всего:{" "}
          <span>{formatCount(passportTotal)}</span>
        </div>
      </div>
      {canManagePassports && passportRefreshJob && passportRefreshJob.status !== "completed" ? (
        <section className={`passport-job passport-job--${passportRefreshJob.status}`} aria-live="polite">
          <div className="passport-job__header">
            <div>
              <strong>Обновление списка паспортов: {passportJobStatusLabel(passportRefreshJob.status)}</strong>
              <span>{passportRefreshPercent}% · {messageLabel(passportRefreshJob.message)}</span>
            </div>
            {passportRefreshActive ? (
              <Button variant="tiny-danger" busy={busy.passportRefreshCancel} disabled={passportRefreshJob.status === "cancelling"} onClick={cancelPassportRefresh}>
                Остановить
              </Button>
            ) : null}
          </div>
          <div className="passport-job__track" role="progressbar" aria-label="Обновление списка паспортов" aria-valuemin="0" aria-valuemax="100" aria-valuenow={passportRefreshPercent}>
            <span style={{ width: `${passportRefreshPercent}%` }} />
          </div>
        </section>
      ) : null}
      {canManagePassports && passportJob && passportJob.status !== "completed" ? (
        <section
          className={`passport-job passport-job--${passportJob.status}`}
          aria-live="polite"
        >
          <div className="passport-job__header">
            <div>
              <strong>
                Фоновая загрузка деталей:{" "}
                {passportJobStatusLabel(passportJob.status)}
              </strong>
              <span>
                Обработано {formatCount(passportJob.processed_count)} из{" "}
                {formatCount(passportJob.eligible_count)} · загружено{" "}
                {formatCount(passportJob.loaded_count)} · ошибок{" "}
                {formatCount(passportJob.failed_count)} · свежих в кэше{" "}
                {formatCount(passportJob.skipped_fresh_count)}
              </span>
            </div>
            {ACTIVE_PASSPORT_JOB_STATUSES.has(passportJob.status) ? (
              <Button
                variant="tiny-danger"
                busy={busy.passportJobCancel}
                onClick={cancelPassportJob}
              >
                Остановить
              </Button>
            ) : null}
          </div>
          <div
            className="passport-job__track"
            role="progressbar"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={passportJobProgress}
          >
            <span style={{ width: `${passportJobProgress}%` }} />
          </div>
          {passportJob.message ? <small>{messageLabel(passportJob.message)}</small> : null}
        </section>
      ) : null}
      <div className="passport-controls">
        <input
          value={passportSearch}
          onChange={(event) => setPassportSearch(event.target.value)}
          onKeyDown={(event) =>
            event.key === "Enter" && loadLocalPassports(1, false)
          }
          placeholder="CVE, название или пакет"
        />
        <Button
          variant="secondary"
          busy={busy.passportLocal}
          onClick={() => loadLocalPassports(1, false)}
        >
          Найти
        </Button>
        <select
          value={safePage}
          onChange={(event) =>
            loadLocalPassports(Number(event.target.value), false)
          }
          disabled={totalPages <= 1}
        >
          {Array.from({ length: totalPages }, (_, index) => (
            <option value={index + 1} key={index + 1}>
              Страница {index + 1} / {totalPages}
            </option>
          ))}
        </select>
      </div>
      <div className="table-shell passport-table-shell">
        <table className="passport-table">
          <thead>
            <tr>
              <SortableHeader
                column="score"
                sort={passportSort}
                onSort={changePassportSort}
                initialDirection="desc"
              >
                Оценка
              </SortableHeader>
              <SortableHeader
                column="name"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Название
              </SortableHeader>
              <SortableHeader
                column="severity"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Критичность
              </SortableHeader>
              <SortableHeader
                column="package"
                sort={passportSort}
                onSort={changePassportSort}
              >
                Пакет
              </SortableHeader>
              <SortableHeader
                column="detail_updated_at"
                sort={passportSort}
                onSort={changePassportSort}
                initialDirection="desc"
              >
                Детали
              </SortableHeader>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {pageRows.length ? (
              pageRows.map((row, rowIndex) => (
                <tr
                  key={
                    row.internal_id ||
                    row.external_id ||
                    `${row.name}-${rowIndex}`
                  }
                  className={
                    selected?.internal_id === row.internal_id
                      ? "is-selected"
                      : ""
                  }
                >
                  <td>
                    <span className="score-badge">{row.score || "—"}</span>
                  </td>
                  <td className="wide-cell">
                    <strong>
                      {row.name || row.external_id || "Без названия"}
                    </strong>
                    <span>{row.external_id}</span>
                    <small className="table-cell-meta">
                      {(row.cves || [])
                        .map((item) => item.display_name)
                        .filter(Boolean)
                        .join(", ") || "CVE не указан"}
                    </small>
                    {row.short_description ? (
                      <details className="table-row-details">
                        <summary>Описание</summary>
                        <p>{row.short_description}</p>
                      </details>
                    ) : null}
                  </td>
                  <td>
                    <Severity value={row.severity} />
                  </td>
                  <td>
                    {[row.package_id, row.package_version]
                      .filter(Boolean)
                      .join(" / ") || "—"}
                  </td>
                  <td>
                    {row.has_detail || row.raw_detail ? (
                      <FreshnessBadge
                        value={row.detail_updated_at || row.last_seen}
                      />
                    ) : (
                      "нет"
                    )}
                  </td>
                  <td>
                    <div className="row-actions">
                      <Button
                        variant="tiny"
                        busy={
                          busy.passportDetail &&
                          selected?.internal_id === row.internal_id
                        }
                        onClick={() => openPassport(row)}
                      >
                        Открыть
                      </Button>
                      {canManagePassports ? (
                        <ActionMenu label="Ещё">
                          <Button
                            variant="tiny"
                            busy={busy[`passportUpdate:${row.internal_id}`]}
                            onClick={() => updatePassport(row)}
                          >
                            Обновить
                          </Button>
                          <Button
                            variant="tiny-danger"
                            busy={busy[`passportDelete:${row.internal_id}`]}
                            onClick={() => setPendingPassportDelete(row)}
                          >
                            Удалить
                          </Button>
                        </ActionMenu>
                      ) : null}
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} className="empty-cell">
                  {passportTotal
                    ? "На этой странице нет записей."
                    : "Нажмите «Сохранённые», чтобы показать паспорта."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {passportTotal ? (
        <div className="passport-pagination">
          <span>
            Страница {formatCount(safePage)} из {formatCount(totalPages)} ·
            показано {formatCount(pageRows.length)} из{" "}
            {formatCount(passportTotal)}
          </span>
          <div>
            <Button
              variant="tiny"
              disabled={safePage <= 1 || busy.passportLocal}
              onClick={() => loadLocalPassports(safePage - 1, false)}
            >
              Назад
            </Button>
            <Button
              variant="tiny"
              disabled={safePage >= totalPages || busy.passportLocal}
              onClick={() => loadLocalPassports(safePage + 1, false)}
            >
              Вперёд
            </Button>
          </div>
        </div>
      ) : null}
      {canManagePassports && queryRaw && !rows.length ? (
        <details className="raw-details">
          <summary>Raw-ответ PDQL запроса</summary>
          <pre>{JSON.stringify(queryRaw, null, 2)}</pre>
        </details>
      ) : null}
      {passportWindowOpen ? (
        <PassportModal
          title="Карточка паспорта уязвимости"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Закрыть"
          onClose={() => setPassportWindowOpen(false)}
        >
          <PassportCard
            row={selected}
            detail={detail}
            loading={busy.passportDetail && !detail}
          />
        </PassportModal>
      ) : null}
      <ConfirmDialog
        open={Boolean(pendingPassportDelete)}
        title="Удалить локальный паспорт?"
        description={`Паспорт «${pendingPassportDelete?.external_id || pendingPassportDelete?.name || pendingPassportDelete?.internal_id || ""}» будет удалён только из PostgreSQL.`}
        impact={[
          "Паспорт в MP VM не изменится",
          "Данные можно повторно загрузить через PDQL",
        ]}
        confirmLabel="Удалить из БД"
        busy={Boolean(
          pendingPassportDelete &&
          busy[`passportDelete:${pendingPassportDelete.internal_id}`],
        )}
        onClose={() => setPendingPassportDelete(null)}
        onConfirm={() => deletePassport(pendingPassportDelete)}
      />
    </Panel>
  );
}

function optionalPositiveInteger(value, label) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const parsed = Number(text);
  if (!Number.isFinite(parsed) || parsed < 1) {
    throw new Error(`${label} должен быть целым числом больше нуля.`);
  }
  return Math.floor(parsed);
}

function passportJobStatusLabel(status) {
  return (
    {
      queued: "в очереди",
      running: "выполняется",
      cancelling: "останавливается",
      cancelled: "остановлена",
      completed: "завершена",
      completed_with_errors: "завершена с ошибками",
      failed: "ошибка",
      interrupted: "прервана перезапуском",
    }[status] ||
    status ||
    "неизвестно"
  );
}
