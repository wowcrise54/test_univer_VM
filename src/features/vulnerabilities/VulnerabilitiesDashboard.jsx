import { useEffect, useRef, useState } from "react";
import { api } from "../../api/client.js";
import { PassportCard, PassportModal } from "../../panels.jsx";
import { formatCount } from "../../shared/format.js";
import { nextTableSort, SortableHeader } from "../../shared/table.jsx";
import { Button, Field, Panel } from "../../shared/ui.jsx";
import {
  useVulnerabilityDashboard,
  VULNERABILITY_PAGE_SIZE,
} from "./useVulnerabilityDashboard.js";

const EMPTY_FILTERS = { q: "", host_q: "", severity: "", source: "" };
const DEFAULT_VULNERABILITY_SORT = {
  key: "affected_hosts",
  direction: "desc",
};
const DEFAULT_HOST_SORT = { key: "severity", direction: "asc" };
const TREND_PERIODS = [7, 30, 90];
const RESOLUTION_PERIODS = [7, 30, 90];
const TREND_METRICS = [
  { key: "affected_hosts", label: "Затронутые хосты" },
  { key: "findings", label: "Findings" },
  { key: "unique_vulnerabilities", label: "Уникальные уязвимости" },
  { key: "high_risk_hosts", label: "Хосты высокого риска" },
];
const TREND_SEVERITIES = ["critical", "high", "medium", "low", "unknown"];

const SEVERITY_LABELS = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  none: "Не указана",
  empty: "Не указана",
  unknown: "Не указана",
  unrated: "Не указана",
};

const SOURCE_LABELS = {
  all: "Все источники",
  asset_cards: "Карточки активов",
  os: "Операционная система",
  software: "Установленное ПО",
  docker: "Docker-контейнеры",
};

export function VulnerabilitiesDashboard({
  currentUser,
  showAlert = () => {},
}) {
  const permissions = new Set(currentUser?.permissions || []);
  const canReadRemediation = permissions.has("remediation.read");
  const canManageRemediation =
    permissions.has("assets.read") &&
    canReadRemediation &&
    permissions.has("remediation.manage");
  const [workspace, setWorkspace] = useState("current");
  const [draftFilters, setDraftFilters] = useState(EMPTY_FILTERS);
  const [filters, setFilters] = useState(EMPTY_FILTERS);
  const [trendDays, setTrendDays] = useState(30);
  const [vulnerabilityOffset, setVulnerabilityOffset] = useState(0);
  const [vulnerabilitySort, setVulnerabilitySort] = useState(
    DEFAULT_VULNERABILITY_SORT,
  );
  const [selected, setSelected] = useState(null);
  const [hostOffset, setHostOffset] = useState(0);
  const [hostSort, setHostSort] = useState(DEFAULT_HOST_SORT);
  const [passport, setPassport] = useState(null);
  const [passportDetail, setPassportDetail] = useState(null);
  const [passportLoading, setPassportLoading] = useState(false);
  const [passportError, setPassportError] = useState(null);
  const [hostFinding, setHostFinding] = useState(null);
  const [remediationBusyAssetId, setRemediationBusyAssetId] = useState(null);
  const [resolutionDays, setResolutionDays] = useState(30);
  const hostHeadingRef = useRef(null);
  const drilldownTriggerRef = useRef(null);
  const restoreDrilldownFocusRef = useRef(false);
  const {
    trendsQuery,
    trendingPassportsQuery,
    summaryQuery,
    vulnerabilitiesQuery,
    hostsQuery,
    resolutionQuery,
  } = useVulnerabilityDashboard({
    filters,
    trendDays,
    vulnerabilityOffset,
    vulnerabilitySort,
    selectedSelector: selected?.selector || "",
    hostOffset,
    hostSort,
    resolutionDays,
    resolutionEnabled: workspace === "resolved",
  });

  useEffect(() => {
    if (selected?.selector) hostHeadingRef.current?.focus();
  }, [selected?.selector]);

  useEffect(() => {
    if (selected || !restoreDrilldownFocusRef.current) return;
    restoreDrilldownFocusRef.current = false;
    drilldownTriggerRef.current?.focus();
  }, [selected]);

  useEffect(() => {
    if (!canReadRemediation && workspace === "resolved") {
      setWorkspace("current");
    }
  }, [canReadRemediation, workspace]);

  const resetResultState = () => {
    setVulnerabilityOffset(0);
    setSelected(null);
    setHostOffset(0);
    setHostSort(DEFAULT_HOST_SORT);
  };

  const applyFilters = (nextFilters) => {
    const normalized = {
      q: String(nextFilters.q || "").trim(),
      host_q: String(nextFilters.host_q || "").trim(),
      severity: nextFilters.severity || "",
      source: nextFilters.source || "",
    };
    setDraftFilters(normalized);
    setFilters(normalized);
    resetResultState();
  };

  const submitFilters = (event) => {
    event.preventDefault();
    applyFilters(draftFilters);
  };

  const selectVulnerability = (row, trigger) => {
    if (!row?.selector) return;
    drilldownTriggerRef.current = trigger || null;
    setSelected(row);
    setHostOffset(0);
    setHostSort(DEFAULT_HOST_SORT);
  };

  const changeVulnerabilitySort = (key, initialDirection = "asc") => {
    setVulnerabilitySort((current) =>
      nextTableSort(current, key, initialDirection),
    );
    setVulnerabilityOffset(0);
  };

  const changeHostSort = (key, initialDirection = "asc") => {
    setHostSort((current) => nextTableSort(current, key, initialDirection));
    setHostOffset(0);
  };

  const refresh = () => {
    if (workspace === "resolved") {
      resolutionQuery.refetch();
      return;
    }
    trendsQuery.refetch();
    trendingPassportsQuery.refetch();
    summaryQuery.refetch();
    vulnerabilitiesQuery.refetch();
    if (selected?.selector) hostsQuery.refetch();
  };

  const closeDrilldown = () => {
    restoreDrilldownFocusRef.current = true;
    setSelected(null);
  };

  const openPassport = async (row) => {
    const mappedPassport =
      row?.passport || row?.passports?.[0] || (row?.internal_id ? row : null);
    if (!mappedPassport?.internal_id) {
      return;
    }
    setPassport(mappedPassport);
    setPassportDetail(mappedPassport.raw_detail || null);
    setPassportError(null);
    setPassportLoading(true);
    try {
      const result = await api(
        `/api/vulnerability-passports/${encodeURIComponent(mappedPassport.internal_id)}`,
      );
      setPassport(result.passport || mappedPassport);
      setPassportDetail(result.raw || result.passport?.raw_detail || {});
    } catch (error) {
      setPassportError(error);
    } finally {
      setPassportLoading(false);
    }
  };

  const closePassport = () => {
    setPassport(null);
    setPassportDetail(null);
    setPassportError(null);
  };

  const startRemediation = async (row) => {
    if (!row?.asset_id || !selected?.selector) return;
    const resumesException = ["risk_accepted", "false_positive"].includes(
      row.remediation?.status,
    );
    if (
      resumesException &&
      !window.confirm(
        "Для этой находки действует исключение. Снять его и возобновить устранение?",
      )
    ) {
      return;
    }
    setRemediationBusyAssetId(row.asset_id);
    try {
      const remediation = await api("/api/remediation/cases/start", {
        method: "POST",
        body: JSON.stringify({
          asset_id: row.asset_id,
          vulnerability_selector: selected.selector,
          comment: "Задача запущена из вкладки «Уязвимости».",
          resume_exception: resumesException,
        }),
      });
      const nextRow = { ...row, remediation };
      setHostFinding((current) =>
        current?.asset_id === row.asset_id ? nextRow : current,
      );
      showAlert(
        `Задача на устранение запущена для ${hostLabel(row)}.`,
        "success",
      );
      await hostsQuery.refetch();
    } catch (error) {
      showAlert(
        error.operatorMessage || error.message || String(error),
        "error",
      );
    } finally {
      setRemediationBusyAssetId(null);
    }
  };

  const summary = summaryQuery.data || {};
  const vulnerabilityRows = resultRows(vulnerabilitiesQuery.data);
  const vulnerabilityTotal = resultTotal(
    vulnerabilitiesQuery.data,
    vulnerabilityRows,
  );
  const hostRows = resultRows(hostsQuery.data);
  const hostTotal = resultTotal(hostsQuery.data, hostRows);
  const refreshing =
    trendsQuery.isFetching ||
    trendingPassportsQuery.isFetching ||
    summaryQuery.isFetching ||
    vulnerabilitiesQuery.isFetching ||
    hostsQuery.isFetching ||
    resolutionQuery.isFetching;

  return (
    <Panel
      id="vulnerabilities"
      eyebrow="08"
      title="Общий обзор уязвимостей"
      description="Оцените масштаб риска, найдите наиболее распространённые уязвимости и откройте список затронутых хостов. Все показатели строятся по локальным данным."
      className="vulnerability-dashboard"
      action={
        <Button variant="secondary" busy={refreshing} onClick={refresh}>
          Перечитать срез
        </Button>
      }
    >
      <VulnerabilityWorkspaceTabs
        value={workspace}
        canReadRemediation={canReadRemediation}
        onChange={(value) => {
          setWorkspace(value);
          setHostFinding(null);
        }}
      />

      {workspace === "resolved" ? (
        <ResolutionStats
          query={resolutionQuery}
          periodDays={resolutionDays}
          onPeriodChange={setResolutionDays}
        />
      ) : (
        <>
          <VulnerabilityFilters
            filters={draftFilters}
            onChange={setDraftFilters}
            onSubmit={submitFilters}
            onReset={() => applyFilters(EMPTY_FILTERS)}
            busy={refreshing}
          />

          <MetricGlossary />

          {summaryQuery.isPending ? (
            <LoadingState label="Загружаю сводку по уязвимостям…" />
          ) : summaryQuery.isError ? (
            <QueryError
              title="Не удалось загрузить сводку"
              error={summaryQuery.error}
              retryLabel="Повторить загрузку сводки"
              onRetry={summaryQuery.refetch}
            />
          ) : (
            <>
              <DashboardContext summary={summary} />
              {summary.coverage?.complete === false ? (
                <div className="vulnerability-coverage-warning" role="note">
                  <strong>Показатели неполные.</strong>
                  <span>
                    Найдены усечённые группы: значения ниже являются нижней
                    оценкой текущего риска.
                  </span>
                </div>
              ) : null}
              <KpiGrid totals={summary.totals || {}} />
              <div className="vulnerability-insights-grid">
                <SeverityBreakdown
                  rows={summary.by_severity || []}
                  selectedSeverity={filters.severity}
                  onSelect={(severity) =>
                    applyFilters({
                      ...filters,
                      severity: filterSeverity(severity),
                    })
                  }
                />
                <TopVulnerabilities
                  rows={summary.top_vulnerabilities || []}
                  selectedSelector={selected?.selector}
                  onSelect={selectVulnerability}
                />
                <TopHosts rows={summary.top_hosts || []} />
              </div>
            </>
          )}

          <TrendingVulnerabilities
            query={trendingPassportsQuery}
            onOpenPassport={openPassport}
          />

          <VulnerabilityTable
            rows={vulnerabilityRows}
            total={vulnerabilityTotal}
            offset={vulnerabilityOffset}
            sort={vulnerabilitySort}
            selectedSelector={selected?.selector}
            pending={vulnerabilitiesQuery.isPending}
            fetching={vulnerabilitiesQuery.isFetching}
            error={vulnerabilitiesQuery.error}
            onRetry={vulnerabilitiesQuery.refetch}
            onSort={changeVulnerabilitySort}
            onSelect={selectVulnerability}
            onOpenPassport={openPassport}
            onPage={setVulnerabilityOffset}
          />

          {selected?.selector ? (
            <HostDrilldown
              selected={selected}
              rows={hostRows}
              total={hostTotal}
              offset={hostOffset}
              sort={hostSort}
              pending={hostsQuery.isPending}
              fetching={hostsQuery.isFetching}
              error={hostsQuery.error}
              headingRef={hostHeadingRef}
              canReadRemediation={canReadRemediation}
              canManageRemediation={canManageRemediation}
              remediationBusyAssetId={remediationBusyAssetId}
              onRetry={hostsQuery.refetch}
              onSort={changeHostSort}
              onPage={setHostOffset}
              onClose={closeDrilldown}
              onOpenPassport={openPassport}
              onOpenFinding={setHostFinding}
              onStartRemediation={startRemediation}
            />
          ) : null}
          <RiskTrendSection
            query={trendsQuery}
            periodDays={trendDays}
            onPeriodChange={setTrendDays}
          />
          {hostFinding ? (
            <HostFindingModal
              selected={selected}
              row={hostFinding}
              canReadRemediation={canReadRemediation}
              canManageRemediation={canManageRemediation}
              busy={remediationBusyAssetId === hostFinding.asset_id}
              onStartRemediation={startRemediation}
              onClose={() => setHostFinding(null)}
            />
          ) : null}
          {passport ? (
            <PassportModal
              title="Паспорт уязвимости"
              className="asset-modal"
              overlayClassName="asset-modal-overlay"
              closeLabel="Назад"
              onClose={closePassport}
            >
              {passportError ? (
                <div className="passport-load-error" role="alert">
                  <strong>Не удалось открыть паспорт.</strong>
                  <span>{passportError.message}</span>
                </div>
              ) : null}
              <PassportCard
                row={passport}
                detail={passportDetail}
                loading={passportLoading}
              />
            </PassportModal>
          ) : null}
        </>
      )}
    </Panel>
  );
}

function VulnerabilityWorkspaceTabs({ value, canReadRemediation, onChange }) {
  return (
    <nav
      className="vulnerability-workspace-tabs"
      aria-label="Разделы уязвимостей"
    >
      <button
        type="button"
        className={value === "current" ? "is-active" : ""}
        aria-current={value === "current" ? "page" : undefined}
        onClick={() => onChange("current")}
      >
        Текущие уязвимости
      </button>
      {canReadRemediation ? (
        <button
          type="button"
          className={value === "resolved" ? "is-active" : ""}
          aria-current={value === "resolved" ? "page" : undefined}
          onClick={() => onChange("resolved")}
        >
          Статистика устранений
        </button>
      ) : null}
    </nav>
  );
}

function ResolutionStats({ query, periodDays, onPeriodChange }) {
  const data = query.data || {};
  const severityRows = data.by_severity || [];
  const trend = data.trend || [];
  const recent = data.recent || [];
  const maximumSeverity = Math.max(
    0,
    ...severityRows.map((row) =>
      Number(row.confirmed_resolutions ?? row.resolved_cases ?? 0),
    ),
  );
  const maximumTrend = Math.max(
    0,
    ...trend.map((row) =>
      Number(row.confirmed_resolutions ?? row.resolved_cases ?? 0),
    ),
  );

  return (
    <section
      className="resolution-stats"
      aria-labelledby="resolution-stats-title"
    >
      <header className="resolution-stats__header">
        <div>
          <span className="vulnerability-section-heading__eyebrow">
            Отдельный срез
          </span>
          <h3 id="resolution-stats-title">Подтверждённые устранения</h3>
          <p>
            Устранение учитывается только после полного свежего сканирования, в
            котором находка больше не обнаружена.
          </p>
        </div>
        <div
          className="risk-trend__periods"
          role="group"
          aria-label="Период статистики устранений"
        >
          {RESOLUTION_PERIODS.map((days) => (
            <button
              type="button"
              className={periodDays === days ? "is-active" : ""}
              aria-pressed={periodDays === days}
              onClick={() => onPeriodChange(days)}
              key={days}
            >
              {days} дней
            </button>
          ))}
        </div>
      </header>

      {query.isPending ? (
        <LoadingState label="Загружаю статистику устранений…" />
      ) : query.isError ? (
        <QueryError
          title="Не удалось загрузить статистику устранений"
          error={query.error}
          retryLabel="Повторить загрузку статистики"
          onRetry={query.refetch}
        />
      ) : (
        <>
          <div
            className="resolution-kpi-grid"
            aria-label="Показатели устранения"
          >
            <ResolutionMetric
              label="Подтверждений"
              value={data.confirmed_resolutions ?? data.resolved_cases}
              note={`за ${formatCount(data.period_days || periodDays)} дней`}
            />
            <ResolutionMetric
              label="Уязвимостей"
              value={data.resolved_vulnerabilities}
              note="уникальных типов"
            />
            <ResolutionMetric
              label="Хостов"
              value={data.resolved_hosts}
              note="с подтверждённым устранением"
            />
            <ResolutionMetric
              label="Остаются устранёнными"
              value={data.currently_resolved ?? data.resolved_cases}
              note="из подтверждений выбранного периода"
            />
            <ResolutionMetric
              label="Средний срок"
              value={
                data.mean_time_to_resolve_days == null
                  ? "—"
                  : `${formatScore(data.mean_time_to_resolve_days)} дн.`
              }
              note="от первого обнаружения"
            />
          </div>

          <div className="resolution-stats__grid">
            <article className="resolution-card">
              <header>
                <h4>По критичности</h4>
                <p>Количество подтверждений за выбранный период</p>
              </header>
              {severityRows.length ? (
                <div className="resolution-severity-list">
                  {severityRows.map((row) => {
                    const value = Number(
                      row.confirmed_resolutions ?? row.resolved_cases ?? 0,
                    );
                    return (
                      <div
                        className="resolution-severity-row"
                        key={row.severity}
                      >
                        <div>
                          <SeverityBadge value={row.severity} />
                          <strong>{formatCount(value)}</strong>
                        </div>
                        <span aria-hidden="true">
                          <i
                            style={{
                              "--bar-width": `${barWidth(value, maximumSeverity)}%`,
                            }}
                          />
                        </span>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <EmptyState>За этот период устранений нет.</EmptyState>
              )}
            </article>

            <article className="resolution-card">
              <header>
                <h4>Динамика подтверждений</h4>
                <p>По дням завершившихся проверочных сканирований</p>
              </header>
              {trend.length ? (
                <div
                  className="resolution-trend"
                  role="list"
                  aria-label="Динамика подтверждённых устранений по дням"
                >
                  {trend.map((row) => {
                    const value =
                      row.confirmed_resolutions ?? row.resolved_cases;
                    return (
                      <div
                        className="resolution-trend__point"
                        role="listitem"
                        aria-label={`${formatTrendDate(
                          row.bucket_start,
                        )}: ${formatCount(value)} подтверждений`}
                        key={row.bucket_start}
                      >
                        <span
                          style={{
                            "--bar-height": `${barWidth(value, maximumTrend)}%`,
                          }}
                          title={`${formatTrendDate(row.bucket_start)}: ${formatCount(
                            value,
                          )}`}
                        >
                          <i />
                        </span>
                        <strong>{formatCount(value)}</strong>
                        <small>{formatTrendDate(row.bucket_start)}</small>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <EmptyState>Динамика за выбранный период пуста.</EmptyState>
              )}
            </article>
          </div>

          <section
            className="resolution-recent"
            aria-labelledby="resolution-recent-title"
          >
            <div className="vulnerability-section-heading">
              <div>
                <h3 id="resolution-recent-title">
                  Последние подтверждения устранения
                </h3>
                <p>
                  История сохраняется, даже если находка позднее появилась
                  снова.
                </p>
              </div>
            </div>
            <div className="table-shell">
              <table className="resolution-recent__table">
                <thead>
                  <tr>
                    <th>Уязвимость</th>
                    <th>Хост</th>
                    <th>Критичность</th>
                    <th>Подтверждено</th>
                    <th>Текущий статус</th>
                    <th>Задача</th>
                  </tr>
                </thead>
                <tbody>
                  {recent.length ? (
                    recent.map((row, index) => (
                      <tr
                        key={`${row.case_id}-${row.resolution_confirmed_at || index}`}
                      >
                        <td>
                          <strong>
                            {row.resolution_cve ||
                              row.cve ||
                              row.resolution_title ||
                              row.title ||
                              row.vulnerability_key}
                          </strong>
                          {(row.resolution_cve || row.cve) &&
                          (row.resolution_title || row.title) ? (
                            <small>{row.resolution_title || row.title}</small>
                          ) : null}
                        </td>
                        <td>
                          <strong>{hostLabel(row)}</strong>
                          <small>
                            {row.ip_address || row.fqdn || row.asset_id}
                          </small>
                        </td>
                        <td>
                          <SeverityBadge
                            value={row.resolution_severity || row.severity}
                          />
                        </td>
                        <td>
                          {formatDate(
                            row.resolution_confirmed_at || row.resolved_at,
                          )}
                        </td>
                        <td>
                          <RemediationStatus status={row.status} />
                        </td>
                        <td>
                          <a
                            className="button tiny"
                            aria-label={`Открыть задачу ${row.resolution_cve || row.cve || row.title || row.case_id} на хосте ${hostLabel(row)}`}
                            href={`/remediation?case=${encodeURIComponent(
                              row.case_id,
                            )}`}
                          >
                            Открыть
                          </a>
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} className="empty-cell">
                        За выбранный период подтверждённых устранений нет.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </>
      )}
    </section>
  );
}

function ResolutionMetric({ label, value, note }) {
  return (
    <article className="resolution-metric">
      <span>{label}</span>
      <strong>
        {typeof value === "number" ? formatCount(value) : (value ?? "—")}
      </strong>
      <small>{note}</small>
    </article>
  );
}

function VulnerabilityFilters({ filters, onChange, onSubmit, onReset, busy }) {
  const update = (key, value) =>
    onChange((current) => ({ ...current, [key]: value }));
  return (
    <form
      className="vulnerability-filters"
      aria-label="Фильтры дашборда уязвимостей"
      onSubmit={onSubmit}
    >
      <Field label="Уязвимость">
        <input
          value={filters.q}
          onChange={(event) => update("q", event.target.value)}
          placeholder="Название, CVE или идентификатор"
        />
      </Field>
      <Field label="Хост">
        <input
          value={filters.host_q}
          onChange={(event) => update("host_q", event.target.value)}
          placeholder="Имя, IP или FQDN"
        />
      </Field>
      <Field label="Критичность">
        <select
          value={filters.severity}
          onChange={(event) => update("severity", event.target.value)}
        >
          <option value="">Любая</option>
          <option value="critical">Критическая</option>
          <option value="high">Высокая</option>
          <option value="medium">Средняя</option>
          <option value="low">Низкая</option>
          <option value="none">Не указана</option>
        </select>
      </Field>
      <Field label="Источник">
        <select
          value={filters.source}
          onChange={(event) => update("source", event.target.value)}
        >
          <option value="">Все источники</option>
          <option value="os">Операционная система</option>
          <option value="software">Установленное ПО</option>
          <option value="docker">Docker-контейнеры</option>
        </select>
      </Field>
      <div className="vulnerability-filters__actions">
        <Button type="submit" busy={busy}>
          Применить фильтры
        </Button>
        <Button type="button" variant="ghost" disabled={busy} onClick={onReset}>
          Сбросить
        </Button>
      </div>
    </form>
  );
}

function MetricGlossary() {
  return (
    <details className="vulnerability-glossary">
      <summary>Как читать показатели: уязвимости, findings и хосты</summary>
      <div className="vulnerability-glossary__grid">
        <article>
          <strong>Уязвимость</strong>
          <p>
            Уникальный тип проблемы, объединённый по идентификатору, CVE или
            названию. Одна уязвимость может встречаться на многих хостах.
          </p>
        </article>
        <article>
          <strong>Finding</strong>
          <p>
            Конкретное обнаружение уязвимости на хосте и объекте — например, в
            пакете или компоненте. На одном хосте может быть несколько findings
            одной уязвимости.
          </p>
        </article>
        <article>
          <strong>Затронутый хост</strong>
          <p>
            Уникальный актив, где есть хотя бы один finding выбранной
            уязвимости. Поэтому хостов обычно не больше, чем findings.
          </p>
        </article>
        <article>
          <strong>Паспорт</strong>
          <p>
            Справочная карточка с описанием, критичностью, CVSS, CVE и способом
            устранения. Паспорт дополняет finding, но не заменяет список хостов.
          </p>
        </article>
      </div>
    </details>
  );
}

function RiskTrendSection({ query, periodDays, onPeriodChange }) {
  const [metric, setMetric] = useState("affected_hosts");
  const rows = trendRows(query.data);
  const latest = rows.at(-1) || null;
  const previous = rows.length > 1 ? rows.at(-2) : null;
  const incomplete = rows.some((row) => !trendCoverageComplete(row));

  return (
    <section className="risk-trend" aria-labelledby="risk-trend-title">
      <header className="risk-trend__header">
        <div>
          <span className="vulnerability-section-heading__eyebrow">
            История локального среза
          </span>
          <h3 id="risk-trend-title">Динамика риска</h3>
          <p>
            Агрегаты по всем сохранённым карточкам. Фильтры текущего среза ниже
            не изменяют исторический график.
          </p>
        </div>
        <div
          className="risk-trend__periods"
          role="group"
          aria-label="Период истории рисков"
        >
          {TREND_PERIODS.map((days) => (
            <button
              type="button"
              className={periodDays === days ? "is-active" : ""}
              aria-pressed={periodDays === days}
              onClick={() => onPeriodChange(days)}
              key={days}
            >
              {days} дней
            </button>
          ))}
        </div>
      </header>

      {query.isPending ? (
        <LoadingState label="Загружаю историю риска…" />
      ) : query.isError ? (
        <QueryError
          title="Не удалось загрузить историю риска"
          error={query.error}
          retryLabel="Повторить загрузку истории"
          onRetry={query.refetch}
        />
      ) : !rows.length ? (
        <EmptyState>
          История начнёт формироваться после первого успешного обновления
          карточек активов.
        </EmptyState>
      ) : (
        <>
          <TrendDeltaGrid latest={latest} previous={previous} />
          {incomplete ? (
            <div className="risk-trend__warning" role="note">
              Часть исторических точек построена по усечённым данным и отмечена
              как нижняя оценка.
            </div>
          ) : null}
          <div className="risk-trend__content">
            <article className="risk-trend__card risk-trend__chart-card">
              <header>
                <div>
                  <h4>Изменение показателя</h4>
                  <p>
                    {query.data?.bucket === "week"
                      ? "Последняя точка каждой недели"
                      : "Последняя точка каждого дня"}
                  </p>
                </div>
                <label>
                  <span>Показатель</span>
                  <select
                    value={metric}
                    onChange={(event) => setMetric(event.target.value)}
                  >
                    {TREND_METRICS.map((item) => (
                      <option value={item.key} key={item.key}>
                        {item.label}
                      </option>
                    ))}
                  </select>
                </label>
              </header>
              <TrendLineChart rows={rows} metric={metric} />
            </article>
            <SeveritySnapshot point={latest} />
          </div>
          <TrendTable rows={rows} />
        </>
      )}
    </section>
  );
}

function TrendDeltaGrid({ latest, previous }) {
  return (
    <div className="risk-trend__deltas" aria-label="Последние изменения риска">
      {TREND_METRICS.map((item) => {
        const current = trendMetric(latest, item.key);
        const before = previous ? trendMetric(previous, item.key) : null;
        const delta = before === null ? null : current - before;
        const tone = delta > 0 ? "danger" : delta < 0 ? "success" : "neutral";
        return (
          <article
            className={`risk-trend__delta risk-trend__delta--${tone}`}
            key={item.key}
          >
            <span>{item.label}</span>
            <strong>{formatCount(current)}</strong>
            <small>{formatTrendDelta(delta)}</small>
          </article>
        );
      })}
    </div>
  );
}

function TrendLineChart({ rows, metric }) {
  const width = 960;
  const height = 260;
  const left = 58;
  const right = 20;
  const top = 22;
  const bottom = 42;
  const plotWidth = width - left - right;
  const plotHeight = height - top - bottom;
  const values = rows.map((row) => trendMetric(row, metric));
  const maximum = Math.max(1, ...values);
  const points = rows.map((row, index) => {
    const x =
      rows.length === 1
        ? left + plotWidth / 2
        : left + (index / (rows.length - 1)) * plotWidth;
    const y =
      top + plotHeight - (trendMetric(row, metric) / maximum) * plotHeight;
    return { row, x, y, value: trendMetric(row, metric) };
  });
  const metricLabel =
    TREND_METRICS.find((item) => item.key === metric)?.label || metric;

  return (
    <svg
      className="risk-trend__chart"
      viewBox={`0 0 ${width} ${height}`}
      role="img"
      aria-label={`${metricLabel}: ${formatCount(values.at(-1))}, точек: ${rows.length}`}
    >
      {[0, 0.5, 1].map((fraction) => {
        const y = top + plotHeight - fraction * plotHeight;
        return (
          <g key={fraction}>
            <line
              className="risk-trend__grid-line"
              x1={left}
              x2={width - right}
              y1={y}
              y2={y}
            />
            <text
              className="risk-trend__axis-label"
              x={left - 10}
              y={y + 4}
              textAnchor="end"
            >
              {formatCount(Math.round(maximum * fraction))}
            </text>
          </g>
        );
      })}
      <polyline
        className="risk-trend__line"
        points={points.map(({ x, y }) => `${x},${y}`).join(" ")}
      />
      {points.map(({ row, x, y, value }) => (
        <g key={`${row.bucket_start}-${row.snapshot_at}`}>
          <circle
            className={`risk-trend__point ${trendCoverageComplete(row) ? "" : "risk-trend__point--warning"}`}
            cx={x}
            cy={y}
            r="6"
          >
            <title>
              {formatTrendDate(row.bucket_start)}: {formatCount(value)}
              {row.carried_forward ? " · без нового снимка" : ""}
            </title>
          </circle>
        </g>
      ))}
      <text className="risk-trend__axis-label" x={left} y={height - 12}>
        {formatTrendDate(rows[0]?.bucket_start)}
      </text>
      <text
        className="risk-trend__axis-label"
        x={width - right}
        y={height - 12}
        textAnchor="end"
      >
        {formatTrendDate(rows.at(-1)?.bucket_start)}
      </text>
    </svg>
  );
}

function SeveritySnapshot({ point }) {
  const severityRows = TREND_SEVERITIES.map((severity) => ({
    severity,
    ...trendSeverity(point, severity),
  }));
  const total = severityRows.reduce(
    (sum, row) => sum + Number(row.findings || 0),
    0,
  );
  return (
    <article className="risk-trend__card risk-trend__severity-card">
      <header>
        <div>
          <h4>Критичность последнего снимка</h4>
          <p>{formatDate(point?.snapshot_at)}</p>
        </div>
      </header>
      {total ? (
        <>
          <div className="risk-trend__severity-stack" aria-hidden="true">
            {severityRows.map((row) => (
              <span
                className={`risk-trend__severity-segment risk-trend__severity-segment--${severityClass(row.severity)}`}
                style={{
                  width: `${(Number(row.findings || 0) / total) * 100}%`,
                }}
                key={row.severity}
              />
            ))}
          </div>
          <ul className="risk-trend__severity-list">
            {severityRows.map((row) => (
              <li key={row.severity}>
                <span
                  className={`risk-trend__severity-dot risk-trend__severity-dot--${severityClass(row.severity)}`}
                />
                <strong>{severityLabel(row.severity)}</strong>
                <span>{formatCount(row.findings)} findings</span>
                <small>{formatCount(row.affected_hosts)} хостов</small>
              </li>
            ))}
          </ul>
        </>
      ) : (
        <EmptyState>В последнем снимке нет findings.</EmptyState>
      )}
    </article>
  );
}

function TrendTable({ rows }) {
  return (
    <details className="risk-trend__details">
      <summary>Табличные данные истории</summary>
      <div className="table-shell risk-trend__table-shell">
        <table>
          <caption className="vulnerability-sr-only">
            Исторические агрегаты уязвимостей
          </caption>
          <thead>
            <tr>
              <th>Период</th>
              <th>Хосты</th>
              <th>Findings</th>
              <th>Уязвимости</th>
              <th>Critical</th>
              <th>High</th>
              <th>Полнота</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.bucket_start}-${row.snapshot_at}`}>
                <td>
                  <strong>{formatTrendDate(row.bucket_start)}</strong>
                  {row.carried_forward ? (
                    <small>Без нового снимка</small>
                  ) : null}
                </td>
                <td>{formatCount(trendMetric(row, "affected_hosts"))}</td>
                <td>{formatCount(trendMetric(row, "findings"))}</td>
                <td>
                  {formatCount(trendMetric(row, "unique_vulnerabilities"))}
                </td>
                <td>{formatCount(trendSeverity(row, "critical").findings)}</td>
                <td>{formatCount(trendSeverity(row, "high").findings)}</td>
                <td>
                  {trendCoverageComplete(row)
                    ? "Полные данные"
                    : "Нижняя оценка"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

function trendRows(data) {
  return Array.isArray(data?.rows)
    ? [...data.rows].sort((left, right) =>
        String(left.bucket_start || "").localeCompare(
          String(right.bucket_start || ""),
        ),
      )
    : [];
}

function trendMetric(point, key) {
  return Number(point?.totals?.[key] || 0);
}

function trendSeverity(point, severity) {
  const collection = point?.by_severity;
  if (Array.isArray(collection)) {
    return collection.find((item) => item.severity === severity) || {};
  }
  return collection?.[severity] || {};
}

function trendCoverageComplete(point) {
  return point?.coverage?.complete !== false;
}

function formatTrendDelta(delta) {
  if (delta === null) return "Нет предыдущей точки";
  if (!delta) return "Без изменений";
  return `${delta > 0 ? "+" : "−"}${formatCount(Math.abs(delta))} к прошлой точке`;
}

function formatTrendDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleDateString("ru-RU", { day: "2-digit", month: "short" });
}

function DashboardContext({ summary }) {
  const coverage = summary.coverage || {};
  const coveragePercent = coverage.cards_total
    ? Math.round(
        (Number(coverage.cards_with_findings || 0) /
          Number(coverage.cards_total)) *
          100,
      )
    : 0;
  const source = sourceLabel(summary);
  return (
    <section
      className={`vulnerability-context ${coverage.complete === false ? "vulnerability-context--warning" : ""}`}
      aria-label="Источник и покрытие данных"
    >
      <div>
        <span>Источник текущего среза</span>
        <strong>{source}</strong>
      </div>
      <div>
        <span>Карточки с findings</span>
        <strong>
          {formatCount(coverage.cards_with_findings)} из{" "}
          {formatCount(coverage.cards_total)} · {coveragePercent}%
        </strong>
      </div>
      <div>
        <span>Период данных</span>
        <strong>
          {formatDate(coverage.oldest_at)} — {formatDate(coverage.freshest_at)}
        </strong>
      </div>
      <div>
        <span>Полнота</span>
        <strong>
          {coverage.complete === false
            ? `Нижняя оценка · групп: ${formatCount(coverage.truncated_groups)}`
            : "Группы не усечены"}
        </strong>
      </div>
    </section>
  );
}

function KpiGrid({ totals }) {
  const cards = [
    {
      label: "Хосты с уязвимостями",
      value: totals.affected_hosts,
      note: `из ${formatCount(totals.hosts_total)} хостов`,
    },
    { label: "Findings", value: totals.findings, note: "обнаружений" },
    {
      label: "Уникальные уязвимости",
      value: totals.unique_vulnerabilities,
      note: "по выбранным фильтрам",
    },
    {
      label: "Уникальные CVE",
      value: totals.unique_cves,
      note: "идентификаторов",
    },
    {
      label: "Высокий риск",
      value: totals.high_risk_hosts,
      note: "хостов с Critical / High",
      tone: "danger",
    },
    {
      label: "Без оценки",
      value: totals.unrated_vulnerabilities,
      note: "уязвимостей без критичности",
      tone: "muted",
    },
  ];
  return (
    <section
      className="vulnerability-kpi-grid"
      aria-label="Ключевые показатели"
    >
      {cards.map((card) => (
        <article
          className={`vulnerability-kpi ${card.tone ? `vulnerability-kpi--${card.tone}` : ""}`}
          key={card.label}
        >
          <span>{card.label}</span>
          <strong>{formatCount(card.value)}</strong>
          <small>{card.note}</small>
        </article>
      ))}
    </section>
  );
}

function SeverityBreakdown({ rows, selectedSeverity, onSelect }) {
  const maximum = Math.max(0, ...rows.map((row) => Number(row.findings || 0)));
  return (
    <InsightCard
      title="Распределение по критичности"
      description="Количество findings и затронутых хостов"
    >
      {rows.length ? (
        <div className="severity-bars">
          {rows.map((row, index) => {
            const severity = String(row.severity || "none").toLowerCase();
            const width = barWidth(row.findings, maximum);
            return (
              <button
                type="button"
                className={`severity-bar severity-bar--${severityClass(severity)}`}
                style={{ "--bar-width": `${width}%` }}
                aria-pressed={filterSeverity(severity) === selectedSeverity}
                onClick={() => onSelect(severity)}
                key={`${severity}-${index}`}
              >
                <span className="ranking-row__track" aria-hidden="true">
                  <span />
                </span>
                <span className="ranking-row__content">
                  <strong>{severityLabel(severity)}</strong>
                  <span>{formatCount(row.findings)} findings</span>
                  <small>{formatCount(row.affected_hosts)} хостов</small>
                </span>
              </button>
            );
          })}
        </div>
      ) : (
        <EmptyState>Распределение пока недоступно.</EmptyState>
      )}
    </InsightCard>
  );
}

function TopVulnerabilities({ rows, selectedSelector, onSelect }) {
  const maximum = Math.max(
    0,
    ...rows.map((row) => Number(row.affected_hosts || 0)),
  );
  return (
    <InsightCard
      title="Наиболее распространённые"
      description="Выберите уязвимость, чтобы увидеть затронутые хосты"
    >
      {rows.length ? (
        <ol className="vulnerability-ranking">
          {rows.map((row, index) => {
            const label = vulnerabilityLabel(row);
            return (
              <li key={`${row.selector || label}-${index}`}>
                <button
                  type="button"
                  className="ranking-row ranking-row--vulnerability"
                  style={{
                    "--bar-width": `${barWidth(row.affected_hosts, maximum)}%`,
                  }}
                  disabled={!row.selector}
                  aria-pressed={row.selector === selectedSelector}
                  aria-label={`Показать хосты с уязвимостью ${label}`}
                  onClick={(event) => onSelect(row, event.currentTarget)}
                >
                  <span className="ranking-row__track" aria-hidden="true">
                    <span />
                  </span>
                  <span className="ranking-row__content">
                    <strong>{label}</strong>
                    <span>
                      <SeverityBadge value={row.severity} />
                      {row.cve ? <code>{row.cve}</code> : null}
                    </span>
                    <small>
                      {formatCount(row.affected_hosts)} хостов ·{" "}
                      {formatCount(row.findings)} findings
                      {row.passports?.length ? " · есть паспорт" : ""}
                    </small>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      ) : (
        <EmptyState>Уязвимости с такими фильтрами не найдены.</EmptyState>
      )}
    </InsightCard>
  );
}

function TopHosts({ rows }) {
  const maximum = Math.max(
    0,
    ...rows.map((row) => Number(row.findings || row.finding_count || 0)),
  );
  return (
    <InsightCard
      title="Хосты по числу findings"
      description="Рейтинг по количеству findings"
    >
      {rows.length ? (
        <ol className="vulnerability-ranking vulnerability-ranking--hosts">
          {rows.map((row, index) => {
            const findings = row.findings ?? row.finding_count;
            return (
              <li
                className="ranking-row ranking-row--host"
                style={{ "--bar-width": `${barWidth(findings, maximum)}%` }}
                key={`${row.asset_id || hostLabel(row)}-${index}`}
              >
                <span className="ranking-row__track" aria-hidden="true">
                  <span />
                </span>
                <span className="ranking-row__content">
                  <strong>{hostLabel(row)}</strong>
                  <span>{row.ip_address || row.fqdn || "Адрес не указан"}</span>
                  <small>
                    {formatCount(findings)} findings ·{" "}
                    {formatCount(row.unique_vulnerabilities)} уязвимостей
                  </small>
                </span>
              </li>
            );
          })}
        </ol>
      ) : (
        <EmptyState>Данные по хостам пока отсутствуют.</EmptyState>
      )}
    </InsightCard>
  );
}

function InsightCard({ title, description, children }) {
  return (
    <section className="vulnerability-insight-card">
      <header>
        <h3>{title}</h3>
        <p>{description}</p>
      </header>
      {children}
    </section>
  );
}

function TrendingVulnerabilities({ query, onOpenPassport }) {
  const rows = resultRows(query.data);

  return (
    <section
      className="trending-vulnerabilities"
      aria-labelledby="trending-vulnerabilities-title"
    >
      <div className="trending-vulnerabilities__heading">
        <div>
          <h3 id="trending-vulnerabilities-title">Трендовые уязвимости</h3>
          <p>
            Паспорта, отмеченные как трендовые, и число затронутых ими хостов
          </p>
        </div>
        {query.isFetching && !query.isPending ? (
          <span role="status">Обновляю…</span>
        ) : null}
      </div>

      {query.isPending ? (
        <LoadingState label="Загружаю трендовые уязвимости…" />
      ) : query.isError ? (
        <QueryError
          title="Не удалось загрузить трендовые уязвимости"
          error={query.error}
          retryLabel="Повторить загрузку трендовых уязвимостей"
          onRetry={query.refetch}
        />
      ) : rows.length ? (
        <ol className="trending-vulnerabilities__list">
          {rows.map((row, index) => {
            const label =
              row.cve ||
              row.external_id ||
              row.name ||
              row.internal_id ||
              "Без названия";
            const vendors = trendTagValues(row.vendors);
            const components = trendTagValues(row.affected_components);
            return (
              <li
                className={`trending-vulnerability trending-vulnerability--${severityClass(row.severity)}`}
                key={`${row.internal_id || label}-${index}`}
              >
                <span
                  className="trending-vulnerability__marker"
                  aria-hidden="true"
                />
                <div className="trending-vulnerability__content">
                  <div className="trending-vulnerability__identity">
                    <button
                      type="button"
                      disabled={!row.internal_id}
                      aria-label={`Открыть паспорт уязвимости ${label}`}
                      onClick={() => onOpenPassport(row)}
                    >
                      {label}
                    </button>
                    <SeverityBadge value={row.severity} />
                    {row.score !== null &&
                    row.score !== undefined &&
                    row.score !== "" ? (
                      <span className="trending-vulnerability__score">
                        CVSS {formatScore(row.score)}
                      </span>
                    ) : null}
                  </div>
                  {row.name && row.name !== label ? (
                    <strong className="trending-vulnerability__name">
                      {row.name}
                    </strong>
                  ) : null}
                  <p className="trending-vulnerability__description">
                    {row.description || "Описание отсутствует."}
                  </p>
                  <div className="trending-vulnerability__dates">
                    <span>
                      В тренде с{" "}
                      <time dateTime={row.is_trend_since || undefined}>
                        {formatCalendarDate(row.is_trend_since)}
                      </time>
                    </span>
                    <span>
                      Опубликована{" "}
                      <time dateTime={row.issue_time || undefined}>
                        {formatCalendarDate(row.issue_time)}
                      </time>
                    </span>
                  </div>
                  {vendors.length || components.length ? (
                    <div className="trending-vulnerability__tags">
                      {vendors.length ? (
                        <TrendTags label="Поставщик" values={vendors} />
                      ) : null}
                      {components.length ? (
                        <TrendTags
                          label="Уязвимые компоненты"
                          values={components}
                        />
                      ) : null}
                    </div>
                  ) : null}
                </div>
                <div
                  className="trending-vulnerability__hosts"
                  aria-label={`Заражённых хостов: ${formatCount(row.affected_hosts)}`}
                >
                  <strong>{formatCount(row.affected_hosts)}</strong>
                  <span>Заражённых хостов</span>
                </div>
              </li>
            );
          })}
        </ol>
      ) : (
        <EmptyState>Трендовые уязвимости не найдены.</EmptyState>
      )}
    </section>
  );
}

function TrendTags({ label, values }) {
  return (
    <div className="trending-vulnerability__tag-group">
      <strong>{label}:</strong>
      <span>
        {values.map((value) => (
          <span className="trending-vulnerability__tag" key={value}>
            {value}
          </span>
        ))}
      </span>
    </div>
  );
}

function VulnerabilityTable({
  rows,
  total,
  offset,
  sort,
  selectedSelector,
  pending,
  fetching,
  error,
  onRetry,
  onSort,
  onSelect,
  onOpenPassport,
  onPage,
}) {
  return (
    <section
      className="vulnerability-table-section"
      aria-labelledby="vulnerability-table-title"
    >
      <div className="vulnerability-section-heading">
        <div>
          <h3 id="vulnerability-table-title">Все уязвимости</h3>
          <p>Найдено: {formatCount(total)}</p>
        </div>
        {fetching && !pending ? <span role="status">Обновляю…</span> : null}
      </div>
      {error ? (
        <QueryError
          title="Не удалось загрузить список уязвимостей"
          error={error}
          retryLabel="Повторить загрузку списка"
          onRetry={onRetry}
        />
      ) : null}
      <div className="table-shell vulnerability-table-shell">
        <table className="vulnerability-table">
          <caption className="vulnerability-sr-only">
            Уязвимости с количеством затронутых хостов
          </caption>
          <thead>
            <tr>
              <SortableHeader column="name" sort={sort} onSort={onSort}>
                Уязвимость
              </SortableHeader>
              <th>CVE</th>
              <SortableHeader column="severity" sort={sort} onSort={onSort}>
                Критичность
              </SortableHeader>
              <SortableHeader
                column="cvss_score"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Макс. CVSS
              </SortableHeader>
              <SortableHeader
                column="affected_hosts"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Хостов
              </SortableHeader>
              <SortableHeader
                column="findings"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Findings
              </SortableHeader>
              <th>Объекты</th>
              <th>Источники</th>
              <th>Паспорт</th>
              <SortableHeader
                column="last_seen"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Последнее обновление
              </SortableHeader>
            </tr>
          </thead>
          <tbody>
            {pending ? (
              <tr>
                <td colSpan={10} className="empty-cell">
                  Загружаю уязвимости…
                </td>
              </tr>
            ) : rows.length ? (
              rows.map((row, index) => {
                const label = vulnerabilityLabel(row);
                const hasPassport = Boolean(row.passports?.[0]?.internal_id);
                return (
                  <tr
                    className={
                      row.selector === selectedSelector ? "is-selected" : ""
                    }
                    key={`${row.selector || label}-${index}`}
                  >
                    <td>
                      <button
                        type="button"
                        className="vulnerability-row-button"
                        disabled={!row.selector}
                        aria-pressed={row.selector === selectedSelector}
                        aria-label={`Показать хосты с уязвимостью ${label}`}
                        title="Показать затронутые хосты"
                        onClick={(event) => onSelect(row, event.currentTarget)}
                      >
                        {label}
                      </button>
                      {row.vulnerability_id ? (
                        <code>{row.vulnerability_id}</code>
                      ) : null}
                    </td>
                    <td>{row.cve || "—"}</td>
                    <td>
                      <SeverityBadge value={row.severity} />
                    </td>
                    <td>{formatScore(row.max_cvss ?? row.cvss_score)}</td>
                    <td>{formatCount(row.affected_hosts)}</td>
                    <td>{formatCount(row.findings)}</td>
                    <td>{formatList(row.affected_objects)}</td>
                    <td>{formatSources(row.sources)}</td>
                    <td>
                      {hasPassport ? (
                        <Button
                          variant="tiny"
                          aria-label={`Открыть паспорт уязвимости ${label}`}
                          onClick={() => onOpenPassport(row)}
                        >
                          Открыть
                        </Button>
                      ) : (
                        <span className="muted-text">Не сопоставлен</span>
                      )}
                    </td>
                    <td>{formatDate(row.last_seen)}</td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={10} className="empty-cell">
                  Уязвимости с такими фильтрами не найдены.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      <Pagination
        label="Уязвимости"
        offset={offset}
        total={total}
        disabled={fetching}
        onPage={onPage}
      />
    </section>
  );
}

function HostDrilldown({
  selected,
  rows,
  total,
  offset,
  sort,
  pending,
  fetching,
  error,
  headingRef,
  canReadRemediation,
  canManageRemediation,
  remediationBusyAssetId,
  onRetry,
  onSort,
  onPage,
  onClose,
  onOpenPassport,
  onOpenFinding,
  onStartRemediation,
}) {
  const label = vulnerabilityLabel(selected);
  const hasPassport = Boolean(selected.passports?.[0]?.internal_id);
  return (
    <section className="host-drilldown" aria-labelledby="host-drilldown-title">
      <div className="vulnerability-section-heading">
        <div>
          <span className="vulnerability-section-heading__eyebrow">
            Drill-down · {formatCount(total)} хостов
          </span>
          <h3 id="host-drilldown-title" ref={headingRef} tabIndex="-1">
            Хосты с уязвимостью «{label}»
          </h3>
          <p>
            {[selected.cve, severityLabel(selected.severity)]
              .filter(Boolean)
              .join(" · ")}
          </p>
        </div>
        <div className="host-drilldown__actions">
          {hasPassport ? (
            <Button
              variant="secondary"
              onClick={() => onOpenPassport(selected)}
            >
              Открыть паспорт
            </Button>
          ) : null}
          <Button variant="ghost" onClick={onClose}>
            Закрыть
          </Button>
        </div>
      </div>
      <div className="host-drilldown__summary">
        <article>
          <span>Идентификатор</span>
          <strong>{selected.vulnerability_id || selected.cve || "—"}</strong>
        </article>
        <article>
          <span>Критичность</span>
          <SeverityBadge value={selected.severity} />
        </article>
        <article>
          <span>Затронуто хостов</span>
          <strong>{formatCount(selected.affected_hosts ?? total)}</strong>
        </article>
        <article>
          <span>Findings</span>
          <strong>{formatCount(selected.findings)}</strong>
        </article>
        <article>
          <span>Паспорт</span>
          <strong>{hasPassport ? "Сопоставлен" : "Не сопоставлен"}</strong>
        </article>
      </div>
      {error ? (
        <QueryError
          title="Не удалось загрузить хосты"
          error={error}
          retryLabel="Повторить загрузку хостов"
          onRetry={onRetry}
        />
      ) : null}
      <div className="table-shell vulnerability-table-shell">
        <table className="vulnerability-table vulnerability-host-table">
          <caption className="vulnerability-sr-only">
            Хосты, затронутые выбранной уязвимостью
          </caption>
          <thead>
            <tr>
              <SortableHeader column="display_name" sort={sort} onSort={onSort}>
                Хост
              </SortableHeader>
              <th>IP / FQDN</th>
              <th>ОС</th>
              <SortableHeader column="severity" sort={sort} onSort={onSort}>
                Критичность
              </SortableHeader>
              <SortableHeader
                column="cvss_score"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Макс. CVSS
              </SortableHeader>
              <SortableHeader
                column="findings"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Findings
              </SortableHeader>
              <th>Объекты</th>
              <th>Источники</th>
              <SortableHeader
                column="last_seen"
                sort={sort}
                onSort={onSort}
                initialDirection="desc"
              >
                Обновлено
              </SortableHeader>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {pending ? (
              <tr>
                <td colSpan={10} className="empty-cell">
                  Загружаю хосты…
                </td>
              </tr>
            ) : rows.length ? (
              rows.map((row, index) => (
                <tr key={`${row.asset_id || hostLabel(row)}-${index}`}>
                  <td>
                    <button
                      type="button"
                      className="vulnerability-host-link"
                      onClick={() => onOpenFinding(row)}
                    >
                      {hostLabel(row)}
                    </button>
                    {row.asset_id ? <code>{row.asset_id}</code> : null}
                  </td>
                  <td>
                    <span>{row.ip_address || "—"}</span>
                    <small>{row.fqdn || ""}</small>
                  </td>
                  <td>
                    <span>{row.os_name || "—"}</span>
                    <small>{row.os_version || ""}</small>
                  </td>
                  <td>
                    <SeverityBadge value={row.severity} />
                  </td>
                  <td>{formatScore(row.max_cvss ?? row.cvss_score)}</td>
                  <td>{formatCount(row.finding_count)}</td>
                  <td>{formatList(row.objects)}</td>
                  <td>{formatSources(row.sources)}</td>
                  <td>{formatDate(row.last_seen)}</td>
                  <td>
                    <HostRemediationActions
                      row={row}
                      compact
                      canRead={canReadRemediation}
                      canManage={canManageRemediation}
                      busy={remediationBusyAssetId === row.asset_id}
                      onOpenFinding={() => onOpenFinding(row)}
                      onStart={() => onStartRemediation(row)}
                    />
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={10} className="empty-cell">
                  Для выбранной уязвимости хосты не найдены.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {fetching && !pending ? (
        <span className="vulnerability-fetching" role="status">
          Обновляю хосты…
        </span>
      ) : null}
      <Pagination
        label="Хосты"
        offset={offset}
        total={total}
        disabled={fetching}
        onPage={onPage}
      />
    </section>
  );
}

function HostFindingModal({
  selected,
  row,
  canReadRemediation,
  canManageRemediation,
  busy,
  onStartRemediation,
  onClose,
}) {
  const remediation = row.remediation;
  return (
    <PassportModal
      title="Уязвимость на хосте"
      className="asset-modal host-finding-modal"
      overlayClassName="asset-modal-overlay"
      closeLabel="Закрыть"
      onClose={onClose}
    >
      <article className="host-finding-card">
        <header>
          <div>
            <span>Конкретная находка</span>
            <h3>{vulnerabilityLabel(selected)}</h3>
            <p>
              {hostLabel(row)} ·{" "}
              {row.ip_address || row.fqdn || "адрес не указан"}
            </p>
          </div>
          <SeverityBadge value={row.severity || selected?.severity} />
        </header>

        <div className="host-finding-card__facts">
          <div>
            <span>Идентификатор</span>
            <strong>
              {selected?.cve || selected?.vulnerability_id || "—"}
            </strong>
          </div>
          <div>
            <span>CVSS</span>
            <strong>{formatScore(row.max_cvss ?? row.cvss_score)}</strong>
          </div>
          <div>
            <span>Findings на хосте</span>
            <strong>{formatCount(row.finding_count)}</strong>
          </div>
          <div>
            <span>Последнее обновление</span>
            <strong>{formatDate(row.last_seen)}</strong>
          </div>
        </div>

        <div className="host-finding-card__details">
          <section>
            <h4>Затронутые объекты</h4>
            <p>{formatList(row.objects)}</p>
          </section>
          <section>
            <h4>Источники</h4>
            <p>{formatSources(row.sources)}</p>
          </section>
          <section>
            <h4>Операционная система</h4>
            <p>
              {[row.os_name, row.os_version].filter(Boolean).join(" ") || "—"}
            </p>
          </section>
        </div>

        {canReadRemediation ? (
          <section className="host-finding-card__remediation">
            <div>
              <span>Задача устранения</span>
              <RemediationStatus status={remediation?.status} />
            </div>
            <dl>
              <div>
                <dt>Ответственный</dt>
                <dd>{remediation?.assignee || "Не назначен"}</dd>
              </div>
              <div>
                <dt>Срок</dt>
                <dd>
                  {formatDate(remediation?.due_at)}
                  {remediation?.overdue ? " · просрочен" : ""}
                </dd>
              </div>
            </dl>
          </section>
        ) : null}

        <div className="host-finding-card__actions">
          <a
            className="button secondary"
            href={`/asset-cards?asset=${encodeURIComponent(row.asset_id)}`}
          >
            Карточка хоста
          </a>
          {canReadRemediation && remediation?.case_id ? (
            <a
              className="button secondary"
              href={`/remediation?case=${encodeURIComponent(
                remediation.case_id,
              )}`}
            >
              Открыть задачу
            </a>
          ) : null}
          {canManageRemediation && remediation?.status !== "in_progress" ? (
            <Button busy={busy} onClick={() => onStartRemediation(row)}>
              {remediationStartLabel(remediation?.status)}
            </Button>
          ) : null}
        </div>
        {!canManageRemediation ? (
          <small className="host-finding-card__permission">
            Для запуска устранения требуется право remediation.manage.
          </small>
        ) : null}
      </article>
    </PassportModal>
  );
}

function HostRemediationActions({
  row,
  compact = false,
  canRead,
  canManage,
  busy,
  onOpenFinding,
  onStart,
}) {
  const remediation = row.remediation;
  return (
    <div
      className={`host-remediation-actions ${
        compact ? "host-remediation-actions--compact" : ""
      }`}
    >
      {canRead ? <RemediationStatus status={remediation?.status} /> : null}
      <Button
        variant="tiny"
        aria-label={`Открыть находку на хосте ${hostLabel(row)}`}
        onClick={onOpenFinding}
      >
        Открыть находку
      </Button>
      {canManage && remediation?.status !== "in_progress" ? (
        <Button
          variant="secondary"
          busy={busy}
          aria-label={`${remediationStartLabel(
            remediation?.status,
          )} на хосте ${hostLabel(row)}`}
          onClick={onStart}
        >
          {remediationStartLabel(remediation?.status)}
        </Button>
      ) : null}
      {canRead && remediation?.case_id ? (
        <a
          className="button tiny"
          aria-label={`Открыть задачу на хосте ${hostLabel(row)}`}
          href={`/remediation?case=${encodeURIComponent(remediation.case_id)}`}
        >
          Задача
        </a>
      ) : null}
    </div>
  );
}

function RemediationStatus({ status }) {
  const normalized = status || "missing";
  return (
    <span
      className={`remediation-status remediation-status--${normalized.replaceAll(
        "_",
        "-",
      )}`}
    >
      {remediationStatusLabel(status)}
    </span>
  );
}

function Pagination({ label, offset, total, disabled, onPage }) {
  const end = Math.min(offset + VULNERABILITY_PAGE_SIZE, total);
  return (
    <nav
      className="vulnerability-pagination"
      aria-label={`Пагинация: ${label}`}
    >
      <Button
        variant="secondary"
        disabled={disabled || offset === 0}
        aria-label={`${label}: предыдущая страница`}
        onClick={() => onPage(Math.max(0, offset - VULNERABILITY_PAGE_SIZE))}
      >
        Назад
      </Button>
      <span aria-live="polite">
        {total
          ? `${formatCount(offset + 1)}–${formatCount(end)} из ${formatCount(total)}`
          : "Нет результатов"}
      </span>
      <Button
        variant="secondary"
        disabled={disabled || end >= total}
        aria-label={`${label}: следующая страница`}
        onClick={() => onPage(offset + VULNERABILITY_PAGE_SIZE)}
      >
        Далее
      </Button>
    </nav>
  );
}

function SeverityBadge({ value }) {
  const severity = String(value || "none").toLowerCase();
  return (
    <span
      className={`vulnerability-severity vulnerability-severity--${severityClass(severity)}`}
    >
      {severityLabel(severity)}
    </span>
  );
}

function LoadingState({ label }) {
  return (
    <div className="vulnerability-loading" role="status">
      {label}
    </div>
  );
}

function QueryError({ title, error, retryLabel, onRetry }) {
  return (
    <div className="vulnerability-error" role="alert">
      <div>
        <strong>{title}</strong>
        <span>
          {error?.operatorMessage || error?.message || "Повторите попытку."}
        </span>
      </div>
      <Button variant="secondary" onClick={() => onRetry()}>
        {retryLabel}
      </Button>
    </div>
  );
}

function EmptyState({ children }) {
  return <div className="vulnerability-empty">{children}</div>;
}

function resultRows(data) {
  return data?.rows || data?.items || [];
}

function resultTotal(data, rows) {
  return Number(data?.total ?? rows.length) || 0;
}

function severityClass(value) {
  return ["critical", "high", "medium", "low"].includes(value) ? value : "none";
}

function severityLabel(value) {
  return (
    SEVERITY_LABELS[String(value || "none").toLowerCase()] ||
    value ||
    "Не указана"
  );
}

function filterSeverity(value) {
  const normalized = String(value || "").toLowerCase();
  return ["empty", "unknown", "unrated"].includes(normalized)
    ? "none"
    : normalized;
}

function sourceLabel(summary) {
  const source = summary.source_metadata || summary.source;
  if (Array.isArray(source))
    return (
      source.map(sourceValue).filter(Boolean).join(", ") || "Локальные данные"
    );
  return sourceValue(source) || summary.source_label || "Локальные данные";
}

function sourceValue(source) {
  if (!source) return "";
  if (typeof source === "string") return SOURCE_LABELS[source] || source;
  if (typeof source !== "object") return String(source);
  const value =
    source.label ||
    source.name ||
    source.source ||
    source.type ||
    source.dataset;
  return SOURCE_LABELS[value] || value || "";
}

function vulnerabilityLabel(row) {
  return row?.name || row?.cve || row?.vulnerability_id || "Без названия";
}

function hostLabel(row) {
  return (
    row?.display_name ||
    row?.hostname ||
    row?.fqdn ||
    row?.ip_address ||
    row?.asset_id ||
    "Хост без имени"
  );
}

function remediationStatusLabel(status) {
  return (
    {
      open: "Открыта",
      in_progress: "В работе",
      risk_accepted: "Риск принят",
      false_positive: "Ложное срабатывание",
      resolved: "Устранена",
      missing: "Не создана",
    }[status || "missing"] || status
  );
}

function remediationStartLabel(status) {
  if (status === "open") return "Взять в работу";
  if (["risk_accepted", "false_positive"].includes(status)) {
    return "Возобновить устранение";
  }
  if (status === "resolved") return "Переоткрыть задачу";
  return "Взять в устранение";
}

function formatScore(value) {
  if (value === null || value === undefined || value === "") return "—";
  const score = Number(value);
  return Number.isFinite(score)
    ? score.toLocaleString("ru-RU", { maximumFractionDigits: 1 })
    : "—";
}

function formatSources(value) {
  if (!Array.isArray(value)) return formatList(value);
  const labels = value
    .map((item) => SOURCE_LABELS[String(item || "").toLowerCase()] || item)
    .filter(Boolean);
  return labels.length ? labels.join(", ") : "—";
}

function formatList(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) {
    const items = value
      .map((item) => {
        if (item && typeof item === "object")
          return item.name || item.label || item.id || "";
        return String(item);
      })
      .filter(Boolean);
    return items.length ? items.join(", ") : "—";
  }
  if (typeof value === "object")
    return value.name || value.label || value.count || "—";
  return String(value);
}

function trendTagValues(value) {
  const values = Array.isArray(value) ? value : [value];
  return Array.from(
    new Set(
      values
        .map((item) => {
          if (item && typeof item === "object") {
            return (
              item.name ||
              item.display_name ||
              item.displayName ||
              item.label ||
              item.id ||
              ""
            );
          }
          return item === null || item === undefined ? "" : String(item);
        })
        .map((item) => String(item).trim())
        .filter(Boolean),
    ),
  );
}

function formatCalendarDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleDateString("ru-RU");
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : date.toLocaleString("ru-RU");
}

function barWidth(value, maximum) {
  const number = Number(value || 0);
  if (!number || !maximum) return 0;
  return Math.max(4, Math.round((number / maximum) * 100));
}
