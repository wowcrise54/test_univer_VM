import { messageLabel } from "../../shared/labels.js";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, createIdempotencyKey } from "../../api/client.js";
import { formatCount, splitTokens } from "../../shared/format.js";
import {
  SortableHeader,
  useSortedRows,
  useTableSort,
} from "../../shared/table.jsx";
import {
  ActionMenu,
  Button,
  ConfirmDialog,
  Disclosure,
  Field,
  Panel,
  Toggle,
} from "../../shared/ui.jsx";
import { AssetCard, assetCardStats } from "./AssetCard.jsx";
import { PassportCard, PassportModal } from "../passports/PassportCard.jsx";
import { TaskPostprocessPanel } from "../tasks/TaskPostprocessPanel.jsx";
import { FreshnessBadge } from "../../shared/badges.jsx";
import {
  clampNumber,
  formatDateTime,
  normalizeSearchText,
} from "../../shared/values.js";

const ACTIVE_ASSET_CARD_JOB_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
]);

const ACTIVE_SCAN_POSTPROCESS_STATUSES = new Set([
  "monitoring",
  "resolving",
  "processing",
  "waiting",
]);

const ACTIVE_BULK_REFRESH_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
  "recovering",
]);

export function AssetCardsPanel({ defaults, busy, runBusy, showAlert, currentUser }) {
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    asset_limit: "1001",
    batch_size: "5000",
    include_nested_groups: true,
    selected_asset_id: "",
    batch_asset_ids: "",
    timeline_timestamp: "",
    limit_per_collection: "5000",
    max_items_per_collection: "5000",
    max_depth: "64",
    docker_vulnerability_pdql: "",
    asset_refresh_parallelism: "",
    save_to_db: true,
  });
  const [candidates, setCandidates] = useState([]);
  const [cards, setCards] = useState([]);
  const [selectedCard, setSelectedCard] = useState(null);
  const [candidateSearch, setCandidateSearch] = useState("");
  const [cardSearch, setCardSearch] = useState("");
  const [queryRaw, setQueryRaw] = useState(null);
  const [assetWindowOpen, setAssetWindowOpen] = useState(false);
  const [selectedPassport, setSelectedPassport] = useState(null);
  const [assetPassportDetail, setAssetPassportDetail] = useState(null);
  const [assetPassportError, setAssetPassportError] = useState("");
  const [assetPassportWindowOpen, setAssetPassportWindowOpen] = useState(false);
  const [assetCardJob, setAssetCardJob] = useState(null);
  const [assetCardBatchJobs, setAssetCardBatchJobs] = useState([]);
  const [assetRefreshRun, setAssetRefreshRun] = useState(null);
  const [assetBulkRefreshOperation, setAssetBulkRefreshOperation] =
    useState(null);
  const [assetRefreshTemplates, setAssetRefreshTemplates] = useState([]);
  const [selectedRefreshTemplateId, setSelectedRefreshTemplateId] =
    useState("");
  const [assetRefreshTemplatesError, setAssetRefreshTemplatesError] =
    useState("");
  const [pendingCardDelete, setPendingCardDelete] = useState(null);
  const [candidateSort, toggleCandidateSort] = useTableSort();
  const [cardSort, toggleCardSort] = useTableSort("last_seen", "desc");
  const permissions = useMemo(
    () => new Set(currentUser?.permissions || []),
    [currentUser],
  );
  const canBuildAssetCards = permissions.has("asset_cards.build");
  const canManageAssetCards = permissions.has("asset_cards.manage");

  const refreshLocalCards = useCallback(
    async (sorting = cardSort) => {
      const params = new URLSearchParams({
        limit: String(clampNumber(form.asset_limit, 1000, 1, 50000)),
      });
      if (cardSearch.trim()) params.set("q", cardSearch.trim());
      params.set("sort_by", sorting.key);
      params.set("sort_dir", sorting.direction);
      const result = await api(`/api/asset-cards/local?${params.toString()}`);
      setCards(result.rows || []);
      return result;
    },
    [cardSearch, cardSort, form.asset_limit],
  );

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.asset_card_pdql || "",
      docker_vulnerability_pdql:
        value.docker_vulnerability_pdql ||
        defaults.docker_vulnerability_pdql ||
        "",
      asset_refresh_parallelism:
        value.asset_refresh_parallelism ||
        String(defaults.asset_card_refresh_workers || 10),
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  useEffect(() => {
    if (!assetWindowOpen) return;
    const closeOnEscape = (event) => {
      if (event.key === "Escape") setAssetWindowOpen(false);
    };
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [assetWindowOpen]);

  useEffect(() => {
    let alive = true;
    Promise.allSettled([
      api("/api/asset-cards/build-jobs/active"),
      api("/api/asset-cards/refresh-scan/templates"),
    ]).then(([activeRequest, templatesRequest]) => {
      if (!alive) return;
      if (activeRequest.status === "fulfilled" && activeRequest.value.job) {
        setAssetCardJob(activeRequest.value.job);
      }
      if (templatesRequest.status === "rejected") {
        const error = templatesRequest.reason;
        setAssetRefreshTemplatesError(
          error?.operatorMessage || error?.message || String(error),
        );
        return;
      }
      const templatesResult = templatesRequest.value;
      const rows = templatesResult.rows || [];
      setAssetRefreshTemplates(rows);
      setSelectedRefreshTemplateId(
        templatesResult.recommended_task_id || rows[0]?.mp_task_id || "",
      );
      setAssetRefreshTemplatesError("");
    });
    return () => {
      alive = false;
    };
  }, [showAlert]);

  useEffect(() => {
    if (
      !assetCardJob?.job_id ||
      !ACTIVE_ASSET_CARD_JOB_STATUSES.has(assetCardJob.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextJob = await api(
          `/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}`,
        );
        if (!alive) return;
        setAssetCardJob(nextJob);
        if (ACTIVE_ASSET_CARD_JOB_STATUSES.has(nextJob.status)) {
          timerId = window.setTimeout(poll, 1000);
          return;
        }
        if (nextJob.status === "completed") {
          const [card] = await Promise.all([
            api(
              `/api/asset-cards/${encodeURIComponent(nextJob.asset_id)}/summary`,
            ),
            refreshLocalCards(),
          ]);
          if (!alive) return;
          setSelectedCard(card);
          setAssetWindowOpen(true);
          showAlert(
            `Карточка актива ${card.display_name || card.asset_id} собрана.`,
            "success",
          );
        } else {
          showAlert(
            `Сборка карточки завершена со статусом «${assetCardJobStatusLabel(nextJob.status)}».`,
            nextJob.status === "failed" ? "error" : "info",
          );
        }
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 3000);
      }
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    assetCardJob?.job_id,
    assetCardJob?.status,
    refreshLocalCards,
    showAlert,
  ]);

  useEffect(() => {
    const activeJobs = assetCardBatchJobs.filter(
      (job) => job.job_id && ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
    );
    if (!activeJobs.length) return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      const settled = await Promise.allSettled(
        activeJobs.map((job) =>
          api(`/api/asset-cards/build-jobs/${encodeURIComponent(job.job_id)}`),
        ),
      );
      if (!alive) return;
      const updates = new Map();
      settled.forEach((result, index) => {
        if (result.status === "fulfilled") {
          updates.set(activeJobs[index].job_id, result.value);
        }
      });
      const nextJobs = assetCardBatchJobs.map(
        (job) => updates.get(job.job_id) || job,
      );
      setAssetCardBatchJobs(nextJobs);
      const stillActive = nextJobs.some((job) =>
        ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
      );
      if (stillActive) {
        timerId = window.setTimeout(poll, 1000);
        return;
      }
      await refreshLocalCards();
      if (!alive) return;
      const completed = nextJobs.filter(
        (job) => job.status === "completed",
      ).length;
      showAlert(
        `Пакетная сборка завершена: ${formatCount(completed)} из ${formatCount(nextJobs.length)} карточек сохранено.`,
        completed === nextJobs.length ? "success" : "error",
      );
    };
    timerId = window.setTimeout(poll, 500);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [assetCardBatchJobs, refreshLocalCards, showAlert]);

  useEffect(() => {
    if (
      !assetRefreshRun?.mp_task_id ||
      !ACTIVE_SCAN_POSTPROCESS_STATUSES.has(assetRefreshRun.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextRun = await api(
          `/api/scanner-tasks/${encodeURIComponent(assetRefreshRun.mp_task_id)}/postprocess-runs/latest`,
        );
        if (!alive) return;
        setAssetRefreshRun(nextRun);
        if (ACTIVE_SCAN_POSTPROCESS_STATUSES.has(nextRun.status)) {
          timerId = window.setTimeout(poll, 3000);
          return;
        }
        const refreshed = await refreshLocalCards();
        if (!alive) return;
        const completedAssetId = (nextRun.items || []).find(
          (item) => item.status === "completed",
        )?.asset_id;
        const nextCardSummary =
          (refreshed.rows || []).find(
            (item) => item.asset_id === completedAssetId,
          ) ||
          (refreshed.rows || []).find(
            (item) => item.ip_address === nextRun.options?.refresh_target_ip,
          );
        if (nextRun.status === "completed" && nextCardSummary?.asset_id) {
          const card = await api(
            `/api/asset-cards/${encodeURIComponent(nextCardSummary.asset_id)}/summary`,
          );
          if (!alive) return;
          setSelectedCard(card);
          setAssetWindowOpen(true);
          showAlert(
            `Карточка ${card.display_name || card.asset_id} обновлена после повторного сканирования IP.`,
            "success",
          );
        } else {
          showAlert(
            nextRun.message ||
              "Повторное сканирование карточки завершилось с ошибками.",
            "error",
          );
        }
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 5000);
      }
    };
    timerId = window.setTimeout(poll, 1000);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [assetRefreshRun?.mp_task_id, refreshLocalCards, showAlert]);

  useEffect(() => {
    if (
      !assetBulkRefreshOperation?.operation_id ||
      !ACTIVE_BULK_REFRESH_STATUSES.has(assetBulkRefreshOperation.status)
    )
      return undefined;
    let alive = true;
    let timerId;
    const poll = async () => {
      try {
        const nextOperation = await api(
          `/api/operations/${encodeURIComponent(assetBulkRefreshOperation.operation_id)}`,
        );
        if (!alive) return;
        setAssetBulkRefreshOperation(nextOperation);
        if (ACTIVE_BULK_REFRESH_STATUSES.has(nextOperation.status)) {
          timerId = window.setTimeout(poll, 3000);
          return;
        }
        await refreshLocalCards();
        if (!alive) return;
        const result = nextOperation.result || {};
        showAlert(
          nextOperation.message ||
            `Массовое обновление завершено: ${formatCount(result.completed_count)} из ${formatCount(result.selected_count)}.`,
          nextOperation.status === "completed" ? "success" : "error",
        );
      } catch (_error) {
        if (alive) timerId = window.setTimeout(poll, 5000);
      }
    };
    timerId = window.setTimeout(poll, 1000);
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [
    assetBulkRefreshOperation?.operation_id,
    assetBulkRefreshOperation?.status,
    refreshLocalCards,
    showAlert,
  ]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const filteredCandidates = useMemo(
    () => filterAssetCandidates(candidates, candidateSearch),
    [candidates, candidateSearch],
  );
  const sortedCandidates = useSortedRows(filteredCandidates, candidateSort);

  const changeCardSort = (key, initialDirection = "asc") => {
    const next = {
      key,
      direction:
        cardSort.key === key
          ? cardSort.direction === "asc"
            ? "desc"
            : "asc"
          : initialDirection,
    };
    toggleCardSort(key, initialDirection);
    runBusy("assetCardsLocal", () => refreshLocalCards(next));
  };

  const queryAssets = () =>
    runBusy("assetCandidateQuery", async () => {
      const requestedLimit = clampNumber(form.asset_limit, 1001, 1, 50000);
      const requestedBatchSize = clampNumber(form.batch_size, 5000, 1, 10000);
      const result = await api("/api/asset-cards/query-assets", {
        method: "POST",
        body: JSON.stringify({
          pdql: form.pdql,
          utc_offset: form.utc_offset || null,
          group_ids: splitTokens(form.group_ids),
          asset_ids: splitTokens(form.asset_ids),
          include_nested_groups: form.include_nested_groups,
          limit: requestedLimit,
          batch_size: requestedBatchSize,
        }),
      });
      const records = result.records || [];
      setCandidates(records);
      setQueryRaw(result.raw || null);
      if (!form.selected_asset_id && records[0]?.asset_id) {
        update("selected_asset_id", records[0].asset_id);
      }
      showAlert(
        `Получено активов: ${formatCount(records.length)}.`,
        records.length ? "success" : "info",
      );
    });

  const buildCard = () =>
    runBusy("assetCardBuild", async () => {
      const assetId = form.selected_asset_id.trim();
      if (!assetId)
        throw new Error("Введите asset_id или выберите актив из списка.");
      const payload = {
        asset_id: assetId,
        timeline_timestamp: form.timeline_timestamp
          ? Number(form.timeline_timestamp)
          : null,
        limit_per_collection: clampNumber(
          form.limit_per_collection,
          5000,
          1,
          5000,
        ),
        max_items_per_collection: clampNumber(
          form.max_items_per_collection,
          5000,
          1,
          50000,
        ),
        max_depth: clampNumber(form.max_depth, 64, 0, 64),
        docker_vulnerability_pdql: form.docker_vulnerability_pdql,
      };
      if (form.save_to_db) {
        const result = await api("/api/asset-cards/build-jobs", {
          method: "POST",
          headers: { "X-Idempotency-Key": createIdempotencyKey("asset-card") },
          body: JSON.stringify(payload),
        });
        setAssetCardJob(result.job);
        showAlert(`Сборка карточки ${assetId} запущена в фоне.`, "info");
        return;
      }
      const result = await api("/api/asset-cards/build", {
        method: "POST",
        body: JSON.stringify({ ...payload, save_to_db: false }),
      });
      const nextCard = result.card;
      setSelectedCard(nextCard);
      setAssetWindowOpen(true);
      if (result.saved) {
        setCards((items) => [
          nextCard,
          ...items.filter((item) => item.asset_id !== nextCard.asset_id),
        ]);
      }
      const stats = assetCardStats(nextCard);
      showAlert(
        `Карточка собрана: ${formatCount(stats.table_rows)} строк data, ${formatCount(stats.collections)} коллекций.`,
        "success",
      );
    });

  const batchAssetIds = useMemo(
    () => [...new Set(splitTokens(form.batch_asset_ids))],
    [form.batch_asset_ids],
  );
  const batchAssetIdsValid =
    batchAssetIds.length >= 1 && batchAssetIds.length <= 2;

  const toggleBatchAsset = (assetId) => {
    if (!assetId) return;
    const selected = new Set(batchAssetIds);
    if (selected.has(assetId)) selected.delete(assetId);
    else if (selected.size < 2) selected.add(assetId);
    update("batch_asset_ids", [...selected].join("\n"));
  };

  const buildCardBatch = () =>
    runBusy("assetCardBatchBuild", async () => {
      if (!batchAssetIdsValid) {
        throw new Error("Укажите один или два уникальных asset_id.");
      }
      const result = await api("/api/asset-cards/build-jobs/batch", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": createIdempotencyKey("asset-card-batch"),
        },
        body: JSON.stringify({
          asset_ids: batchAssetIds,
          timeline_timestamp: form.timeline_timestamp
            ? Number(form.timeline_timestamp)
            : null,
          limit_per_collection: clampNumber(
            form.limit_per_collection,
            5000,
            1,
            5000,
          ),
          max_items_per_collection: clampNumber(
            form.max_items_per_collection,
            5000,
            1,
            50000,
          ),
          max_depth: clampNumber(form.max_depth, 64, 0, 64),
          docker_vulnerability_pdql: form.docker_vulnerability_pdql,
        }),
      });
      const responseJobs =
        result.jobs || result.items || result.batch?.jobs || [];
      if (!Array.isArray(responseJobs) || responseJobs.length === 0) {
        throw new Error("Backend не вернул задачи пакетной сборки.");
      }
      const jobs = responseJobs.map((item) => item.job || item);
      setAssetCardBatchJobs(jobs);
      showAlert(
        `Запущена сборка ${formatCount(jobs.length)} карточек активов.`,
        "info",
      );
    });

  const loadLocalCards = () =>
    runBusy("assetCardsLocal", async () => {
      await refreshLocalCards();
    });

  useEffect(() => {
    refreshLocalCards().catch(() => {
      // The list keeps its empty state; the refresh button shows errors.
    });
    // Only the first render loads automatically.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openLocalCard = (row) => {
    setSelectedCard({ ...row, loaded_sections: ["summary"] });
    setAssetWindowOpen(true);
  };

  useEffect(() => {
    const assetId =
      typeof window === "undefined"
        ? null
        : new URLSearchParams(window.location.search).get("asset");
    if (!assetId) return;
    api(`/api/asset-cards/${encodeURIComponent(assetId)}/summary`)
      .then((card) => {
        setSelectedCard(card);
        setAssetWindowOpen(true);
      })
      .catch((error) =>
        showAlert(error.operatorMessage || error.message, "error"),
      );
  }, [showAlert]);

  const updateLocalCard = (row) =>
    runBusy(`assetCardUpdate:${row.asset_id}`, async () => {
      const result = await api(
        `/api/asset-cards/${encodeURIComponent(row.asset_id)}/refresh-scan`,
        {
          method: "POST",
          headers: {
            "X-Idempotency-Key": createIdempotencyKey(
              "asset-card-refresh-scan",
            ),
          },
          body: JSON.stringify({}),
        },
      );
      if (!result.postprocess_run_id || result.status !== "started") {
        throw new Error(
          result.error ||
            result.message ||
            "Автоматическая задача не была запущена.",
        );
      }
      setAssetRefreshRun(result.postprocess);
      showAlert(
        `Создана задача ${result.task_id}; IP ${result.target_ip} отправлен на повторное сканирование.`,
        "info",
      );
    });

  const updateAllLocalCards = () =>
    runBusy("assetCardsBulkRefresh", async () => {
      const result = await api("/api/asset-cards/refresh-scan/bulk", {
        method: "POST",
        headers: {
          "X-Idempotency-Key": createIdempotencyKey("asset-cards-bulk-refresh"),
        },
        body: JSON.stringify({
          selection: "all",
          template_task_id: selectedRefreshTemplateId || null,
          parallelism: clampNumber(
            form.asset_refresh_parallelism,
            defaults?.asset_card_refresh_workers || 10,
            1,
            defaults?.asset_card_refresh_workers || 10,
          ),
        }),
      });
      if (!result.operation_id || !result.operation) {
        throw new Error(
          "Массовое обновление карточек не было поставлено в очередь.",
        );
      }
      setAssetBulkRefreshOperation(result.operation);
      showAlert(
        `Все сохранённые карточки поставлены на обновление: до ${clampNumber(
          form.asset_refresh_parallelism,
          defaults?.asset_card_refresh_workers || 10,
          1,
          defaults?.asset_card_refresh_workers || 10,
        )} одновременно. Прогресс доступен в центре операций.`,
        "info",
      );
    });

  const cancelAssetCardJob = () => {
    if (!assetCardJob?.job_id) return;
    runBusy("assetCardJobCancel", async () => {
      const result = await api(
        `/api/asset-cards/build-jobs/${encodeURIComponent(assetCardJob.job_id)}/cancel`,
        {
          method: "POST",
        },
      );
      setAssetCardJob(result);
      showAlert("Остановка сборки карточки запрошена.", "info");
    });
  };

  const deleteLocalCard = (row) => {
    const label = row.display_name || row.hostname || row.asset_id;
    runBusy(`assetCardDelete:${row.asset_id}`, async () => {
      await api(`/api/asset-cards/${encodeURIComponent(row.asset_id)}`, {
        method: "DELETE",
      });
      setCards((items) =>
        items.filter((item) => item.asset_id !== row.asset_id),
      );
      if (selectedCard?.asset_id === row.asset_id) {
        setSelectedCard(null);
        setAssetWindowOpen(false);
      }
      showAlert(`Карточка актива ${label} удалена.`, "success");
      setPendingCardDelete(null);
    });
  };

  const openAssetPassport = (passport) =>
    runBusy("assetCardPassportDetail", async () => {
      const passportSummary =
        typeof passport === "string"
          ? { internal_id: passport }
          : passport || {};
      const passportId = passportSummary.internal_id;
      if (!passportId)
        throw new Error("Для этой уязвимости ещё не найден локальный паспорт.");
      setSelectedPassport(passportSummary);
      setAssetPassportDetail(null);
      setAssetPassportError("");
      setAssetPassportWindowOpen(true);
      try {
        const result = await api(
          `/api/vulnerability-passports/${encodeURIComponent(passportId)}`,
        );
        const nextPassport = result.passport || {
          ...passportSummary,
          internal_id: passportId,
          raw_detail: result.raw || null,
          has_detail: Boolean(result.raw),
        };
        setSelectedPassport(nextPassport);
        setAssetPassportDetail(result.raw || nextPassport.raw_detail || {});
      } catch (error) {
        setAssetPassportError(error.message || String(error));
        throw error;
      }
    });

  const assetCardJobProgress = Math.max(
    0,
    Math.min(100, Number(assetCardJob?.progress_percent) || 0),
  );
  const assetCardJobActive = ACTIVE_ASSET_CARD_JOB_STATUSES.has(
    assetCardJob?.status,
  );
  const assetCardBatchActive = assetCardBatchJobs.some((job) =>
    ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
  );
  const assetCardBatchCompletedCount = assetCardBatchJobs.filter(
    (job) => job.status === "completed",
  ).length;
  const assetCardBatchFailedCount = assetCardBatchJobs.filter((job) =>
    ["failed", "cancelled", "interrupted"].includes(job.status),
  ).length;
  const assetCardBatchActiveCount = assetCardBatchJobs.filter((job) =>
    ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status),
  ).length;
  const assetRefreshActive = ACTIVE_SCAN_POSTPROCESS_STATUSES.has(
    assetRefreshRun?.status,
  );
  const assetBulkRefreshActive = ACTIVE_BULK_REFRESH_STATUSES.has(
    assetBulkRefreshOperation?.status,
  );

  return (
    <Panel
      id="asset-cards"
      action={
        <div className="row-actions">
          {canBuildAssetCards ? (
            <ActionMenu label="Ещё">
              <Button
                aria-label="Обновить все карточки активов"
                busy={busy.assetCardsBulkRefresh}
                disabled={
                  !selectedRefreshTemplateId ||
                  assetCardJobActive ||
                  assetRefreshActive ||
                  assetBulkRefreshActive
                }
                onClick={updateAllLocalCards}
              >
                Обновить все из MP VM
              </Button>
            </ActionMenu>
          ) : null}
        </div>
      }
    >
      <div className="asset-local-header">
        <input
          value={cardSearch}
          onChange={(event) => setCardSearch(event.target.value)}
          onKeyDown={(event) => event.key === "Enter" && loadLocalCards()}
          placeholder="IP, FQDN, имя хоста или ОС"
        />
        <Button
          variant="secondary"
          busy={busy.assetCardsLocal}
          onClick={loadLocalCards}
        >
          Показать сохранённые
        </Button>
      </div>
      <div className="table-shell">
        <table className="asset-card-list-table">
          <thead>
            <tr>
              <SortableHeader
                column="display_name"
                sort={cardSort}
                onSort={changeCardSort}
              >
                Актив
              </SortableHeader>
              <SortableHeader
                column="ip_address"
                sort={cardSort}
                onSort={changeCardSort}
              >
                IP / FQDN
              </SortableHeader>
              <SortableHeader
                column="os_name"
                sort={cardSort}
                onSort={changeCardSort}
              >
                Платформа
              </SortableHeader>
              <SortableHeader
                column="last_seen"
                sort={cardSort}
                onSort={changeCardSort}
                initialDirection="desc"
              >
                Обновлено
              </SortableHeader>
              <th>Действия</th>
            </tr>
          </thead>
          <tbody>
            {cards.length ? (
              cards.map((row) => {
                const stats = assetCardStats(row);
                return (
                  <tr key={row.asset_id}>
                    <td className="wide-cell">
                      <strong>
                        {row.display_name || row.hostname || row.asset_id}
                      </strong>
                      <span>
                        <code>{row.asset_id}</code>
                      </span>
                    </td>
                    <td>
                      {[row.ip_address, row.fqdn].filter(Boolean).join(" / ") ||
                        "—"}
                    </td>
                    <td>
                      {[row.os_name, row.os_version]
                        .filter(Boolean)
                        .join(" ") || "—"}
                      <small className="table-cell-meta">
                        {row.asset_type || "Тип не указан"} ·{" "}
                        {formatCount(stats.table_rows)} строк ·{" "}
                        {formatCount(stats.collections)} коллекций
                      </small>
                    </td>
                    <td>
                      <FreshnessBadge
                        value={row.last_seen}
                        freshForHours={14 * 24}
                        staleAfterHours={14 * 24}
                      />
                    </td>
                    <td>
                      <div className="row-actions">
                        <Button
                          variant="tiny"
                          busy={
                            busy.assetCardOpen &&
                            selectedCard?.asset_id === row.asset_id
                          }
                          onClick={() => openLocalCard(row)}
                        >
                          Открыть
                        </Button>
                        {canBuildAssetCards || canManageAssetCards ? (
                          <ActionMenu label="Ещё">
                            {canBuildAssetCards ? (
                              <Button
                                variant="tiny"
                                disabled={
                                  assetCardJobActive || assetRefreshActive
                                }
                                busy={busy[`assetCardUpdate:${row.asset_id}`]}
                                onClick={() => updateLocalCard(row)}
                              >
                                Обновить
                              </Button>
                            ) : null}
                            {canManageAssetCards ? (
                              <Button
                                variant="tiny-danger"
                                busy={busy[`assetCardDelete:${row.asset_id}`]}
                                onClick={() => setPendingCardDelete(row)}
                              >
                                Удалить
                              </Button>
                            ) : null}
                          </ActionMenu>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })
            ) : (
              <tr>
                <td colSpan={5} className="empty-cell">
                  {canBuildAssetCards
                    ? "Соберите карточку или загрузите сохранённые из БД."
                    : "Загрузите сохранённые карточки из БД."}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {canBuildAssetCards ? (
        <Disclosure className="asset-card-build" title="Сбор из MP VM">
          <Disclosure
            title="Обновление карточек из MP VM"
            meta={selectedRefreshTemplateId ? "Шаблон выбран" : "Не настроено"}
          >
            <Field label="Задача MP VM для обновления карточек">
              <select
                value={selectedRefreshTemplateId}
                onChange={(event) =>
                  setSelectedRefreshTemplateId(event.target.value)
                }
              >
                <option value="">Выберите задачу-шаблон</option>
                {assetRefreshTemplates.map((task) => (
                  <option key={task.mp_task_id} value={task.mp_task_id}>
                    {task.name || task.mp_task_id}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Параллельных обновлений">
              <input
                type="number"
                min="1"
                max={defaults?.asset_card_refresh_workers || 10}
                value={form.asset_refresh_parallelism}
                onChange={(event) =>
                  update("asset_refresh_parallelism", event.target.value)
                }
              />
            </Field>
            {assetRefreshTemplatesError ? (
              <small className="error-text">
                Не удалось загрузить задачи-шаблоны:{" "}
                {assetRefreshTemplatesError}
              </small>
            ) : assetRefreshTemplates.length === 0 ? (
              <small className="error-text">
                В MP VM не найдено задач с заполненными scope и scanner profile.
                Создайте такую задачу перед массовым обновлением карточек.
              </small>
            ) : null}
          </Disclosure>
          <Field label="PDQL-запрос активов">
            <textarea
              className="code-input"
              rows={4}
              value={form.pdql}
              onChange={(event) => update("pdql", event.target.value)}
            />
          </Field>
          <Disclosure
            title="Параметры поиска"
            meta={
              form.group_ids || form.asset_ids
                ? "Есть ограничения"
                : "По умолчанию"
            }
          >
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
                  value={form.asset_limit}
                  onChange={(event) =>
                    update("asset_limit", event.target.value)
                  }
                  type="number"
                  min="1"
                  max="50000"
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
            </div>
          </Disclosure>
          <div className="action-row">
            <Button busy={busy.assetCandidateQuery} onClick={queryAssets}>
              Найти активы
            </Button>
            <div className="inline-metric">
              Найдено: <span>{formatCount(filteredCandidates.length)}</span>
            </div>
          </div>

          <div className="asset-card-builder">
            <div className="asset-card-build-primary">
              <Field label="ID актива">
                <input
                  value={form.selected_asset_id}
                  onChange={(event) =>
                    update("selected_asset_id", event.target.value)
                  }
                  placeholder="ID из списка или вручную"
                />
              </Field>
              <Button
                busy={busy.assetCardBuild}
                disabled={assetCardJobActive || assetCardBatchActive}
                onClick={buildCard}
              >
                Собрать карточку
              </Button>
            </div>
            <Disclosure
              title="Параметры сборки"
              meta={form.save_to_db ? "Сохранить в БД" : "Без сохранения"}
            >
              <Field label="PDQL уязвимостей Docker-контейнеров">
                <textarea
                  className="code-input"
                  rows={6}
                  value={form.docker_vulnerability_pdql}
                  onChange={(event) =>
                    update("docker_vulnerability_pdql", event.target.value)
                  }
                />
              </Field>
              <div className="form-grid form-grid--two form-grid--spaced">
                <Field label="Момент времени (Unix)">
                  <input
                    value={form.timeline_timestamp}
                    onChange={(event) =>
                      update("timeline_timestamp", event.target.value)
                    }
                    type="number"
                    placeholder="Сейчас"
                  />
                </Field>
                <Field label="Лимит запроса коллекции">
                  <input
                    value={form.limit_per_collection}
                    onChange={(event) =>
                      update("limit_per_collection", event.target.value)
                    }
                    type="number"
                    min="1"
                    max="5000"
                  />
                </Field>
                <Field label="Максимум элементов коллекции">
                  <input
                    value={form.max_items_per_collection}
                    onChange={(event) =>
                      update("max_items_per_collection", event.target.value)
                    }
                    type="number"
                    min="1"
                    max="50000"
                  />
                </Field>
                <Field label="Глубина обхода">
                  <input
                    value={form.max_depth}
                    onChange={(event) =>
                      update("max_depth", event.target.value)
                    }
                    type="number"
                    min="0"
                    max="64"
                  />
                </Field>
                <Toggle
                  label="Сохранить карточку локально"
                  checked={form.save_to_db}
                  onChange={(value) => update("save_to_db", value)}
                />
              </div>
            </Disclosure>
          </div>

          <Disclosure
            title="Пакетная сборка"
            meta={
              batchAssetIds.length
                ? `Выбрано: ${batchAssetIds.length}`
                : "Не выбрано"
            }
          >
            <Field label="ID активов для пакетной сборки" wide>
              <textarea
                rows={4}
                value={form.batch_asset_ids}
                onChange={(event) =>
                  update("batch_asset_ids", event.target.value)
                }
                placeholder="До двух ID, по одному в строке"
                aria-describedby="asset-card-batch-help"
              />
            </Field>
            <small
              id="asset-card-batch-help"
              className={batchAssetIds.length > 2 ? "error-text" : undefined}
            >
              Выбрано: {formatCount(batchAssetIds.length)} из 2
              {batchAssetIds.length > 2 ? ". Удалите лишние значения." : ""}
            </small>
            <div className="action-row">
              <Button
                busy={busy.assetCardBatchBuild}
                disabled={
                  !batchAssetIdsValid ||
                  assetCardJobActive ||
                  assetCardBatchActive
                }
                onClick={buildCardBatch}
              >
                Собрать выбранные карточки
              </Button>
            </div>
          </Disclosure>
        </Disclosure>
      ) : null}

      {canBuildAssetCards && assetCardBatchJobs.length ? (
        <section className="passport-job asset-card-job" aria-live="polite">
          <div className="passport-job__header">
            <strong>Пакетная сборка карточек</strong>
            <span>
              Готово: {formatCount(assetCardBatchCompletedCount)} · Ошибки:{" "}
              {formatCount(assetCardBatchFailedCount)} · В работе:{" "}
              {formatCount(assetCardBatchActiveCount)}
            </span>
          </div>
          {assetCardBatchJobs.map((job, index) => {
            const progress = Math.max(
              0,
              Math.min(100, Number(job.progress_percent) || 0),
            );
            return (
              <div key={job.job_id || job.asset_id || index}>
                <div className="asset-local-header">
                  <div>
                    <strong>{job.asset_id || `Карточка ${index + 1}`}</strong>
                    <small>
                      {assetCardJobStatusLabel(job.status)} ·{" "}
                      {assetCardJobStageLabel(job.stage)} ·{" "}
                      {formatCount(progress)}%
                    </small>
                  </div>
                  <span
                    className={`status-pill ${ACTIVE_ASSET_CARD_JOB_STATUSES.has(job.status) ? "status-pill--running" : ""}`}
                  >
                    {assetCardJobStatusLabel(job.status)}
                  </span>
                </div>
                <div
                  className="passport-job__track"
                  role="progressbar"
                  aria-label={`Прогресс сборки карточки ${
                    job.asset_id || index + 1
                  }`}
                  aria-valuemin="0"
                  aria-valuemax="100"
                  aria-valuenow={progress}
                  aria-valuetext={`${progress}% — ${assetCardJobStageLabel(job.stage)}`}
                >
                  <span style={{ width: `${progress}%` }} />
                </div>
                {job.message ? <small>{messageLabel(job.message)}</small> : null}
              </div>
            );
          })}
        </section>
      ) : null}

      {canBuildAssetCards && assetCardJob ? (
        <section
          className={`passport-job asset-card-job passport-job--${assetCardJob.status}${assetCardJobActive ? " asset-card-job--active" : ""}`}
          aria-live="polite"
        >
          <div className="passport-job__header">
            <div>
              <strong>
                Сборка карточки {assetCardJob.asset_id}:{" "}
                {assetCardJobStatusLabel(assetCardJob.status)}
              </strong>
              <span>
                Этап: {assetCardJobStageLabel(assetCardJob.stage)} ·{" "}
                {formatCount(assetCardJobProgress)}% · запросов{" "}
                {formatCount(assetCardJob.completed_requests)} /{" "}
                {formatCount(assetCardJob.discovered_requests)} · узлов{" "}
                {formatCount(assetCardJob.node_count)} · коллекций{" "}
                {formatCount(assetCardJob.collection_count)} · уязвимостей{" "}
                {formatCount(assetCardJob.finding_count)} · предупреждений{" "}
                {formatCount(assetCardJob.warning_count)}
              </span>
            </div>
            {assetCardJobActive ? (
              <Button
                variant="tiny-danger"
                busy={busy.assetCardJobCancel}
                onClick={cancelAssetCardJob}
              >
                Остановить
              </Button>
            ) : null}
          </div>
          {assetCardJob.trace_id ? (
            <small>
              Trace ID: <code>{assetCardJob.trace_id}</code>
            </small>
          ) : null}
          <div
            className="passport-job__track"
            role="progressbar"
            aria-label="Прогресс сборки карточки"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={assetCardJobProgress}
            aria-valuetext={`${assetCardJobProgress}% — ${assetCardJobStageLabel(assetCardJob.stage)}`}
          >
            <span style={{ width: `${assetCardJobProgress}%` }} />
          </div>
          {assetCardJob.message ? <small>{messageLabel(assetCardJob.message)}</small> : null}
        </section>
      ) : null}

      {canBuildAssetCards && assetRefreshRun ? (
        <div className="asset-refresh-scan">
          <div className="asset-local-header">
            <div>
              <strong>Обновление карточки через повторное сканирование</strong>
              <small>
                Задача MP VM: <code>{assetRefreshRun.mp_task_id}</code>
              </small>
            </div>
            {assetRefreshActive ? (
              <span className="status-pill status-pill--running">
                Выполняется
              </span>
            ) : null}
          </div>
          <TaskPostprocessPanel run={assetRefreshRun} />
        </div>
      ) : null}

      {canBuildAssetCards && assetBulkRefreshOperation ? (
        <section className="passport-job asset-refresh-scan" aria-live="polite">
          <div className="asset-local-header">
            <div>
              <strong>Массовое обновление карточек активов</strong>
              <small>
                {messageLabel(assetBulkRefreshOperation.message) ||
                  "Операция поставлена в очередь."}
              </small>
            </div>
            <span
              className={`status-pill ${assetBulkRefreshActive ? "status-pill--running" : ""}`}
            >
              {formatCount(assetBulkRefreshOperation.progress_percent)}%
            </span>
          </div>
          <div
            className="passport-job__track"
            role="progressbar"
            aria-label="Прогресс массового обновления карточек"
            aria-valuemin="0"
            aria-valuemax="100"
            aria-valuenow={
              Number(assetBulkRefreshOperation.progress_percent) || 0
            }
          >
            <span
              style={{
                width: `${Math.max(0, Math.min(100, Number(assetBulkRefreshOperation.progress_percent) || 0))}%`,
              }}
            />
          </div>
        </section>
      ) : null}

      {canBuildAssetCards && candidates.length ? (
        <>
          <div className="passport-controls">
            <input
              value={candidateSearch}
              onChange={(event) => setCandidateSearch(event.target.value)}
              placeholder="Поиск по asset_id, имени, ОС"
            />
            <select
              value={form.selected_asset_id}
              onChange={(event) =>
                update("selected_asset_id", event.target.value)
              }
            >
              <option value="">Выберите актив</option>
              {sortedCandidates.slice(0, 1000).map((row, index) => (
                <option
                  value={row.asset_id || ""}
                  key={row.asset_id || `${row.display_name}-${index}`}
                >
                  {[row.display_name, row.os_name, row.asset_id]
                    .filter(Boolean)
                    .join(" · ")}
                </option>
              ))}
            </select>
          </div>
          <div className="table-shell asset-candidates-shell">
            <table className="asset-candidates-table">
              <thead>
                <tr>
                  <SortableHeader
                    column="display_name"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    Актив
                  </SortableHeader>
                  <SortableHeader
                    column="os_name"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    ОС
                  </SortableHeader>
                  <SortableHeader
                    column="creation_time"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                    initialDirection="desc"
                  >
                    Создан
                  </SortableHeader>
                  <SortableHeader
                    column="update_time"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                    initialDirection="desc"
                  >
                    Обновлён
                  </SortableHeader>
                  <SortableHeader
                    column="asset_id"
                    sort={candidateSort}
                    onSort={toggleCandidateSort}
                  >
                    ID актива
                  </SortableHeader>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sortedCandidates.slice(0, 300).map((row, index) => (
                  <tr key={row.asset_id || `${row.display_name}-${index}`}>
                    <td>{row.display_name || "—"}</td>
                    <td>{row.os_name || "—"}</td>
                    <td>{formatDateTime(row.creation_time)}</td>
                    <td>{formatDateTime(row.update_time)}</td>
                    <td>
                      <code>{row.asset_id || "n/a"}</code>
                    </td>
                    <td>
                      <Button
                        variant="tiny"
                        disabled={!row.asset_id}
                        onClick={() =>
                          update("selected_asset_id", row.asset_id || "")
                        }
                      >
                        Выбрать
                      </Button>
                      <Button
                        variant="tiny"
                        disabled={
                          !row.asset_id ||
                          (!batchAssetIds.includes(row.asset_id) &&
                            batchAssetIds.length >= 2)
                        }
                        aria-pressed={batchAssetIds.includes(row.asset_id)}
                        onClick={() => toggleBatchAsset(row.asset_id)}
                      >
                        {batchAssetIds.includes(row.asset_id)
                          ? "Убрать из пакета"
                          : "В пакет"}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      ) : canBuildAssetCards && queryRaw ? (
        <details className="raw-details">
          <summary>Raw-ответ PDQL запроса активов</summary>
          <pre>{JSON.stringify(queryRaw, null, 2)}</pre>
        </details>
      ) : null}


      {assetWindowOpen ? (
        <PassportModal
          title="Карточка актива"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Закрыть"
          onClose={() => setAssetWindowOpen(false)}
        >
          <AssetCard
            card={selectedCard}
            loading={busy.assetCardBuild || busy.assetCardOpen}
            onOpenPassport={openAssetPassport}
          />
        </PassportModal>
      ) : null}
      {assetPassportWindowOpen ? (
        <PassportModal
          title="Паспорт уязвимости"
          className="asset-modal"
          overlayClassName="asset-modal-overlay"
          closeLabel="Назад к активу"
          onClose={() => setAssetPassportWindowOpen(false)}
        >
          {assetPassportError ? (
            <div className="passport-load-error" role="alert">
              Не удалось загрузить паспорт: {assetPassportError}
            </div>
          ) : null}
          <PassportCard
            row={selectedPassport}
            detail={assetPassportDetail}
            loading={busy.assetCardPassportDetail && !assetPassportDetail}
          />
        </PassportModal>
      ) : null}
      <ConfirmDialog
        open={Boolean(pendingCardDelete)}
        title="Удалить локальную карточку?"
        description={`Карточка «${pendingCardDelete?.display_name || pendingCardDelete?.hostname || pendingCardDelete?.asset_id || ""}» будет удалена только из PostgreSQL.`}
        impact={[
          "Актив в MP VM не изменится",
          "Карточку можно собрать заново из MP VM",
        ]}
        confirmLabel="Удалить из БД"
        busy={Boolean(
          pendingCardDelete &&
          busy[`assetCardDelete:${pendingCardDelete.asset_id}`],
        )}
        onClose={() => setPendingCardDelete(null)}
        onConfirm={() => deleteLocalCard(pendingCardDelete)}
      />
    </Panel>
  );
}

function filterAssetCandidates(rows, query) {
  const normalizedQuery = normalizeSearchText(query);
  if (!normalizedQuery) return rows;
  return rows.filter((row) =>
    buildAssetCandidateSearchText(row).includes(normalizedQuery),
  );
}

function buildAssetCandidateSearchText(row) {
  return normalizeSearchText(
    [
      row.asset_id,
      row.display_name,
      row.os_name,
      row.creation_time,
      row.update_time,
      JSON.stringify(row.raw_record || {}),
    ]
      .filter(Boolean)
      .join(" "),
  );
}

function assetCardJobStatusLabel(status) {
  return (
    {
      queued: "в очереди",
      running: "выполняется",
      cancelling: "останавливается",
      cancelled: "остановлена",
      completed: "завершена",
      failed: "ошибка",
      interrupted: "прервана перезапуском",
    }[status] ||
    status ||
    "неизвестно"
  );
}

function assetCardJobStageLabel(stage) {
  return (
    {
      queued: "ожидание",
      starting: "подготовка",
      collecting: "сбор данных",
      timeline: "timeline token",
      root: "корневой объект",
      tree_and_vulnerabilities: "дерево и уязвимости",
      tree_ready: "дерево собрано, загружаются уязвимости",
      vulnerabilities_ready: "уязвимости собраны, загружается дерево",
      assembling: "сборка результата",
      saving: "сохранение",
      cancelling: "остановка",
      cancelled: "остановлено",
      completed: "готово",
      failed: "ошибка",
      interrupted: "прервано",
    }[stage] ||
    stage ||
    "неизвестно"
  );
}
