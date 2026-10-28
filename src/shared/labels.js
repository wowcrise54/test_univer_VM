// Russian labels for values that arrive from the API as machine keys.
// Unknown keys fall back to the raw value so new statuses stay visible.

export const SEVERITY_LABELS = {
  critical: "Критическая",
  high: "Высокая",
  medium: "Средняя",
  low: "Низкая",
  none: "Не указана",
  empty: "Не указана",
  unknown: "Не указана",
  unrated: "Не указана",
};

export function severityLabel(value) {
  return (
    SEVERITY_LABELS[String(value || "none").toLowerCase()] ||
    value ||
    "Не указана"
  );
}

export function severityClass(value) {
  const normalized = String(value || "").toLowerCase();
  return ["critical", "high", "medium", "low"].includes(normalized)
    ? normalized
    : "none";
}

export const REMEDIATION_STATUS_LABELS = {
  open: "Открыта",
  in_progress: "В работе",
  risk_accepted: "Риск принят",
  false_positive: "Ложное срабатывание",
  resolved: "Устранена",
};

export function remediationStatusLabel(status) {
  if (!status || status === "missing") return "Не создана";
  return REMEDIATION_STATUS_LABELS[status] || status;
}

export function operationStatusLabel(status) {
  return (
    {
      queued: "В очереди",
      running: "Выполняется",
      cancelling: "Останавливается",
      recovering: "Восстанавливается",
      completed: "Завершено",
      completed_with_errors: "С ошибками",
      failed: "Ошибка",
      cancelled: "Отменено",
      interrupted: "Прервано",
      needs_attention: "Требует внимания",
    }[status] || status
  );
}

export function operationKindLabel(kind) {
  return (
    {
      automation_run: "Запуск по расписанию",
      scan_postprocess: "Обработка результатов сканирования",
      asset_card_build: "Карточка актива",
      asset_card_bulk_refresh: "Массовое обновление карточек",
      asset_search_reindex: "Индексация карточек",
      passport_detail_sync: "Детали паспортов",
      pdql_export: "PDQL-экспорт",
      asset_removal: "Удаление активов",
      task_delete: "Удаление задачи MP VM",
    }[kind] || kind
  );
}

export function searchTypeLabel(type) {
  return (
    {
      asset: "Актив",
      vulnerability: "Уязвимость",
      task: "Задача",
      case: "Кейс",
      operation: "Операция",
      automation: "Расписание",
      coverage: "Покрытие",
    }[type] || type
  );
}

export function campaignStatusLabel(status) {
  return (
    {
      draft: "Черновик",
      active: "Активна",
      completed: "Завершена",
      cancelled: "Отменена",
    }[status] || status
  );
}
