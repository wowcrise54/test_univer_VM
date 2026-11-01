import React, { useMemo } from "react";
import { createPortal } from "react-dom";
import { formatCount } from "../../shared/format.js";
import { severityLabel } from "../../shared/labels.js";
import { Button, useDialogAccessibility } from "../../shared/ui.jsx";
import { firstFilled } from "../../shared/values.js";

export function PassportModal({
  children,
  onClose,
  title = "Паспорт уязвимости",
  className = "",
  overlayClassName = "",
  closeLabel = "Закрыть",
}) {
  const titleId = React.useId();
  const dialogRef = useDialogAccessibility(true, onClose);
  const modal = (
    <div className={`passport-modal ${overlayClassName}`} role="presentation">
      <div className="passport-modal__backdrop" onClick={onClose} />
      <div
        ref={dialogRef}
        className={`passport-modal__window ${className}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
      >
        <div className="passport-modal__bar">
          <strong id={titleId}>{title}</strong>
          <Button variant="ghost" onClick={onClose}>
            {closeLabel}
          </Button>
        </div>
        {children}
      </div>
    </div>
  );
  return typeof document === "undefined"
    ? modal
    : createPortal(modal, document.body);
}

export function PassportCard({ row, detail, loading }) {
  const raw = detail || row?.raw_detail || row?.raw_record || {};
  const model = useMemo(() => buildPassportModel(row, raw), [row, raw]);

  if (!row && !detail) {
    return (
      <div className="passport-placeholder">
        Выберите строку в таблице, чтобы открыть карточку паспорта уязвимости.
      </div>
    );
  }

  return (
    <div className="asset-console">
      <div
        className="asset-tabs"
        role="tablist"
        aria-label="Разделы карточки паспорта"
      >
        <button
          type="button"
          role="tab"
          id="passport-summary-tab"
          aria-controls="passport-summary-panel"
          className="is-active"
          aria-selected="true"
        >
          Сводка
        </button>
      </div>
      <div
        className="passport-summary-scroll"
        role="tabpanel"
        id="passport-summary-panel"
        aria-labelledby="passport-summary-tab"
      >
        <PassportSummaryTab model={model} row={row} loading={loading} />
      </div>
    </div>
  );
}

function PassportSummaryTab({ model, row, loading }) {
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <PassportSection title="Основная информация">
          <KeyValue label="Критичность" value={severityLabel(model.severity)} />
          <KeyValue label="Оценка" value={model.score} />
          <KeyValue label="Внешний ID" value={row?.external_id} />
          <KeyValue label="ID паспорта" value={row?.internal_id} />
          <KeyValue label="Пакет" value={model.packageLine} />
          <KeyValue
            label="Дата публикации"
            value={formatPassportDateTime(model.issueTime)}
          />
        </PassportSection>
        <PassportSection title="Описание">
          <p>
            {model.description ||
              "Описания нет."}
          </p>
        </PassportSection>
        <PassportSection title="Как исправить">
          <p>
            {model.remediation ||
              "Рекомендации нет."}
          </p>
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>CVE</span>
          <strong>{formatCount(model.cves.length)}</strong>
        </div>
        <div className="asset-summary-card">
          <span>Деталь</span>
          <strong>
            {loading
              ? "загрузка"
              : row?.has_detail || row?.raw_detail
                ? "в БД"
                : "нет"}
          </strong>
        </div>
        <PassportSection title="CVE">
          {model.cves.length ? (
            model.cves.slice(0, 16).map((item) =>
              item.url ? (
                <a
                  href={item.url}
                  target="_blank"
                  rel="noreferrer"
                  key={item.display_name || item.url}
                >
                  {item.display_name || item.url}
                </a>
              ) : (
                <code key={item.display_name}>{item.display_name}</code>
              ),
            )
          ) : (
            <span className="muted-text">CVE не найдены.</span>
          )}
        </PassportSection>
        <PassportSection title="Ссылки">
          {model.links.length ? (
            model.links.slice(0, 12).map((link) => (
              <a href={link} target="_blank" rel="noreferrer" key={link}>
                {link}
              </a>
            ))
          ) : (
            <span className="muted-text">Ссылки не найдены.</span>
          )}
        </PassportSection>
        <PassportSection title="Идентификаторы">
          {model.identifiers.length ? (
            model.identifiers.map((id) => <code key={id}>{id}</code>)
          ) : (
            <span className="muted-text">Идентификаторы не найдены.</span>
          )}
        </PassportSection>
      </div>
    </div>
  );
}

function buildPassportModel(row, raw) {
  const title = firstFilled(
    readPath(raw, "name"),
    readPath(raw, "displayName"),
    readPath(raw, "title"),
    readPath(raw, "vulnerability.name"),
    row?.name,
  );
  const score = firstFilled(
    readPath(raw, "score"),
    readPath(raw, "cvss3Score"),
    readPath(raw, "cvss.score"),
    row?.score,
  );
  const severity = firstFilled(
    readPath(raw, "severityRating"),
    readPath(raw, "severity"),
    row?.severity,
  );
  const cves = mergeCves(row?.cves || [], collectCves(raw));
  const links = collectLinks(raw, cves);
  const identifiers = collectIdentifiers(raw, cves, row);
  const description = firstText(
    readPath(raw, "description"),
    readPath(raw, "vulnerabilityDescription"),
    readPath(raw, "details.description"),
    readPath(raw, "localizedDescription"),
  );
  const remediation = firstText(
    readPath(raw, "howToFix"),
    readPath(raw, "solution"),
    readPath(raw, "recommendation"),
    readPath(raw, "remediation"),
    readPath(raw, "fixDescription"),
  );
  const issueTime = firstFilled(
    readPath(raw, "issueTime"),
    readPath(raw, "publishedAt"),
    row?.issue_time,
  );
  const packageLine = [
    firstFilled(readPath(raw, "packageId"), row?.package_id),
    firstFilled(readPath(raw, "packageVersion"), row?.package_version),
  ]
    .filter(Boolean)
    .join(" / ");

  return {
    title,
    score,
    severity,
    cves,
    links,
    identifiers,
    description,
    remediation,
    issueTime,
    packageLine,
  };
}

export function PassportSection({ title, children }) {
  return (
    <section className="passport-section">
      <h4>{title}</h4>
      {children}
    </section>
  );
}

export function KeyValue({ label, value }) {
  if (!value) return null;
  return (
    <div className="kv-row">
      <span>{label}</span>
      <strong>{String(value)}</strong>
    </div>
  );
}

function readPath(source, path) {
  if (!source || typeof source !== "object") return undefined;
  return path.split(".").reduce((value, key) => {
    if (!value || typeof value !== "object") return undefined;
    return value[key];
  }, source);
}

function firstText(...values) {
  for (const value of values) {
    const text = textValue(value);
    if (text) return text;
  }
  return "";
}

function textValue(value) {
  if (value === undefined || value === null || value === "") return "";
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean")
    return String(value);
  if (Array.isArray(value))
    return value.map(textValue).filter(Boolean).join("\n");
  if (typeof value === "object") {
    return (
      firstFilled(
        value.displayName,
        value.name,
        value.title,
        value.value,
        value.text,
        value.description,
      ) || ""
    );
  }
  return "";
}

function formatPassportDateTime(value) {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString("ru-RU");
}

function normalizeCveItem(item) {
  if (!item) return null;
  if (typeof item === "string") return { display_name: item, url: null };
  if (typeof item !== "object") return null;
  const displayName = firstFilled(
    item.display_name,
    item.displayName,
    item.name,
    item.id,
    item.value,
  );
  return displayName || item.url
    ? { display_name: displayName, url: item.url || null }
    : null;
}

function mergeCves(...groups) {
  const seen = new Set();
  const result = [];
  for (const group of groups) {
    for (const item of group || []) {
      const normalized = normalizeCveItem(item);
      if (!normalized) continue;
      const key = `${normalized.display_name || ""}|${normalized.url || ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      result.push(normalized);
    }
  }
  return result;
}

function collectCves(raw) {
  const candidates = [
    readPath(raw, "cves"),
    readPath(raw, "CVEs"),
    readPath(raw, "cve"),
    readPath(raw, "cveIds"),
    readPath(raw, "identifiers"),
    readPath(raw, "databaseIdentifiers"),
    readPath(raw, "vulnerability.cves"),
  ];
  const result = [];
  for (const value of candidates) {
    if (Array.isArray(value)) {
      result.push(...value);
    } else if (value) {
      result.push(value);
    }
  }
  return result;
}

function collectLinks(raw, cves) {
  const urls = new Set();
  for (const cve of cves || []) {
    if (cve.url) urls.add(cve.url);
  }
  collectUrls(raw, urls);
  return Array.from(urls);
}

function collectUrls(value, urls, depth = 0) {
  if (depth > 8 || value === undefined || value === null) return;
  if (typeof value === "string") {
    if (/^https?:\/\//i.test(value)) urls.add(value);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item) => collectUrls(item, urls, depth + 1));
    return;
  }
  if (typeof value === "object") {
    Object.values(value).forEach((item) => collectUrls(item, urls, depth + 1));
  }
}

function collectIdentifiers(raw, cves, row) {
  const values = new Set();
  [row?.external_id, row?.internal_id]
    .filter(Boolean)
    .forEach((value) => values.add(String(value)));
  for (const cve of cves || []) {
    if (cve.display_name) values.add(cve.display_name);
  }
  const rawIds = [
    readPath(raw, "id"),
    readPath(raw, "internalId"),
    readPath(raw, "cwe"),
    readPath(raw, "cwes"),
    readPath(raw, "identifiers"),
    readPath(raw, "databaseIdentifiers"),
  ];
  for (const value of rawIds) {
    if (Array.isArray(value)) {
      value
        .map(textValue)
        .filter(Boolean)
        .forEach((item) => values.add(item));
    } else {
      const text = textValue(value);
      if (text) values.add(text);
    }
  }
  return Array.from(values).slice(0, 40);
}
