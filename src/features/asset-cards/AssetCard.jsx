import React, { useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { recordFrontendEvent } from "../../diagnostics.js";
import { formatCount } from "../../shared/format.js";
import { severityLabel } from "../../shared/labels.js";
import { AssetConfigurationTab } from "./AssetConfigurationTab.jsx";
import { AssetVulnerabilitiesTabPaged } from "./AssetVulnerabilitiesTab.jsx";
import { KeyValue, PassportSection } from "../passports/PassportCard.jsx";
import { firstFilled } from "../../shared/values.js";

export function AssetCard({ card, loading, onOpenPassport }) {
  const raw = assetCardRaw(card);
  const root = card?.root || raw.root || {};
  const data = root.data || {};
  const stats = assetCardStats(card);
  const [activeTab, setActiveTab] = useState("summary");
  const tabIdPrefix = React.useId().replaceAll(":", "");
  const assetTabs = [
    ["summary", "Сводка"],
    ["vulnerabilities", "Уязвимости"],
    ["configuration", "Конфигурация"],
    ["history", "История"],
  ];
  const assetId = firstFilled(card?.asset_id, raw.asset_id, root.objectId);
  const assetType = firstFilled(card?.asset_type, raw.asset_type, root.type);
  const hostname = firstFilled(card?.hostname, data.hostname, root.displayName);
  const ipAddress = firstFilled(card?.ip_address, data.ipAddress);
  const fqdn = firstFilled(card?.fqdn, data.fqdn);
  const osLine = [
    firstFilled(card?.os_name, data.osName),
    firstFilled(card?.os_version, data.osVersion),
  ]
    .filter(Boolean)
    .join(" ");

  useEffect(() => {
    if (!card) return;
    setActiveTab("summary");
  }, [card?.asset_id]);

  useEffect(() => {
    if (!card) return undefined;
    const started = performance.now();
    const frame = window.requestAnimationFrame(() => {
      recordFrontendEvent(
        "ui.section.rendered",
        {
          section: `asset-card:${activeTab}`,
          asset_id: assetId,
          duration_ms: Math.round((performance.now() - started) * 100) / 100,
        },
        { section: activeTab },
      );
    });
    return () => window.cancelAnimationFrame(frame);
  }, [activeTab, assetId, card]);

  if (!card) {
    return (
      <div className="passport-placeholder">
        Соберите карточку или откройте сохранённую запись из БД.
      </div>
    );
  }

  return (
    <div className="asset-console">
      <div
        className="asset-tabs"
        role="tablist"
        aria-label="Разделы карточки актива"
      >
        {assetTabs.map(([id, label], index) => (
          <button
            type="button"
            role="tab"
            id={`${tabIdPrefix}-tab-${id}`}
            aria-controls={`${tabIdPrefix}-panel-${id}`}
            aria-selected={activeTab === id}
            tabIndex={activeTab === id ? 0 : -1}
            className={activeTab === id ? "is-active" : ""}
            onClick={() => setActiveTab(id)}
            onKeyDown={(event) => {
              if (
                !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)
              )
                return;
              event.preventDefault();
              const nextIndex =
                event.key === "Home"
                  ? 0
                  : event.key === "End"
                    ? assetTabs.length - 1
                    : (index +
                        (event.key === "ArrowRight" ? 1 : -1) +
                        assetTabs.length) %
                      assetTabs.length;
              setActiveTab(assetTabs[nextIndex][0]);
              const tabButtons =
                event.currentTarget.parentElement?.querySelectorAll(
                  '[role="tab"]',
                );
              tabButtons?.[nextIndex]?.focus();
            }}
            key={id}
          >
            {label}
          </button>
        ))}
      </div>
      {activeTab === "summary" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-summary`}
          aria-labelledby={`${tabIdPrefix}-tab-summary`}
        >
          <AssetSummaryTab
            assetId={assetId}
            assetType={assetType}
            hostname={hostname}
            fqdn={fqdn}
            ipAddress={ipAddress}
            osLine={osLine}
            root={root}
            stats={stats}
            loading={loading}
          />
        </div>
      ) : null}
      {activeTab === "history" ? <AssetHistoryTab assetId={assetId} /> : null}
      {activeTab === "vulnerabilities" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-vulnerabilities`}
          aria-labelledby={`${tabIdPrefix}-tab-vulnerabilities`}
        >
          {assetId ? (
            <AssetVulnerabilitiesTabPaged
              assetId={assetId}
              onOpenPassport={onOpenPassport}
            />
          ) : (
            <AssetSectionLoading loading={false} />
          )}
        </div>
      ) : null}
      {activeTab === "configuration" ? (
        <div
          className="asset-tabpanel"
          role="tabpanel"
          id={`${tabIdPrefix}-panel-configuration`}
          aria-labelledby={`${tabIdPrefix}-tab-configuration`}
        >
          {assetId ? (
            <AssetConfigurationTab assetId={assetId} card={card} />
          ) : (
            <AssetSectionLoading loading={false} />
          )}
        </div>
      ) : null}
    </div>
  );
}

function AssetSectionLoading({ loading }) {
  return (
    <div className="passport-placeholder">
      {loading
        ? "Раздел загружается..."
        : "Раздел будет загружен при открытии."}
    </div>
  );
}

function AssetHistoryTab({ assetId }) {
  const [state, setState] = useState({ loading: true, items: [], error: null });
  useEffect(() => {
    let active = true;
    api(`/api/asset-cards/${encodeURIComponent(assetId)}/history`)
      .then(
        (data) =>
          active &&
          setState({ loading: false, items: data.items || [], error: null }),
      )
      .catch(
        (error) => active && setState({ loading: false, items: [], error }),
      );
    return () => {
      active = false;
    };
  }, [assetId]);
  if (state.loading) return <div className="muted-text">Загрузка истории…</div>;
  if (state.error)
    return <div className="error-text">История пока недоступна.</div>;
  return (
    <div className="asset-history-list">
      {state.items.length ? (
        state.items.map((item) => (
          <PassportSection
            key={item.captured_at}
            title={new Date(item.captured_at).toLocaleString()}
          >
            <KeyValue
              label="Качество"
              value={`${item.quality?.status || "—"} (${item.quality?.score ?? "—"})`}
            />
            <KeyValue
              label="Изменений"
              value={formatCount(item.changes?.length || 0)}
            />
          </PassportSection>
        ))
      ) : (
        <span className="muted-text">
          История появится после следующего обновления карточки.
        </span>
      )}
    </div>
  );
}

function AssetSummaryTab({
  assetId,
  assetType,
  hostname,
  fqdn,
  ipAddress,
  osLine,
  root,
  stats,
  loading,
}) {
  const warnings = stats.warnings || [];
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <PassportSection title="Основная информация">
          <KeyValue label="Тип" value={assetType} />
          <KeyValue label="Имя хоста" value={hostname} />
          <KeyValue label="FQDN" value={fqdn} />
          <KeyValue label="IP" value={ipAddress} />
          <KeyValue label="ОС" value={osLine} />
          <KeyValue label="ID актива" value={assetId} />
          {loading ? <KeyValue label="Состояние" value="собирается" /> : null}
        </PassportSection>
        <PassportSection title="Предупреждения">
          {warnings.length ? (
            warnings
              .slice(0, 16)
              .map((warning) => <code key={warning}>{warning}</code>)
          ) : (
            <span className="muted-text">Предупреждений нет.</span>
          )}
        </PassportSection>
      </div>
      <div className="asset-summary-side">
        <div className="asset-summary-card">
          <span>Критичность</span>
          <strong>
            {root?.vulnerabilityLevel
              ? severityLabel(root.vulnerabilityLevel)
              : "—"}
          </strong>
        </div>
      </div>
    </div>
  );
}

function assetCardRaw(card) {
  return card || {};
}

export function assetCardStats(card) {
  const raw = assetCardRaw(card);
  return card?.stats || raw.stats || {};
}
