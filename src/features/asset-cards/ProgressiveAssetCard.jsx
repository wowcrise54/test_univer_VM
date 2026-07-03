import {
  memo,
  startTransition,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";

import { api } from "../../api/client.js";
import { formatCount } from "../../shared/format.js";


const cardCache = new Map();

export function invalidateAssetCardCache(assetId) {
  for (const key of cardCache.keys()) {
    if (key.startsWith(`${assetId}:`) || key === `overview:${assetId}`) cardCache.delete(key);
  }
}

function cached(key, loader) {
  if (cardCache.has(key)) return Promise.resolve(cardCache.get(key));
  const pending = loader().then((value) => {
    cardCache.set(key, value);
    return value;
  }).catch((error) => {
    cardCache.delete(key);
    throw error;
  });
  cardCache.set(key, pending);
  return pending;
}

function query(path, params = {}) {
  const search = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    if (value !== null && value !== undefined && value !== "") search.set(key, String(value));
  });
  return search.size ? `${path}?${search.toString()}` : path;
}

function display(value) {
  if (value === null || value === undefined || value === "") return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function flattenDocument(document, depth = 0, prefix = "") {
  if (!document || typeof document !== "object") return [];
  const source = document.data && typeof document.data === "object" ? document.data : document;
  return Object.entries(source)
    .filter(([key]) => !["raw", "raw_value", "raw_record", "node", "items"].includes(key))
    .flatMap(([key, value]) => {
      const path = prefix ? `${prefix}.${key}` : key;
      const row = { path, name: key, value, depth };
      if (depth >= 2 || !value || typeof value !== "object") return [row];
      return [row, ...flattenDocument(value, depth + 1, path)];
    });
}

function useOverview(assetId) {
  const [state, setState] = useState({ data: null, error: "", loading: true });
  useEffect(() => {
    const controller = new AbortController();
    setState({ data: null, error: "", loading: true });
    cached(`overview:${assetId}`, () => api(`/api/asset-cards/${encodeURIComponent(assetId)}/overview`, { signal: controller.signal }))
      .then((data) => setState({ data, error: "", loading: false }))
      .catch((error) => {
        if (error.name !== "AbortError") setState({ data: null, error: error.message || String(error), loading: false });
      });
    return () => controller.abort();
  }, [assetId]);
  return state;
}

export function ProgressiveAssetCard({ assetId, onOpenPassport }) {
  const overviewState = useOverview(assetId);
  const [activeTab, setActiveTab] = useState("summary");

  useEffect(() => setActiveTab("summary"), [assetId]);

  if (overviewState.loading) {
    return <div className="asset-progressive-skeleton" aria-live="polite"><span /><span /><span />Загрузка сводки карточки…</div>;
  }
  if (overviewState.error) return <div className="passport-load-error">Не удалось открыть карточку: {overviewState.error}</div>;

  const overview = overviewState.data;
  return (
    <div className="asset-console">
      <div className="asset-tabs" role="tablist" aria-label="Разделы карточки актива">
        {[["summary", "Сводка"], ["vulnerabilities", "Уязвимости"], ["configuration", "Конфигурация"]].map(([id, label]) => (
          <button
            type="button"
            className={activeTab === id ? "is-active" : ""}
            aria-selected={activeTab === id}
            onClick={() => startTransition(() => setActiveTab(id))}
            key={id}
          >
            {label}
          </button>
        ))}
      </div>
      {activeTab === "summary" ? <OverviewTab overview={overview} /> : null}
      {activeTab === "configuration" ? <ConfigurationTab assetId={assetId} version={overview.version} /> : null}
      {activeTab === "vulnerabilities" ? <VulnerabilitiesTab assetId={assetId} version={overview.version} onOpenPassport={onOpenPassport} /> : null}
    </div>
  );
}

const OverviewTab = memo(function OverviewTab({ overview }) {
  const asset = overview.asset || {};
  const root = overview.root || {};
  const stats = overview.stats || {};
  const rows = [
    ["asset_id", asset.asset_id],
    ["Type", asset.asset_type || root.type],
    ["Hostname", asset.hostname || root.data?.hostname || root.displayName],
    ["FQDN", asset.fqdn || root.data?.fqdn],
    ["IP", asset.ip_address || root.data?.ipAddress],
    ["ОС", [asset.os_name, asset.os_version].filter(Boolean).join(" ")],
  ];
  return (
    <div className="asset-summary-grid">
      <div className="asset-summary-main">
        <section className="passport-section">
          <h4>Основная информация</h4>
          {rows.filter(([, value]) => value).map(([label, value]) => (
            <div className="kv-row" key={label}><span>{label}</span><strong>{display(value)}</strong></div>
          ))}
        </section>
        <section className="passport-section">
          <h4>Снимок</h4>
          <div className="kv-row"><span>Обновлён</span><strong>{display(asset.last_seen)}</strong></div>
          <div className="kv-row"><span>Timeline</span><strong>{display(asset.token_timestamp)}</strong></div>
        </section>
      </div>
      <div className="asset-summary-side">
        {[["Коллекции", stats.collections], ["Узлы", stats.nodes], ["Строки data", stats.table_rows], ["Уязвимости", stats.vulnerabilities || stats.findings]].map(([label, value]) => (
          <div className="asset-summary-card" key={label}><span>{label}</span><strong>{formatCount(value || 0)}</strong></div>
        ))}
      </div>
    </div>
  );
});

function ConfigurationTab({ assetId, version }) {
  const [entries, setEntries] = useState([]);
  const [expanded, setExpanded] = useState(new Set());
  const [loadedParents, setLoadedParents] = useState(new Set());
  const [selected, setSelected] = useState(null);
  const [detail, setDetail] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const controllers = useRef(new Set());

  const loadChildren = useCallback(async (parentPath = null, cursor = null) => {
    const controller = new AbortController();
    controllers.current.add(controller);
    const cacheKey = `${assetId}:${version}:tree:${parentPath || "root"}:${cursor || "0"}`;
    try {
      const result = await cached(cacheKey, () => api(query(`/api/asset-cards/${encodeURIComponent(assetId)}/configuration/tree`, {
        parent_path: parentPath,
        cursor,
        limit: 200,
      }), { signal: controller.signal }));
      setEntries((current) => {
        const byPath = new Map(current.map((entry) => [entry.path, entry]));
        result.rows.forEach((entry) => byPath.set(entry.path, entry));
        return Array.from(byPath.values());
      });
      if (parentPath !== null) setLoadedParents((current) => new Set(current).add(parentPath));
      return result;
    } finally {
      controllers.current.delete(controller);
    }
  }, [assetId, version]);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError("");
    loadChildren()
      .then(async (rootResult) => {
        if (!alive) return;
        const root = rootResult.rows[0];
        if (root) {
          setSelected(root);
          setExpanded(new Set([root.path]));
          await loadChildren(root.path);
        }
      })
      .catch((requestError) => alive && requestError.name !== "AbortError" && setError(requestError.message || String(requestError)))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
      controllers.current.forEach((controller) => controller.abort());
    };
  }, [loadChildren]);

  useEffect(() => {
    if (!selected) return undefined;
    const controller = new AbortController();
    setDetail(null);
    const cacheKey = `${assetId}:${version}:detail:${selected.kind}:${selected.path}:0`;
    cached(cacheKey, () => api(query(`/api/asset-cards/${encodeURIComponent(assetId)}/configuration/detail`, {
      path: selected.path,
      kind: selected.kind,
      limit: 200,
      offset: 0,
    }), { signal: controller.signal }))
      .then(setDetail)
      .catch((requestError) => requestError.name !== "AbortError" && setError(requestError.message || String(requestError)));
    return () => controller.abort();
  }, [assetId, selected, version]);

  const toggle = async (entry) => {
    const next = new Set(expanded);
    if (next.has(entry.path)) next.delete(entry.path);
    else {
      next.add(entry.path);
      if (!loadedParents.has(entry.path)) await loadChildren(entry.path);
    }
    setExpanded(next);
  };

  const visible = useMemo(() => {
    const children = new Map();
    entries.forEach((entry) => {
      const key = entry.parent_path || "__root__";
      if (!children.has(key)) children.set(key, []);
      children.get(key).push(entry);
    });
    const output = [];
    const visit = (parent) => {
      (children.get(parent) || []).forEach((entry) => {
        output.push(entry);
        if (expanded.has(entry.path)) visit(entry.path);
      });
    };
    visit("__root__");
    return output;
  }, [entries, expanded]);

  if (loading) return <div className="asset-tab-loading">Загрузка структуры…</div>;
  if (error && !entries.length) return <div className="passport-load-error">{error}</div>;
  return (
    <div className="asset-config-layout">
      <aside className="asset-tree-pane">
        <div className="asset-tree">
          {visible.map((entry) => (
            <div className={selected?.path === entry.path ? "asset-tree-row is-selected" : "asset-tree-row"} style={{ "--depth": entry.depth || 0 }} key={entry.path}>
              <button type="button" className={entry.has_children ? "asset-tree-toggle" : "asset-tree-toggle is-empty"} onClick={() => entry.has_children && toggle(entry)}>
                {entry.has_children ? (expanded.has(entry.path) ? "▾" : "›") : ""}
              </button>
              <button type="button" className="asset-tree-label" onClick={() => setSelected(entry)}><span>{entry.label}</span><small>{entry.subtitle}</small></button>
              {entry.item_count ? <span className="asset-tree-meta">{formatCount(entry.item_count)}</span> : null}
            </div>
          ))}
        </div>
      </aside>
      <ConfigurationDetail detail={detail} selected={selected} assetId={assetId} version={version} />
    </div>
  );
}

function ConfigurationDetail({ detail, selected, assetId, version }) {
  const [rows, setRows] = useState([]);
  const [loadingMore, setLoadingMore] = useState(false);
  useEffect(() => setRows(detail?.rows || []), [detail]);
  if (!selected || !detail) return <section className="asset-detail-pane"><div className="asset-tab-loading">Загрузка раздела…</div></section>;
  const propertyRows = selected.kind === "collection" ? [] : flattenDocument(detail.entry);
  const tableRows = selected.kind === "collection" ? rows : propertyRows;
  const keys = selected.kind === "collection"
    ? Array.from(new Set(tableRows.flatMap((row) => Object.keys(row?.data || row || {})))).filter((key) => !key.startsWith("raw")).slice(0, 12)
    : ["name", "value"];
  const loadMore = async () => {
    setLoadingMore(true);
    try {
      const next = await cached(`${assetId}:${version}:detail:${selected.kind}:${selected.path}:${rows.length}`, () => api(query(`/api/asset-cards/${encodeURIComponent(assetId)}/configuration/detail`, {
        path: selected.path, kind: selected.kind, limit: 200, offset: rows.length,
      })));
      setRows((current) => [...current, ...(next.rows || [])]);
    } finally {
      setLoadingMore(false);
    }
  };
  return (
    <section className="asset-detail-pane asset-detail-pane--table">
      <div className="asset-detail-heading"><div><strong>{selected.label}</strong><span>Показано {formatCount(tableRows.length)} из {formatCount(detail.total)}</span></div><code>{selected.path}</code></div>
      <div className="table-shell asset-detail-table-shell">
        <table className="asset-detail-table"><thead><tr>{keys.map((key) => <th key={key}>{key}</th>)}</tr></thead><tbody>
          {tableRows.map((row, index) => {
            const source = selected.kind === "collection" ? (row.data || row) : row;
            return <tr key={row.path || row.object_id || index}>{keys.map((key) => <td key={key}>{display(source[key])}</td>)}</tr>;
          })}
        </tbody></table>
      </div>
      {selected.kind === "collection" && rows.length < detail.total ? <button className="asset-load-more" type="button" disabled={loadingMore} onClick={loadMore}>{loadingMore ? "Загрузка…" : "Показать ещё"}</button> : null}
    </section>
  );
}

function VulnerabilitiesTab({ assetId, version, onOpenPassport }) {
  const [data, setData] = useState(null);
  const [expanded, setExpanded] = useState(new Set());
  const [findings, setFindings] = useState({});
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    cached(`${assetId}:${version}:vulnerability-groups`, () => api(`/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/groups`, { signal: controller.signal }))
      .then(setData)
      .catch((requestError) => requestError.name !== "AbortError" && setError(requestError.message || String(requestError)));
    return () => controller.abort();
  }, [assetId, version]);

  const loadGroup = async (group, offset = 0) => {
    const key = `${group.source_type}:${group.collection_id}`;
    const result = await cached(`${assetId}:${version}:findings:${key}:${offset}`, () => api(query(`/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/findings`, {
      source: group.source_type, collection_id: group.collection_id, limit: 100, offset,
    })));
    setFindings((current) => ({ ...current, [key]: { ...result, rows: offset ? [...(current[key]?.rows || []), ...result.rows] : result.rows } }));
  };
  const toggle = async (group) => {
    const key = `${group.source_type}:${group.collection_id}`;
    const next = new Set(expanded);
    if (next.has(key)) next.delete(key);
    else {
      next.add(key);
      if (!findings[key]) await loadGroup(group);
    }
    setExpanded(next);
  };
  if (error) return <div className="passport-load-error">{error}</div>;
  if (!data) return <div className="asset-tab-loading">Загрузка групп уязвимостей…</div>;
  return (
    <section className="asset-vulnerability-pane">
      <div className="asset-vulnerability-heading"><div><strong>Уязвимости</strong><span>Групп: {formatCount(data.total)}</span></div></div>
      <div className="asset-vulnerability-table-shell"><table className="asset-vulnerability-table"><thead><tr><th>Уязвимость</th><th>CVSS</th><th>CVE</th></tr></thead><tbody>
        {data.groups.map((group) => {
          const key = `${group.source_type}:${group.collection_id}`;
          const groupData = findings[key];
          return [
            <tr className="asset-vulnerability-group" key={key}><td><button type="button" className="asset-vulnerability-toggle" onClick={() => toggle(group)}><span>{expanded.has(key) ? "⌄" : "›"}</span><strong>{group.name || group.collection_id}</strong> ({formatCount(group.vulnerability_count)})</button></td><td>{display(group.cvss_score)}</td><td /></tr>,
            ...(expanded.has(key) ? (groupData?.rows || []).map((finding, index) => {
              const passport = finding.passports?.[0];
              return <tr className="asset-vulnerability-finding" key={finding.vulnerability_instance_id || `${key}:${index}`}><td>{finding.name || "Без названия"}</td><td>{display(finding.cvss_score)}</td><td>{passport ? <button type="button" className="asset-vulnerability-passport-link" onClick={() => onOpenPassport?.(passport)}>{finding.cve_name || "Открыть паспорт"}</button> : (finding.cve_name || "—")}</td></tr>;
            }) : []),
            expanded.has(key) && groupData && groupData.rows.length < groupData.total ? <tr key={`${key}:more`}><td colSpan={3}><button type="button" className="asset-load-more" onClick={() => loadGroup(group, groupData.rows.length)}>Показать ещё</button></td></tr> : null,
          ];
        })}
      </tbody></table></div>
    </section>
  );
}
