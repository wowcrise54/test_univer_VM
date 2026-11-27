import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../api/client.js";
import { formatCount } from "../../shared/format.js";
import {
  SortableHeader,
  useSortedRows,
  useTableSort,
} from "../../shared/table.jsx";
import { Button } from "../../shared/ui.jsx";
import { firstFilled } from "../../shared/values.js";

const ASSET_CONFIG_TREE_LIMIT = 200;

const ASSET_CONFIG_DETAIL_LIMIT = 200;

function normalizeAssetTreeEntry(row) {
  return {
    ...row,
    parentPath: row.parentPath ?? row.parent_path ?? null,
    hasChildren: Boolean(row.hasChildren ?? row.has_children),
    depth: Number(row.depth || 0),
  };
}

function mergeAssetTreeEntries(current, incoming) {
  const byPath = new Map(current.map((entry) => [entry.path, entry]));
  incoming.forEach((entry) => {
    if (!entry?.path) return;
    byPath.set(entry.path, { ...(byPath.get(entry.path) || {}), ...entry });
  });
  return Array.from(byPath.values()).sort((left, right) => {
    if (left.path === "asset") return -1;
    if (right.path === "asset") return 1;
    return String(left.path || "").localeCompare(String(right.path || ""));
  });
}

const WINDOWS_ASSET_CARD_EXCLUDED_BRANCHES = new Set([
  "aclaccesslist",
  "aclaccesslists",
  "accountlockoutpolicy",
  "accountlockoutpolicies",
  "appliedaccesslist",
  "appliedaccesslists",
  "arp",
  "arptable",
  "arptables",
  "auditpolicy",
  "auditpolicies",
  "bios",
  "certificate",
  "certificates",
  "cpu",
  "cpus",
  "centralprocessor",
  "dnscache",
  "dnsclient",
  "dnsclientsettings",
  "dynamicrouting",
  "eventlog",
  "eventlogs",
  "eventlogsettings",
  "gpcredentials",
  "group",
  "groups",
  "hdd",
  "hdds",
  "harddisk",
  "harddisks",
  "hypervisor",
  "hypervisors",
  "ipv6",
  "ipv6settings",
  "lanmanserver",
  "lanmanworkstation",
  "logicaldisk",
  "logicaldisks",
  "motherboard",
  "nattable",
  "nattables",
  "neighbor",
  "neighbors",
  "neighbordevices",
  "networkadapter",
  "networkadapters",
  "networkconnection",
  "networkconnections",
  "oscandidates",
  "operatingsystemcandidates",
  "osfingerprints",
  "operatingsystemfingerprint",
  "passwordpolicy",
  "passwordpolicies",
  "pcidevice",
  "pcidevices",
  "peripheral",
  "peripherals",
  "peripheraldevices",
  "powermanagement",
  "printer",
  "printers",
  "roles",
  "trace",
  "traces",
  "traceroutes",
  "usbdevice",
  "usbdevices",
]);

function normalizeAssetCardBranch(value) {
  return String(value || "")
    .replace(/[_-]/g, "")
    .toLowerCase();
}

function isWindowsAssetCard(card) {
  const raw = card || {};
  const root = raw.root || {};
  const rootData = root.data || {};
  return [
    raw.asset_type,
    raw.assetType,
    raw.os_name,
    raw.osName,
    root.type,
    root.assetType,
    root.osName,
    rootData.osName,
    rootData.os_name,
    rootData.operatingSystem,
  ].some((value) =>
    String(value || "")
      .toLowerCase()
      .includes("windows"),
  );
}

function isExcludedWindowsAssetPath(path) {
  return String(path || "")
    .split(/[.[]/)
    .some((segment) =>
      WINDOWS_ASSET_CARD_EXCLUDED_BRANCHES.has(
        normalizeAssetCardBranch(segment),
      ),
    );
}

export function AssetConfigurationTab({ assetId, card }) {
  const [entries, setEntries] = useState([]);
  const [expandedPaths, setExpandedPaths] = useState(["asset"]);
  const [selectedPath, setSelectedPath] = useState("asset");
  const [loadedParents, setLoadedParents] = useState(new Set());
  const [loadingParents, setLoadingParents] = useState({});
  const [detailsByPath, setDetailsByPath] = useState({});
  const [loadingDetails, setLoadingDetails] = useState({});
  const [error, setError] = useState("");
  const expandedSet = useMemo(() => new Set(expandedPaths), [expandedPaths]);
  const selectedEntry = useMemo(
    () =>
      entries.find((entry) => entry.path === selectedPath) ||
      entries[0] ||
      null,
    [entries, selectedPath],
  );
  const visibleTreeEntries = useMemo(
    () =>
      entries.filter(
        (entry) =>
          (!isWindowsAssetCard(card) ||
            !isExcludedWindowsAssetPath(entry.path)) &&
          isAssetTreeEntryVisible(entry, expandedSet, entries),
      ),
    [card, entries, expandedSet],
  );

  const loadTree = useCallback(
    async (parentPath = null) => {
      if (!assetId) return;
      const key = parentPath || "";
      setLoadingParents((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        limit: String(ASSET_CONFIG_TREE_LIMIT),
      });
      if (parentPath) params.set("parent_path", parentPath);
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/configuration/tree?${params.toString()}`,
        );
        const nextEntries = (result.rows || [])
          .filter(
            (entry) =>
              !isWindowsAssetCard(card) ||
              !isExcludedWindowsAssetPath(entry.path),
          )
          .map(normalizeAssetTreeEntry);
        setEntries((current) => mergeAssetTreeEntries(current, nextEntries));
        setLoadedParents((current) => {
          const next = new Set(current);
          next.add(key);
          return next;
        });
      } catch (requestError) {
        setError(requestError.message || String(requestError));
      } finally {
        setLoadingParents((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId, card],
  );

  const loadDetail = useCallback(
    async (entry, offset = 0) => {
      if (!assetId || !entry?.path) return;
      const key = entry.path;
      setLoadingDetails((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        path: entry.path,
        kind: entry.kind || "",
        limit: String(ASSET_CONFIG_DETAIL_LIMIT),
        offset: String(offset),
      });
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/configuration/detail?${params.toString()}`,
        );
        setDetailsByPath((current) => {
          const previousRows = offset ? current[key]?.rows || [] : [];
          return {
            ...current,
            [key]: {
              ...result,
              rows: [...previousRows, ...(result.rows || [])],
            },
          };
        });
      } catch (requestError) {
        setError(requestError.message || String(requestError));
      } finally {
        setLoadingDetails((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId],
  );

  useEffect(() => {
    setEntries([]);
    setExpandedPaths(["asset"]);
    setSelectedPath("asset");
    setLoadedParents(new Set());
    setLoadingParents({});
    setDetailsByPath({});
    setLoadingDetails({});
    setError("");
    if (assetId) void loadTree(null);
  }, [assetId, loadTree]);

  useEffect(() => {
    if (!entries.length) return;
    setSelectedPath((current) =>
      entries.some((entry) => entry.path === current)
        ? current
        : entries[0].path,
    );
  }, [entries]);

  useEffect(() => {
    if (
      !selectedEntry ||
      detailsByPath[selectedEntry.path] ||
      loadingDetails[selectedEntry.path]
    )
      return;
    void loadDetail(selectedEntry, 0);
  }, [detailsByPath, loadDetail, loadingDetails, selectedEntry]);

  const toggleTreeEntry = useCallback(
    (path) => {
      const entry = entries.find((item) => item.path === path);
      setExpandedPaths((current) =>
        current.includes(path)
          ? current.filter((item) => item !== path)
          : [...current, path],
      );
      if (
        entry?.hasChildren &&
        !expandedSet.has(path) &&
        !loadedParents.has(path) &&
        !loadingParents[path]
      ) {
        void loadTree(path);
      }
    },
    [entries, expandedSet, loadedParents, loadingParents, loadTree],
  );

  const selectEntry = useCallback(
    (path) => {
      const entry = entries.find((item) => item.path === path);
      setSelectedPath(path);
      if (entry && !detailsByPath[path] && !loadingDetails[path]) {
        void loadDetail(entry, 0);
      }
    },
    [detailsByPath, entries, loadDetail, loadingDetails],
  );

  const detail = selectedEntry ? detailsByPath[selectedEntry.path] : null;
  const loadingDetail = selectedEntry
    ? Boolean(loadingDetails[selectedEntry.path])
    : false;

  return (
    <div className="asset-config-layout">
      {error ? (
        <div className="passport-load-error" role="alert">
          {error}
        </div>
      ) : null}
      <AssetTree
        entries={visibleTreeEntries}
        selectedPath={selectedEntry?.path}
        expandedSet={expandedSet}
        onToggle={toggleTreeEntry}
        onSelect={selectEntry}
      />
      <AssetConfigTablePaged
        entry={selectedEntry}
        detail={detail}
        loading={
          loadingDetail || Boolean(loadingParents[""] && !entries.length)
        }
        onLoadMore={() =>
          selectedEntry &&
          detail &&
          loadDetail(selectedEntry, detail.rows?.length || 0)
        }
      />
    </div>
  );
}

function AssetConfigTablePaged({ entry, detail, loading, onLoadMore }) {
  const [tableSort, toggleTableSort] = useTableSort();
  const table = detail || {
    rows: [],
    columns: [{ key: "value", title: "Value" }],
    total: 0,
    has_more: false,
  };
  const sortedRows = useSortedRows(table.rows || [], tableSort);
  if (!entry) {
    return (
      <section className="asset-detail-pane">
        <div className="empty-cell">
          {loading ? "Загрузка..." : "Выберите раздел слева."}
        </div>
      </section>
    );
  }

  return (
    <section
      className={`asset-detail-pane asset-detail-pane--${table.layout || "table"}`}
      aria-label={entry.label}
    >
      {loading && !detail ? (
        <div className="empty-cell">Загрузка...</div>
      ) : null}
      {table.layout === "properties" ? (
        <AssetPropertyList rows={table.rows || []} />
      ) : (
        <div className="table-shell asset-detail-table-shell">
          <table className="asset-detail-table">
            <thead>
              <tr>
                {(table.columns || []).map((column) => (
                  <SortableHeader
                    key={column.key}
                    column={column.key}
                    sort={tableSort}
                    onSort={toggleTableSort}
                  >
                    {column.title}
                  </SortableHeader>
                ))}
              </tr>
            </thead>
            <tbody>
              {sortedRows.length ? (
                sortedRows.map((row, rowIndex) => (
                  <tr key={row.key || rowIndex}>
                    {(table.columns || []).map((column) => (
                      <td key={column.key}>
                        {formatAssetCell(row[column.key])}
                      </td>
                    ))}
                  </tr>
                ))
              ) : (
                <tr>
                  <td
                    colSpan={(table.columns || []).length || 1}
                    className="empty-cell"
                  >
                    В выбранном разделе нет данных.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
      <div className="table-footer">
        <span>
          Показано {formatCount((table.rows || []).length)} из{" "}
          {formatCount(table.total || (table.rows || []).length)} строк.
        </span>
        {table.has_more ? (
          <Button variant="tiny" busy={loading} onClick={onLoadMore}>
            Загрузить ещё
          </Button>
        ) : null}
      </div>
    </section>
  );
}

function AssetTree({ entries, selectedPath, expandedSet, onToggle, onSelect }) {
  return (
    <aside className="asset-tree-pane">
      <div className="asset-tree">
        {entries.map((entry) => (
          <div
            className={
              selectedPath === entry.path
                ? "asset-tree-row is-selected"
                : "asset-tree-row"
            }
            style={{ "--depth": entry.depth }}
            key={entry.path}
          >
            <button
              type="button"
              className={
                entry.hasChildren
                  ? "asset-tree-toggle"
                  : "asset-tree-toggle is-empty"
              }
              onClick={() => entry.hasChildren && onToggle(entry.path)}
              aria-label={expandedSet.has(entry.path) ? "Свернуть" : "Раскрыть"}
            >
              {entry.hasChildren
                ? expandedSet.has(entry.path)
                  ? "▾"
                  : "›"
                : ""}
            </button>
            <button
              type="button"
              className="asset-tree-label"
              onClick={() => onSelect(entry.path)}
            >
              <span>{entry.label}</span>
              {entry.subtitle ? <small>{entry.subtitle}</small> : null}
            </button>
            {entry.meta ? (
              <span className="asset-tree-meta">{entry.meta}</span>
            ) : (
              <span className="asset-tree-search" aria-hidden="true" />
            )}
          </div>
        ))}
      </div>
    </aside>
  );
}

function AssetPropertyList({ rows }) {
  const [tableSort, toggleTableSort] = useTableSort();
  const visibleRows = useSortedRows(rows, tableSort, {
    title: (row) => row.title || row.name,
  }).slice(0, 1000);
  if (!visibleRows.length) {
    return <div className="empty-cell">В выбранном разделе нет данных.</div>;
  }

  return (
    <div className="table-shell asset-detail-table-shell">
      <table className="asset-detail-table asset-property-list">
        <thead>
          <tr>
            <SortableHeader
              column="title"
              sort={tableSort}
              onSort={toggleTableSort}
            >
              Название
            </SortableHeader>
            <SortableHeader
              column="value"
              sort={tableSort}
              onSort={toggleTableSort}
            >
              Значение
            </SortableHeader>
          </tr>
        </thead>
        <tbody>
          {visibleRows.map((row, index) => (
            <tr
              className="asset-property-row"
              style={{ "--depth": row.depth || 0 }}
              key={row.key || index}
            >
              <td className="asset-property-name">
                <span>{row.title || row.name}</span>
                {row.name && row.name !== row.title ? (
                  <small>{row.name}</small>
                ) : null}
              </td>
              <td>
                <strong>{formatAssetCell(row.value)}</strong>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function isAssetTreeEntryVisible(entry, expandedSet, entries) {
  if (!entry.parentPath) return true;
  const byPath = new Map(entries.map((item) => [item.path, item]));
  let parentPath = entry.parentPath;
  while (parentPath) {
    if (!expandedSet.has(parentPath)) return false;
    parentPath = byPath.get(parentPath)?.parentPath;
  }
  return true;
}

function isHiddenAssetTechnicalField(key) {
  const normalized = String(key || "")
    .replace(/[_-]/g, "")
    .toLowerCase();
  return (
    normalized === "type" ||
    normalized === "objectid" ||
    normalized.startsWith("raw")
  );
}

export function buildAssetPropertyRows({
  name,
  title,
  value,
  path,
  type = "",
  depth = 0,
}) {
  if (isAssetExpandableContainer(value)) {
    return buildNestedAssetPropertyRows({
      value,
      path,
      name,
      title,
      depth: depth + 1,
    });
  }
  const row = {
    key: path,
    title,
    name,
    type,
    value,
    path,
    depth,
  };
  return [row];
}

function buildNestedAssetPropertyRows({ value, path, name, title, depth }) {
  if (depth > 8 || value === undefined || value === null) return [];
  if (Array.isArray(value)) {
    return value.flatMap((item, index) =>
      buildAssetPropertyRows({
        name: `${name}[${index}]`,
        title: `${title} ${index + 1}`,
        value: item,
        path: `${path}[${index}]`,
        depth,
      }),
    );
  }
  if (typeof value !== "object" || "hasItems" in value) return [];

  const nested =
    value.data && typeof value.data === "object" ? value.data : value;
  return Object.entries(nested)
    .filter(([key]) => !isHiddenAssetTechnicalField(key))
    .flatMap(([key, item]) =>
      buildAssetPropertyRows({
        name: `${name}.${key}`,
        title: labelizeAssetKey(key),
        value: item,
        path: `${path}.${key}`,
        depth,
      }),
    );
}

function isAssetExpandableContainer(value) {
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && typeof value === "object" && !("hasItems" in value));
}

function labelizeAssetKey(key) {
  const labels = {
    ipAddress: "IP-адрес",
    fqdn: "Полное имя узла",
    hostname: "Имя узла",
    hostType: "Тип узла",
    macAddress: "MAC-адрес",
    osName: "Название ОС",
    osVersion: "Версия ОС",
    isVirtual: "Виртуальное устройство",
    displayName: "Название",
    objectId: "Идентификатор",
    type: "Тип",
  };
  return (
    labels[key] || String(key || "").replace(/([a-zа-яё])([A-ZА-ЯЁ])/g, "$1 $2")
  );
}

export function formatAssetCell(value) {
  if (value === undefined || value === null || value === "") return "—";
  if (typeof value === "boolean") return value ? "Да" : "Нет";
  if (typeof value === "number") return String(value);
  if (typeof value === "string") return value;
  if (Array.isArray(value)) return value.map(formatAssetCell).join(", ");
  if (typeof value === "object") {
    if ("hasItems" in value) return value.hasItems ? "Есть" : "Нет";
    return firstFilled(
      value.displayName,
      value.name,
      value.title,
      value.value,
      "—",
    );
  }
  return String(value);
}
