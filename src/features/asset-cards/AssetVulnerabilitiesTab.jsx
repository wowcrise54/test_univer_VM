import React, { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../../api/client.js";
import { formatCount } from "../../shared/format.js";
import { sortRows, useTableSort } from "../../shared/table.jsx";
import { Button } from "../../shared/ui.jsx";
import {
  AssetVulnerabilityFindingRow,
  AssetVulnerabilityTableHeader,
  formatVulnerabilityScore,
} from "./AssetVulnerabilityTable.jsx";
import { AssetWazuhMatches } from "./AssetWazuhMatches.jsx";

const ASSET_VULNERABILITY_FINDING_LIMIT = 100;

function assetSourceKey(source, index) {
  return (
    source?.source ||
    source?.collection_type ||
    source?.title ||
    `source-${index}`
  );
}

function assetGroupKey(source, group, index) {
  return `${source?.source || group?.source || "source"}:${group?.collection_id || index}`;
}

function dockerPackageSections(rows) {
  const sections = new Map();
  rows.forEach((finding) => {
    const packageName = finding.package_name || "Пакет не определён";
    const packageVersion = finding.package_version || "";
    const fixedVersion = finding.fixed_version || "";
    const key = `${packageName}\u0000${packageVersion}\u0000${fixedVersion}`;
    if (!sections.has(key)) {
      sections.set(key, {
        key,
        package_name: packageName,
        package_version: packageVersion,
        fixed_version: fixedVersion,
        rows: [],
      });
    }
    sections.get(key).rows.push(finding);
  });
  return Array.from(sections.values());
}

function dockerGroupMetadata(group) {
  const containerMetadata = [
    group.docker_engine,
    group.container_id ? `Container ID: ${group.container_id}` : "",
    group.image_id ? `Image ID: ${group.image_id}` : "",
    group.digest && group.digest !== group.image_id
      ? `Digest: ${group.digest}`
      : "",
  ].filter(Boolean);
  const isContainerGroup = Boolean(
    group.container_name ||
    group.container_id ||
    group.docker_engine ||
    group.image_id,
  );

  if (isContainerGroup) {
    return (
      containerMetadata.join(" · ") || "Метаданные контейнера не определены"
    );
  }

  return (
    [
      [group.image_os_name, group.image_os_version].filter(Boolean).join(" "),
      group.digest,
    ]
      .filter(Boolean)
      .join(" · ") || "ОС образа не определена"
  );
}

export function AssetVulnerabilitiesTabPaged({ assetId, onOpenPassport }) {
  const [snapshot, setSnapshot] = useState({ header: {}, sources: [] });
  const [loadingGroups, setLoadingGroups] = useState(false);
  const [error, setError] = useState("");
  const [collapsedSources, setCollapsedSources] = useState([]);
  const [expandedGroups, setExpandedGroups] = useState([]);
  const [findingsByGroup, setFindingsByGroup] = useState({});
  const [loadingFindings, setLoadingFindings] = useState({});
  const [tableSort, toggleTableSort] = useTableSort();
  const [vulnerabilityView, setVulnerabilityView] = useState("regular");
  const allSources = Array.isArray(snapshot.sources) ? snapshot.sources : [];
  const dockerSource = allSources.find((source) => source.source === "docker");
  const dockerCount = (dockerSource?.groups || []).reduce(
    (total, group) => total + (Number(group.vulnerabilities_count) || 0),
    0,
  );
  const sources = allSources.filter((source) =>
    vulnerabilityView === "docker"
      ? source.source === "docker"
      : source.source !== "docker",
  );
  const header = snapshot.header || {};
  const collapsedSourceSet = useMemo(
    () => new Set(collapsedSources),
    [collapsedSources],
  );
  const expandedGroupSet = useMemo(
    () => new Set(expandedGroups),
    [expandedGroups],
  );
  const sourceKeys = useMemo(() => sources.map(assetSourceKey), [sources]);
  const loadedFindingCount = sources.reduce(
    (total, source) =>
      total +
      (source.groups || []).reduce(
        (groupTotal, group, groupIndex) =>
          groupTotal +
          (findingsByGroup[assetGroupKey(source, group, groupIndex)]?.rows
            ?.length || 0),
        0,
      ),
    0,
  );
  const sourceCount = (source) =>
    (source.groups || []).reduce(
      (total, group) => total + (Number(group.vulnerabilities_count) || 0),
      0,
    );

  useEffect(() => {
    let alive = true;
    setSnapshot({ header: {}, sources: [] });
    setCollapsedSources([]);
    setExpandedGroups([]);
    setFindingsByGroup({});
    setLoadingFindings({});
    setError("");
    setVulnerabilityView("regular");
    if (!assetId) return undefined;
    setLoadingGroups(true);
    api(
      `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/groups`,
    )
      .then((result) => {
        if (!alive) return;
        setSnapshot(result.vulnerabilities || { header: {}, sources: [] });
      })
      .catch((requestError) => {
        if (alive) setError(requestError.message || String(requestError));
      })
      .finally(() => {
        if (alive) setLoadingGroups(false);
      });
    return () => {
      alive = false;
    };
  }, [assetId]);

  const loadFindings = useCallback(
    async (source, group, offset = 0) => {
      const key = assetGroupKey(source, group, 0);
      if (!group?.collection_id || !assetId || loadingFindings[key]) return;
      setLoadingFindings((current) => ({ ...current, [key]: true }));
      const params = new URLSearchParams({
        source: source?.source || group.source || "",
        collection_id: group.collection_id,
        limit: String(ASSET_VULNERABILITY_FINDING_LIMIT),
        offset: String(offset),
      });
      try {
        const result = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/findings?${params.toString()}`,
        );
        setFindingsByGroup((current) => {
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
        setLoadingFindings((current) => ({ ...current, [key]: false }));
      }
    },
    [assetId, loadingFindings],
  );

  const toggleSource = useCallback((key) => {
    setCollapsedSources((current) =>
      current.includes(key)
        ? current.filter((item) => item !== key)
        : [...current, key],
    );
  }, []);

  const toggleGroup = useCallback(
    (source, group, groupIndex) => {
      const key = assetGroupKey(source, group, groupIndex);
      setExpandedGroups((current) => {
        if (current.includes(key))
          return current.filter((item) => item !== key);
        return [...current, key];
      });
      if (!expandedGroupSet.has(key) && !findingsByGroup[key]) {
        void loadFindings(source, group, 0);
      }
    },
    [expandedGroupSet, findingsByGroup, loadFindings],
  );

  const expandAll = () => setCollapsedSources([]);
  const collapseAll = () => {
    setCollapsedSources(sourceKeys);
    setExpandedGroups([]);
  };

  return (
    <section
      className="asset-vulnerability-pane"
      aria-label="Уязвимости актива"
    >
      <div
        className="asset-vulnerability-subtabs"
        role="tablist"
        aria-label="Тип уязвимостей"
      >
        <button
          type="button"
          role="tab"
          aria-selected={vulnerabilityView === "regular"}
          className={vulnerabilityView === "regular" ? "is-active" : ""}
          onClick={() => setVulnerabilityView("regular")}
        >
          ОС и ПО
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={vulnerabilityView === "docker"}
          className={vulnerabilityView === "docker" ? "is-active" : ""}
          onClick={() => setVulnerabilityView("docker")}
        >
          Docker-контейнеры · {formatCount(dockerCount)}
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={vulnerabilityView === "wazuh"}
          className={vulnerabilityView === "wazuh" ? "is-active" : ""}
          onClick={() => setVulnerabilityView("wazuh")}
        >
          Уязвимости, найденные Wazuh
        </button>
      </div>
      {vulnerabilityView === "wazuh" ? (
        <AssetWazuhMatches
          key={assetId}
          assetId={assetId}
          onOpenPassport={onOpenPassport}
        />
      ) : null}
      <div
        className="asset-vulnerability-mpvm"
        hidden={vulnerabilityView === "wazuh"}
      >
        <div className="asset-vulnerability-toolbar">
          {sources.map((source, index) => (
            <span key={assetSourceKey(source, index)}>
              {source.source === "os"
                ? "Уязвимости ОС"
                : source.source === "docker"
                  ? "Docker-контейнеры"
                  : "Уязвимости ПО"}
              : <strong>{formatCount(sourceCount(source))}</strong>
            </span>
          ))}
          {vulnerabilityView === "regular" ? (
            <span>
              Сетевые сервисы:{" "}
              <strong>
                {formatCount(
                  header.network_services_vulnerabilities_count || 0,
                )}
              </strong>
            </span>
          ) : null}
        </div>
        <div className="asset-vulnerability-heading">
          <div>
            <strong>
              {vulnerabilityView === "docker"
                ? "Уязвимости Docker-контейнеров"
                : "Уязвимости"}
            </strong>
            <span>
              Загружено {formatCount(loadedFindingCount)} из{" "}
              {formatCount(
                vulnerabilityView === "docker"
                  ? dockerCount
                  : header.os_soft_vulnerabilities_count || loadedFindingCount,
              )}{" "}
              уязвимостей.
            </span>
            {vulnerabilityView === "docker" &&
            dockerSource?.status === "fallback" ? (
              <span className="asset-docker-source-status">
                Docker-PDQL недоступен — использованы структурированные данные
                карточки.
              </span>
            ) : null}
          </div>
          {sourceKeys.length ? (
            <div className="asset-vulnerability-controls">
              <button type="button" onClick={expandAll}>
                Развернуть все
              </button>
              <button type="button" onClick={collapseAll}>
                Свернуть все
              </button>
            </div>
          ) : null}
        </div>
        {error ? (
          <div className="passport-load-error" role="alert">
            {error}
          </div>
        ) : null}
        <div
          className="asset-vulnerability-table-shell"
          tabIndex="0"
          aria-label="Прокручиваемый список уязвимостей"
        >
          <table className="asset-vulnerability-table">
            <AssetVulnerabilityTableHeader
              sort={tableSort}
              onSort={toggleTableSort}
            />
            <tbody>
              {sources.map((source, sourceIndex) => {
                const sourceKey = assetSourceKey(source, sourceIndex);
                const sourceCollapsed = collapsedSourceSet.has(sourceKey);
                const groups = sortRows(source.groups || [], tableSort, {
                  name: (group) => group.name,
                  cve_name: (group) => group.name,
                });
                return (
                  <React.Fragment key={sourceKey}>
                    <tr className="asset-vulnerability-source">
                      <td colSpan={3}>
                        <button
                          type="button"
                          className="asset-vulnerability-toggle"
                          aria-expanded={!sourceCollapsed}
                          onClick={() => toggleSource(sourceKey)}
                        >
                          <span
                            className="asset-vulnerability-caret"
                            aria-hidden="true"
                          >
                            {sourceCollapsed ? "›" : "⌄"}
                          </span>
                          <span>
                            {source.source === "docker"
                              ? "Docker-контейнеры"
                              : source.title ||
                                (source.source === "os"
                                  ? "Уязвимости ОС"
                                  : "Уязвимости программного обеспечения")}{" "}
                            ({formatCount(sourceCount(source))})
                          </span>
                        </button>
                      </td>
                    </tr>
                    {!sourceCollapsed
                      ? groups.map((group, groupIndex) => {
                          const key = assetGroupKey(source, group, groupIndex);
                          const expanded = expandedGroupSet.has(key);
                          const page = findingsByGroup[key] || {
                            rows: [],
                            total: Number(group.vulnerabilities_count) || 0,
                            has_more: false,
                          };
                          const rows = sortRows(page.rows || [], tableSort, {
                            name: (finding) => finding.name || finding.cve_name,
                          });
                          const displayedRows =
                            source.source === "docker"
                              ? dockerPackageSections(rows).flatMap(
                                  (section) => [
                                    { ...section, __dockerPackage: true },
                                    ...section.rows,
                                  ],
                                )
                              : rows;
                          return (
                            <React.Fragment key={key}>
                              <tr className="asset-vulnerability-group">
                                <td>
                                  <button
                                    type="button"
                                    className="asset-vulnerability-toggle"
                                    aria-expanded={expanded}
                                    onClick={() =>
                                      toggleGroup(source, group, groupIndex)
                                    }
                                  >
                                    <span
                                      className="asset-vulnerability-caret"
                                      aria-hidden="true"
                                    >
                                      {expanded ? "⌄" : "›"}
                                    </span>
                                    <span>
                                      <strong>
                                        {group.container_name ||
                                          group.name ||
                                          group.container_id ||
                                          "Без названия"}
                                      </strong>{" "}
                                      (
                                      {formatCount(
                                        group.vulnerabilities_count ||
                                          page.total ||
                                          0,
                                      )}
                                      )
                                    </span>
                                    {group.truncated ? (
                                      <small>Показана неполная коллекция</small>
                                    ) : null}
                                    {source.source === "docker" ? (
                                      <small className="asset-docker-image-meta">
                                        {dockerGroupMetadata(group)}
                                      </small>
                                    ) : null}
                                  </button>
                                </td>
                                <td>
                                  {formatVulnerabilityScore(group.cvss_score)}
                                </td>
                                <td />
                              </tr>
                              {expanded
                                ? displayedRows.map((finding, findingIndex) => {
                                    if (finding.__dockerPackage) {
                                      return (
                                        <tr
                                          className="asset-docker-package"
                                          key={`package-${finding.key}`}
                                        >
                                          <td colSpan={3}>
                                            <span className="asset-vulnerability-leaf">
                                              ›
                                            </span>
                                            <strong>
                                              {finding.package_name}
                                            </strong>
                                            {finding.package_version
                                              ? ` ${finding.package_version}`
                                              : ""}
                                            {finding.fixed_version
                                              ? ` → ${finding.fixed_version}`
                                              : ""}
                                            <small>
                                              {formatCount(finding.rows.length)}
                                            </small>
                                          </td>
                                        </tr>
                                      );
                                    }
                                    return (
                                      <AssetVulnerabilityFindingRow
                                        key={
                                          finding.vulnerability_instance_id ||
                                          `${group.collection_id}-${findingIndex}`
                                        }
                                        finding={finding}
                                        docker={source.source === "docker"}
                                        onOpenPassport={onOpenPassport}
                                      />
                                    );
                                  })
                                : null}
                              {expanded && loadingFindings[key] ? (
                                <tr>
                                  <td colSpan={3} className="empty-cell">
                                    Загрузка...
                                  </td>
                                </tr>
                              ) : null}
                              {expanded && page.has_more ? (
                                <tr>
                                  <td colSpan={3} className="table-footer">
                                    <Button
                                      variant="tiny"
                                      busy={loadingFindings[key]}
                                      onClick={() =>
                                        loadFindings(
                                          source,
                                          group,
                                          page.rows.length,
                                        )
                                      }
                                    >
                                      Загрузить ещё
                                    </Button>
                                  </td>
                                </tr>
                              ) : null}
                            </React.Fragment>
                          );
                        })
                      : null}
                  </React.Fragment>
                );
              })}
              {loadingGroups ? (
                <tr>
                  <td colSpan={3} className="empty-cell">
                    Загрузка...
                  </td>
                </tr>
              ) : null}
              {!loadingGroups &&
              !sources.some((source) => (source.groups || []).length) ? (
                <tr>
                  <td colSpan={3} className="empty-cell">
                    {vulnerabilityView === "docker"
                      ? dockerSource?.status === "unavailable"
                        ? "Docker-PDQL недоступен, структурированные данные о контейнерах не найдены."
                        : "Уязвимости Docker-контейнеров для этого актива не найдены."
                      : "Уязвимостей в сохранённом снимке нет."}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}
