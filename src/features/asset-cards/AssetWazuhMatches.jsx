import { Fragment, useEffect, useState } from "react";
import { api } from "../../api/client.js";
import { formatCount } from "../../shared/format.js";
import { sortRows, useTableSort } from "../../shared/table.jsx";
import { Button } from "../../shared/ui.jsx";
import { formatDateTime } from "../../shared/values.js";
import {
  AssetVulnerabilityFindingRow,
  AssetVulnerabilityTableHeader,
} from "./AssetVulnerabilityTable.jsx";

const PAGE_SIZE = 50;
const RESULT_POLL_MS = 30_000;

export function AssetWazuhMatches({ assetId, onOpenPassport }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(true);
  const [page, setPage] = useState(0);
  const [expandedPackages, setExpandedPackages] = useState(new Set());
  const [sort, toggleSort] = useTableSort("cve_name");

  useEffect(() => {
    let active = true;
    let timer;

    async function load() {
      try {
        const data = await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/wazuh-cti?additional_only=true`,
        );
        if (active) {
          setResult(data);
          setError("");
        }
      } catch (err) {
        if (active) setError(err.operatorMessage || err.message);
      } finally {
        if (active) {
          setBusy(false);
          timer = setTimeout(load, RESULT_POLL_MS);
        }
      }
    }

    load();
    return () => {
      active = false;
      clearTimeout(timer);
    };
  }, [assetId]);

  const uniqueCves = new Set();
  const byPackage = new Map();
  for (const match of result?.matches || []) {
    uniqueCves.add(match.cve);
    const key = JSON.stringify([match.package, match.version]);
    if (!byPackage.has(key)) {
      byPackage.set(key, {
        key,
        label: `${match.package} ${match.version}`,
        findings: new Map(),
      });
    }
    const passport = result.passports?.[match.passport_id];
    byPackage.get(key).findings.set(match.cve, {
      cve_name: match.cve,
      name: passport?.name || match.cve,
      cvss_score: passport?.cvss_score ?? null,
      passport_ids: [match.passport_id],
    });
  }
  const packages = sortRows([...byPackage.values()], {
    key: "label",
    direction: "asc",
  });
  const visiblePage = Math.min(
    page,
    Math.max(0, Math.ceil(packages.length / PAGE_SIZE) - 1),
  );

  function togglePackage(key) {
    setExpandedPackages((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <section
      className="asset-vulnerability-table-shell asset-vulnerability-wazuh"
      aria-label="Локальная проверка Wazuh CTI"
      tabIndex={0}
    >
      {busy ? (
        <p role="status">Загружаем результаты сверки Wazuh CTI…</p>
      ) : null}
      {error ? <p role="alert">{error}</p> : null}
      {result?.pending ? (
        <p role="status">Карточка ожидает фоновой сверки по Wazuh CTI.</p>
      ) : null}
      {result && !result.pending ? (
        <>
          <p role="status">
            {result.platform
              ? `Проверено по локальным правилам: ${result.evaluated_packages} из ${result.packages} пакетов. Дополнительных CVE: ${uniqueCves.size}.`
              : "Для выпуска этой ОС локальное сопоставление недоступно."}
            {result.platform && !result.inventory_complete
              ? " Инвентарь пакетов неполный."
              : ""}
            {result.unknown_assessments
              ? ` Неоднозначных проверок: ${result.unknown_assessments}.`
              : ""}
            {result.inventory_at
              ? ` Дата карточки: ${formatDateTime(result.inventory_at)}.`
              : ""}
            {result.checked_at
              ? ` Последняя сверка: ${formatDateTime(result.checked_at)}.`
              : ""}
          </p>
          <table className="asset-vulnerability-table">
            <AssetVulnerabilityTableHeader sort={sort} onSort={toggleSort} />
            <tbody>
              {packages.length ? (
                packages
                  .slice(visiblePage * PAGE_SIZE, (visiblePage + 1) * PAGE_SIZE)
                  .map(({ key, label, findings }) => {
                    const expanded = expandedPackages.has(key);
                    return (
                      <Fragment key={key}>
                        <tr className="asset-vulnerability-group">
                          <td colSpan={3}>
                            <button
                              type="button"
                              className="asset-vulnerability-toggle"
                              aria-expanded={expanded}
                              onClick={() => togglePackage(key)}
                            >
                              <span
                                className="asset-vulnerability-caret"
                                aria-hidden="true"
                              >
                                {expanded ? "⌄" : "›"}
                              </span>
                              <span>{label}</span>
                              <small>{formatCount(findings.size)} CVE</small>
                            </button>
                          </td>
                        </tr>
                        {expanded &&
                          sortRows([...findings.values()], sort, {
                            cvss_score: (finding) =>
                              finding.cvss_score === null
                                ? null
                                : Number(finding.cvss_score),
                          }).map((finding) => (
                            <AssetVulnerabilityFindingRow
                              key={finding.cve_name}
                              finding={finding}
                              onOpenPassport={onOpenPassport}
                            />
                          ))}
                      </Fragment>
                    );
                  })
              ) : (
                <tr>
                  <td colSpan={3} className="empty-cell">
                    Дополнительных уязвимостей Wazuh не найдено.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {packages.length > PAGE_SIZE ? (
            <div>
              <Button
                disabled={visiblePage === 0}
                onClick={() => setPage(visiblePage - 1)}
              >
                Назад
              </Button>
              <Button
                disabled={(visiblePage + 1) * PAGE_SIZE >= packages.length}
                onClick={() => setPage(visiblePage + 1)}
              >
                Далее
              </Button>
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
