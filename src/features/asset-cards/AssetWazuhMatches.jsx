import { useEffect, useState } from "react";
import { api } from "../../api/client.js";
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

  const byCve = new Map();
  for (const match of result?.matches || []) {
    if (!byCve.has(match.cve)) {
      const passport = result.passports?.[match.passport_id];
      byCve.set(match.cve, {
        cve_name: match.cve,
        name: passport?.name || match.cve,
        cvss_score: passport?.cvss_score ?? null,
        passport_ids: [match.passport_id],
        packages: [],
      });
    }
    byCve.get(match.cve).packages.push(`${match.package} · ${match.version}`);
  }
  const findings = sortRows([...byCve.values()], sort, {
    cvss_score: (finding) =>
      finding.cvss_score === null ? null : Number(finding.cvss_score),
  });
  const visiblePage = Math.min(
    page,
    Math.max(0, Math.ceil(findings.length / PAGE_SIZE) - 1),
  );

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
              ? `Проверено по локальным правилам: ${result.evaluated_packages} из ${result.packages} пакетов. Дополнительных CVE: ${findings.length}.`
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
            <AssetVulnerabilityTableHeader
              sort={sort}
              onSort={(column, direction) => {
                setPage(0);
                toggleSort(column, direction);
              }}
            />
            <tbody>
              {findings.length ? (
                findings
                  .slice(visiblePage * PAGE_SIZE, (visiblePage + 1) * PAGE_SIZE)
                  .map((finding) => (
                    <AssetVulnerabilityFindingRow
                      key={finding.cve_name}
                      finding={finding}
                      onOpenPassport={onOpenPassport}
                    >
                      <small className="asset-docker-package-meta">
                        {finding.packages.join(", ")}
                      </small>
                    </AssetVulnerabilityFindingRow>
                  ))
              ) : (
                <tr>
                  <td colSpan={3} className="empty-cell">
                    Дополнительных уязвимостей Wazuh не найдено.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
          {findings.length > PAGE_SIZE ? (
            <div>
              <Button
                disabled={visiblePage === 0}
                onClick={() => setPage(visiblePage - 1)}
              >
                Назад
              </Button>
              <Button
                disabled={(visiblePage + 1) * PAGE_SIZE >= findings.length}
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
