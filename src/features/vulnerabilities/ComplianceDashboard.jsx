import { useState } from "react";
import { downloadApiFile } from "../../api/client.js";
import { formatCount } from "../../shared/format.js";
import { Button } from "../../shared/ui.jsx";
import { useComplianceDashboard } from "./useComplianceDashboard.js";

const today = () => new Date().toISOString().slice(0, 10);
const categoryLabel = (value) => ({ user_device: "Пользовательское устройство", server: "Сервер", unclassified: "Не классифицирован" })[value] || value || "—";
const value = (input) => input ?? "—";

export function ComplianceDashboard({ enabled, showAlert }) {
  const [scope, setScope] = useState("internet");
  const [assessmentDate, setAssessmentDate] = useState(today);
  const [downloading, setDownloading] = useState("");
  const { summaryQuery, findingsQuery, staleQuery } = useComplianceDashboard({ scope, assessmentDate, enabled });
  const summary = summaryQuery.data || {};
  const findings = findingsQuery.data?.rows || [];
  const stale = staleQuery.data?.rows || [];
  const pending = summaryQuery.isPending || findingsQuery.isPending || staleQuery.isPending;
  const error = summaryQuery.error || findingsQuery.error || staleQuery.error;

  const refresh = () => {
    summaryQuery.refetch();
    findingsQuery.refetch();
    staleQuery.refetch();
  };
  const download = async (format) => {
    setDownloading(format);
    try {
      await downloadApiFile(`/api/reports/vulnerabilities/compliance/${scope}/${format}`, {
        method: "POST",
        body: JSON.stringify({ assessment_date: assessmentDate }),
      });
      showAlert(`Отчёт ${format.toUpperCase()} загружен.`, "success");
    } catch (downloadError) {
      showAlert(downloadError.operatorMessage || downloadError.message, "error");
    } finally {
      setDownloading("");
    }
  };

  return (
    <section className="compliance-dashboard" aria-labelledby="compliance-title">
      <header className="compliance-toolbar">
        <div>
          <h3 id="compliance-title">Контроль критических уязвимостей</h3>
          <p>{scope === "internet" ? "Активы в диапазоне 10.255.0.0/16" : "Пользовательские устройства и серверы по типу актива"}</p>
        </div>
        <div className="compliance-actions">
          <div className="compliance-segments" role="group" aria-label="Контур отчёта">
            <button type="button" className={scope === "internet" ? "is-active" : ""} onClick={() => setScope("internet")}>Внешний контур</button>
            <button type="button" className={scope === "organization" ? "is-active" : ""} onClick={() => setScope("organization")}>Организация</button>
          </div>
          <label>Дата оценки<input type="date" value={assessmentDate} onChange={(event) => setAssessmentDate(event.target.value)} /></label>
          <Button variant="secondary" onClick={refresh}>Обновить</Button>
          <Button busy={downloading === "pdf"} onClick={() => download("pdf")}>PDF</Button>
          <Button busy={downloading === "xlsx"} onClick={() => download("xlsx")}>XLSX</Button>
        </div>
      </header>
      {error ? <div className="vulnerability-error" role="alert"><strong>Не удалось загрузить данные</strong><span>{error.operatorMessage || error.message}</span></div> : pending ? <div className="vulnerability-loading" role="status">Загружаю контрольный срез…</div> : <>
        <div className="compliance-metrics">
          <Metric label="Активов в контуре" count={summary.assets_total} />
          <Metric label="Свежие результаты" count={summary.fresh_assets} />
          <Metric label="Критические находки" count={summary.critical_findings} critical />
          <Metric label="Не соответствует свежести" count={summary.stale_assets} warning />
        </div>
        <ReportTable title="Критические уязвимости" empty="Критические уязвимости на свежих результатах не обнаружены." headers={["Актив", "IP", "Тип актива", "Категория", "Дата сканирования", "CVE/ID", "CVSS"]} rows={findings.map((row) => [row.display_name || row.asset_id, row.ip_address, row.asset_type, categoryLabel(row.asset_category), row.scan_at, row.cve || row.vulnerability_id, row.cvss_score])} />
        <ReportTable title="Не соответствует требованиям по свежести" empty="Все активы имеют результаты сканирования не старше 30 дней." headers={["Актив", "IP", "Тип актива", "Категория", "Дата сканирования", "Возраст, дней", "Причина"]} rows={stale.map((row) => [row.display_name || row.asset_id, row.ip_address, row.asset_type, categoryLabel(row.asset_category), row.scan_at, row.age_days, row.freshness_reason])} />
      </>}
    </section>
  );
}

function Metric({ label, count, critical, warning }) { return <article className={`compliance-metric${critical ? " is-critical" : ""}${warning ? " is-warning" : ""}`}><span>{label}</span><strong>{formatCount(count || 0)}</strong></article>; }
function ReportTable({ title, headers, rows, empty }) { return <section className="compliance-table"><h4>{title}</h4>{rows.length ? <div className="table-scroll"><table><thead><tr>{headers.map((header) => <th key={header}>{header}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr key={`${row[0]}-${index}`}>{row.map((cell, cellIndex) => <td key={cellIndex}>{value(cell)}</td>)}</tr>)}</tbody></table></div> : <p className="vulnerability-empty">{empty}</p>}</section>; }
