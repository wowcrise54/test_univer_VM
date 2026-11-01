import { useEffect, useState } from "react";
import { api, downloadApiFile } from "../../api/client.js";
import { splitTokens } from "../../shared/format.js";
import {
  ActionMenu,
  Button,
  Disclosure,
  Field,
  Panel,
  Toggle,
} from "../../shared/ui.jsx";

export function ExportPanel({
  defaults,
  busy,
  runBusy,
  refreshAssets,
  showAlert,
  currentUser,
}) {
  const permissions = new Set(currentUser?.permissions || []);
  const canManageExports = permissions.has("imports_exports.manage");
  const [form, setForm] = useState({
    pdql: "",
    utc_offset: "+05:00",
    group_ids: "",
    asset_ids: "",
    report_asset_ids: "",
    include_nested_groups: true,
    import_results: true,
    delete_assets_after_export: false,
  });
  const [result, setResult] = useState("");
  const [importBusy, setImportBusy] = useState(false);
  const [reportAssetSearch, setReportAssetSearch] = useState("");
  const [reportAssetOptions, setReportAssetOptions] = useState([]);
  const [selectedReportAssetId, setSelectedReportAssetId] = useState("");
  const [reportAssetLookupBusy, setReportAssetLookupBusy] = useState(false);

  useEffect(() => {
    if (!defaults) return;
    setForm((value) => ({
      ...value,
      pdql: value.pdql || defaults.software_vuln_pdql || "",
      utc_offset: value.utc_offset || defaults.utc_offset || "+05:00",
    }));
  }, [defaults]);

  useEffect(() => {
    const query = reportAssetSearch.trim();
    if (!query) {
      setReportAssetOptions([]);
      setReportAssetLookupBusy(false);
      return undefined;
    }
    let alive = true;
    const timer = window.setTimeout(async () => {
      setReportAssetLookupBusy(true);
      try {
        const response = await api(
          `/api/asset-cards/local?q=${encodeURIComponent(query)}&limit=20&sort_by=display_name&sort_dir=asc`,
        );
        if (alive) setReportAssetOptions(response.rows || []);
      } catch {
        if (alive) setReportAssetOptions([]);
      } finally {
        if (alive) setReportAssetLookupBusy(false);
      }
    }, 250);
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [reportAssetSearch]);

  const update = (key, value) =>
    setForm((current) => ({ ...current, [key]: value }));
  const runExport = () =>
    runBusy("export", async () => {
      const payload = {
        pdql: form.pdql,
        utc_offset: form.utc_offset || null,
        group_ids: splitTokens(form.group_ids),
        asset_ids: splitTokens(form.asset_ids),
        include_nested_groups: form.include_nested_groups,
        import_results: form.import_results,
        delete_assets_after_export: form.delete_assets_after_export,
      };
      const response = await api("/api/exports/pdql", {
        method: "POST",
        body: JSON.stringify(payload),
      });
      setResult(JSON.stringify(response, null, 2));
      showAlert("Экспорт завершён.", "success");
      await refreshAssets();
    });

  const importCsvFile = async (event) => {
    const input = event.target;
    const file = input.files?.[0];
    if (!file) return;
    const body = new FormData();
    body.append("file", file);
    setImportBusy(true);
    try {
      const response = await api("/api/import/csv-file", {
        method: "POST",
        body,
      });
      setResult(JSON.stringify(response, null, 2));
      showAlert(`CSV загружен: ${file.name}`, "success");
      await refreshAssets();
    } catch (error) {
      showAlert(error.operatorMessage || error.message, "error");
    } finally {
      setImportBusy(false);
      input.value = "";
    }
  };

  const downloadVulnerabilityReport = (reportType) =>
    runBusy(`report-${reportType}`, async () => {
      const report = await downloadApiFile(
        `/api/reports/vulnerabilities/${reportType}/csv`,
        {
          method: "POST",
          body: JSON.stringify({
            asset_ids: [...new Set(splitTokens(form.report_asset_ids))],
          }),
        },
      );
      showAlert(`CSV-отчёт сформирован: ${report.filename}`, "success");
    });

  const downloadVulnerabilityXlsx = () =>
    runBusy("report-xlsx", async () => {
      const report = await downloadApiFile("/api/reports/vulnerabilities/xlsx", {
        method: "POST",
        body: JSON.stringify({ asset_id: selectedReportAssetId }),
      });
      showAlert(`XLSX-отчёт сформирован: ${report.filename}`, "success");
    });

  return (
    <>
      <Panel id="export-reports" title="Отчёты по уязвимостям">
        <div className="form-grid form-grid--two">
          <Field label="Актив для XLSX">
            <input
              aria-label="Поиск актива для XLSX-отчёта"
              value={reportAssetSearch}
              onChange={(event) => {
                setReportAssetSearch(event.target.value);
                setSelectedReportAssetId("");
              }}
              placeholder="IP, имя хоста или ID"
            />
            {reportAssetLookupBusy ? (
              <small className="muted-text">Поиск…</small>
            ) : null}
            {reportAssetOptions.length ? (
              <div
                className="report-asset-options"
                role="listbox"
                aria-label="Найденные активы"
              >
                {reportAssetOptions.map((asset) => {
                  const label =
                    asset.display_name || asset.hostname || asset.asset_id;
                  const details = [asset.ip_address, asset.hostname]
                    .filter(Boolean)
                    .join(" · ");
                  return (
                    <button
                      type="button"
                      role="option"
                      aria-selected={selectedReportAssetId === asset.asset_id}
                      className={`report-asset-option${selectedReportAssetId === asset.asset_id ? " is-selected" : ""}`}
                      key={asset.asset_id}
                      title={asset.asset_id}
                      onClick={() => {
                        setSelectedReportAssetId(asset.asset_id);
                        setReportAssetSearch(label);
                        setReportAssetOptions([]);
                      }}
                    >
                      <strong>{label}</strong>
                      <span>{details}</span>
                    </button>
                  );
                })}
              </div>
            ) : null}
          </Field>
          <Field label="ID активов для CSV">
            <textarea
              aria-label="Asset ID для отчёта"
              rows={2}
              value={form.report_asset_ids}
              onChange={(event) => update("report_asset_ids", event.target.value)}
              placeholder="ID через запятую"
            />
          </Field>
        </div>
        <div className="action-row report-downloads">
          <span className="selection-count">Скачать:</span>
          <Button
            variant="secondary"
            busy={busy["report-xlsx"]}
            disabled={!selectedReportAssetId}
            onClick={downloadVulnerabilityXlsx}
          >
            XLSX
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости ОС"
            busy={busy["report-os"]}
            onClick={() => downloadVulnerabilityReport("os")}
          >
            ОС
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости ПО"
            busy={busy["report-software"]}
            onClick={() => downloadVulnerabilityReport("software")}
          >
            ПО
          </Button>
          <Button
            variant="secondary"
            aria-label="Скачать уязвимости Docker"
            busy={busy["report-docker"]}
            onClick={() => downloadVulnerabilityReport("docker")}
          >
            Docker
          </Button>
        </div>
      </Panel>
      {canManageExports ? (
        <Panel id="export">
          <Disclosure
            className={
              form.delete_assets_after_export ? "disclosure--danger" : ""
            }
            title="PDQL-выгрузка"
            meta={
              form.delete_assets_after_export ? "Удаление в MP VM" : null
            }
          >
            <Field label="PDQL запрос">
              <textarea
                className="code-input"
                rows={8}
                value={form.pdql}
                onChange={(event) => update("pdql", event.target.value)}
              />
            </Field>
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
              <Toggle
                label="Включая вложенные группы"
                checked={form.include_nested_groups}
                onChange={(value) => update("include_nested_groups", value)}
              />
              <Toggle
                label="Сохранить локально"
                checked={form.import_results}
                onChange={(value) => update("import_results", value)}
              />
            </div>
            <div className="action-row export-run">
              <label
                className={`toggle${form.delete_assets_after_export ? " toggle--danger" : ""}`}
              >
                <input
                  type="checkbox"
                  checked={form.delete_assets_after_export}
                  onChange={(event) =>
                    update("delete_assets_after_export", event.target.checked)
                  }
                />
                <span>Удалить активы в MP VM после сохранения</span>
              </label>
              <Button
                variant={form.delete_assets_after_export ? "danger" : "primary"}
                busy={busy.export}
                onClick={runExport}
              >
                {form.delete_assets_after_export
                  ? "Экспортировать и удалить из MP VM"
                  : "Выполнить экспорт"}
              </Button>
              <ActionMenu label="Импорт">
                <label className="upload-button">
                  {importBusy ? "Загрузка…" : "Загрузить CSV"}
                  <input
                    className="visually-hidden"
                    type="file"
                    accept=".csv,text/csv"
                    disabled={importBusy}
                    onChange={importCsvFile}
                  />
                </label>
              </ActionMenu>
            </div>
            {result ? (
              <Disclosure title="Результат">
                <pre className="result-box">{result}</pre>
              </Disclosure>
            ) : null}
          </Disclosure>
        </Panel>
      ) : null}
    </>
  );
}
