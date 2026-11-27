import { useState } from "react";
import { api } from "../../api/client.js";
import { Button } from "../../shared/ui.jsx";
import { formatDateTime } from "../../shared/values.js";

const PAGE_SIZE = 50;

export function AssetWazuhMatches({ assetId, onOpenPassport }) {
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(0);

  async function check() {
    setBusy(true);
    setError("");
    setResult(null);
    setPage(0);
    try {
      setResult(
        await api(
          `/api/asset-cards/${encodeURIComponent(assetId)}/vulnerabilities/wazuh-cti`,
        ),
      );
    } catch (err) {
      setError(err.operatorMessage || err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Локальная проверка Wazuh CTI">
      <Button onClick={check} busy={busy} disabled={busy}>
        Проверить по Wazuh CTI
      </Button>
      {error ? <p role="alert">{error}</p> : null}
      {result ? (
        <>
          <p role="status">
            {result.platform
              ? `Проверено по локальным правилам: ${result.evaluated_packages} из ${result.packages} пакетов. Потенциальных совпадений: ${result.matches.length}.`
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
          </p>
          {result.matches.length ? (
            <ul>
              {result.matches
                .slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)
                .map((match) => (
                  <li
                    key={JSON.stringify([
                      match.passport_id,
                      match.package,
                      match.version,
                    ])}
                  >
                    <Button
                      variant="tiny"
                      onClick={() =>
                        onOpenPassport?.({ internal_id: match.passport_id })
                      }
                    >
                      {match.cve}
                    </Button>{" "}
                    {match.package} · {match.version}
                  </li>
                ))}
            </ul>
          ) : null}
          {result.matches.length > PAGE_SIZE ? (
            <div>
              <Button disabled={page === 0} onClick={() => setPage(page - 1)}>
                Назад
              </Button>
              <Button
                disabled={(page + 1) * PAGE_SIZE >= result.matches.length}
                onClick={() => setPage(page + 1)}
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
