# MP VM REST API Client

React/Vite web UI и FastAPI backend-клиент для MP VM / MP10.

Что умеет приложение:

- подключаться к MP VM через OAuth password grant или готовый Bearer token;
- загружать справочники `credentials`, `scopes`, `scanner_profiles`;
- создавать, изменять, валидировать, запускать, останавливать и удалять задачи сканирования;
- запускать precheck перед основной задачей и останавливать долгие задачи по таймеру;
- выполнять PDQL, выгружать CSV, импортировать результат в локальную PostgreSQL;
- удалять активы из MP VM после успешного сохранения результата в локальную БД;
- показывать локальную таблицу сохранённых активов, ПО и уязвимостей;
- получать список паспортов уязвимостей через PDQL и открывать карточку паспорта по `internalId`.
- принудительно обновлять карточки активов и детали паспортов из MP VM, а также удалять их из локальной PostgreSQL.

Прямой функционал синхронизации внутренней PostgreSQL БД MP VM удалён. Приложение больше не использует отдельное подключение к source DB и старые endpoints синхронизации.

## Локальный запуск

Сначала поднимите PostgreSQL из compose или укажите свой DSN в `MPVM_DATABASE_URL`.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MPVM_DATABASE_URL="postgresql://mpvm:mpvm@localhost:55432/mpvm"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Откройте `http://127.0.0.1:8000`.

## React-разработка

```powershell
npm install
npm run dev
```

Vite dev server откроется на `http://127.0.0.1:5173` и будет проксировать `/api` на FastAPI `http://127.0.0.1:8000`.

Production-сборка кладётся в `app/static`:

```powershell
npm run build
```

## Docker

```powershell
docker compose -f docker-compose.corpnet.example.yml up --build
```

Dockerfile собирает React через Vite и копирует готовую статику в Python-образ. Данные PostgreSQL сохраняются в volume `mpvm_postgres`, CSV-экспорты - в `mpvm_exports`.

## Диагностическое логирование

Backend, сборка карточек, MP VM HTTP, PostgreSQL и frontend пишут связанные JSONL-события в `MPVM_LOG_DIR` (по умолчанию `output/logs`). Каждый API-ответ содержит `X-Trace-ID`, `X-Request-ID` и `Server-Timing`; trace ID также показывается в задании сборки карточки и добавляется к frontend-ошибкам.

Полная карточка актива загружается параллельным конвейером с сохранением всех коллекций (`full=true`, лимиты и глубина не уменьшаются). По умолчанию одновременно выполняется до `MPVM_ASSET_CARD_REQUEST_WORKERS=8` запросов, но не больше общего `MPVM_BACKGROUND_REQUEST_LIMIT=10`. Итоговая статистика карточки содержит длительности дерева, уязвимостей и сохранения, пиковый параллелизм и время ожидания очереди.

Файлы журналов: `app.jsonl`, `asset-card-build.jsonl`, `mpvm-http.jsonl`, `database.jsonl`, `frontend.jsonl`, `errors.jsonl`. Ротация задаётся через `MPVM_LOG_MAX_BYTES` и `MPVM_LOG_BACKUP_COUNT`, срок хранения — через `MPVM_LOG_RETENTION_DAYS`.

`MPVM_DEBUG_PAYLOADS=true` включает отдельный `debug-payloads.jsonl`. Тела ограничиваются `MPVM_DEBUG_PAYLOAD_MAX_BYTES` и очищаются от token/password/secret/cookie/Authorization и реквизитов строки подключения. Этот режим предназначен только для кратковременной диагностики.

Диагностический архив по заданию или трассе:

```powershell
python -m app.diagnostics bundle --job-id <job-id>
python -m app.diagnostics bundle --trace-id <trace-id> --output output/diagnostics/trace.zip
```

Архив содержит очищенные события, сводку типов событий и безопасную конфигурацию логирования.

Для проверки накладных расходов выполните одинаковые 20 запросов после запуска приложения с `MPVM_LOG_LEVEL=INFO`, затем с `DEBUG`, и сравните p95:

```powershell
python scripts/benchmark_logging_sla.py run --url http://127.0.0.1:8000/api/asset-cards/<asset-id> --label INFO --output output/info.json
python scripts/benchmark_logging_sla.py run --url http://127.0.0.1:8000/api/asset-cards/<asset-id> --label DEBUG --output output/debug.json
python scripts/benchmark_logging_sla.py compare --info output/info.json --debug output/debug.json --max-overhead-percent 10
```

## Паспорта уязвимостей

Раздел `Паспорта` выполняет PDQL:

```pdql
select(@VulnerPassport, compact(VulnerPassport.CVEs),
VulnerPassport.SeverityRating, VulnerPassport.Score,
VulnerPassport.IssueTime, VulnerPassport.PackageId,
VulnerPassport.PackageVersion, VulnerPassport.Metrics)
| limit(0)
```

Backend сначала получает `pdqlToken`, затем забирает записи таблицы:

```http
GET /api/assets_temporal_readmodel/v1/assets_grid/data?limit=1001&pdqlToken=<token>
```

Из полученных `records` берётся `@VulnerPassport.internalId`. При открытии карточки выполняется запрос:

```http
GET /api/assets_temporal_readmodel/v1/vulnerabilities/{internalId}
```

В UI показывается сводка паспорта с названием, CVE, score, severity, описанием, исправлением, ссылками и идентификаторами. Отдельная вкладка с raw JSON не отображается.
Список паспортов можно фильтровать по CVE, названию, `internalId` и package. Поиск и пагинация по 50 строк выполняются на backend; тяжёлые `raw_record_json` и `raw_detail_json` не передаются в ответе списка. Полный JSON возвращается только при открытии конкретной карточки.
Список сохраняется в таблицу `vulnerability_passports` сразу после загрузки из `/assets_grid/data`, после чего HTTP-ответ возвращается пользователю. Детали догружаются фоновой задачей с прогрессом и отменой: одновременно выполняется до `MPVM_PASSPORT_DETAIL_WORKERS` запросов, записи сохраняются пачками по 100, а детали моложе `MPVM_PASSPORT_DETAIL_TTL_HOURS` часов повторно не запрашиваются.
Для больших выгрузок используйте поля `Сколько загрузить` и `Размер пачки`: пустой лимит загружает все доступные паспорта, а backend ходит в MP VM батчами до 10 000 записей через `offset + limit`.

## Основные endpoints приложения

- `POST /api/session/connect` - подключиться к MP VM.
- `GET /api/session` - текущее состояние подключения.
- `GET /api/mpvm/lookups` - получить credentials/scopes/profiles.
- `GET /api/mpvm/scanner-tasks/remote` - получить задачи из MP VM.
- `GET /api/scanner-tasks` - локально сохранённые задачи.
- `POST /api/scanner-tasks` - создать задачу через `POST /api/scanning/v4/scanner_tasks/create`.
- `PUT /api/scanner-tasks/{id}` - изменить задачу через `PUT /api/scanning/v4/scanner_tasks/{id}`.
- `POST /api/scanner-tasks/{id}/validate` - проверить задачу.
- `POST /api/scanner-tasks/{id}/start` - запустить задачу и вернуть `202`; завершение сканирования, создание локальных карточек и удаление успешно просканированных активов в MP VM выполняются в фоне.
- `GET /api/scanner-tasks/{id}/postprocess-runs/latest` - получить прогресс фоновой обработки и статусы каждого target/asset.

После запуска основной задачи клиент опрашивает `/api/scanning/v2/runs/{runId}/jobs`. Каждый job с `runMode=default` обрабатывается отдельно сразу после перехода `errorStatus` в `success`; connection-check/precheck jobs исключаются. Для точного IP/FQDN успешного job asset разрешается без дополнительного фильтра по времени, после чего его локальная карточка пересобирается и перезаписывается.

Диагностические сообщения этой цепочки выводятся в стандартный лог приложения как JSON с префиксом `[scan-postprocess]`. В Docker их можно смотреть командой `docker compose logs -f mpvm-client` и фильтровать по `postprocess_run_id`, `task_id`, `job_id`, target или `asset_id`.
- `POST /api/scanner-tasks/{id}/stop` - остановить задачу.
- `POST /api/scanner-tasks/{id}/delete` - удалить задачу в MP VM и убрать локальную строку.
- `POST /api/exports/pdql` - выполнить PDQL, скачать CSV, импортировать в PostgreSQL и при необходимости удалить активы из MP VM.
- `POST /api/import/sample` - импортировать пример `host_software_vulnerabilities_10.104.103.0_24.csv`.
- `GET /api/assets` - таблица сохранённых строк уязвимостей.
- `GET /api/assets/summary` - сводка локальной БД.
- `POST /api/vulnerability-passports/query` - получить список паспортов уязвимостей по PDQL.
- `GET /api/vulnerability-passports/local` - получить компактную страницу сохранённых паспортов (`q`, `severity`, `pdql_token`, `limit`, `offset`).
- `GET /api/vulnerability-passports/detail-jobs/active` - получить активную фоновую загрузку деталей.
- `GET /api/vulnerability-passports/detail-jobs/{jobId}` - получить прогресс фоновой загрузки.
- `POST /api/vulnerability-passports/detail-jobs/{jobId}/cancel` - остановить фоновую загрузку.
- `GET /api/vulnerability-passports/{internalId}` - получить детальную карточку паспорта.
- `PUT /api/vulnerability-passports/{internalId}` - принудительно обновить основные поля и детали сохранённого паспорта из MP VM.
- `DELETE /api/vulnerability-passports/{internalId}` - удалить паспорт из локальной PostgreSQL.
- `GET /api/asset-cards/local` - получить сохранённые карточки активов.
- `GET /api/asset-cards/{assetId}` - получить сохранённую карточку актива.
- `PUT /api/asset-cards/{assetId}` - заново собрать и обновить сохранённую карточку из MP VM.
- `DELETE /api/asset-cards/{assetId}` - удалить карточку актива из локальной PostgreSQL.
- `POST /api/asset-cards/build-jobs` - запустить фоновую сборку полной карточки актива.
- `GET /api/asset-cards/build-jobs/active` - получить активную сборку карточки.
- `GET /api/asset-cards/build-jobs/{jobId}` - получить этап, монотонный `progress_percent` и счётчики сборки.
- `POST /api/asset-cards/build-jobs/{jobId}/cancel` - остановить сборку без сохранения частичного результата.

Уязвимости в сохранённой карточке содержат `passport_ids` для совместимости и компактный массив `passports` для прямого открытия одного паспорта или выбора из нескольких.

## Payload создания задачи

Backend строит payload по логике `mp10_export_VM_info.py`:

```json
{
  "name": "Windows audit 10.104.103.0/24",
  "description": "...",
  "scope": "<scope id>",
  "profile": "<scan profile id>",
  "agents": { "agentIds": ["<collector id>"] },
  "overrides": {
    "transports": {
      "windows": {
        "wmi_and_rpc_and_re": {
          "connection": {
            "auth": {
              "ref_value": "<credential id>",
              "ref_type": "credential"
            }
          }
        }
      }
    }
  },
  "include": { "assets": [], "targets": ["10.104.103.0/24"], "assetsGroups": [] },
  "exclude": { "assets": [], "targets": [], "assetsGroups": [] },
  "hostDiscovery": { "enabled": true, "profile": "<hostDiscovery profile id>" },
  "triggerParameters": { "isEnabled": false, "type": "Daily" },
  "deniedScanSettings": { "isEnabled": false, "periods": [] },
  "isFqdnPriority": true,
  "groups": []
}
```
