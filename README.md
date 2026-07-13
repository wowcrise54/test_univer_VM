# MP VM REST API Client

## Дашборд уязвимостей

Страница `/vulnerabilities` показывает текущий срез уязвимостей из сохранённых в PostgreSQL карточек `asset_cards`.

- `GET /api/vulnerabilities/summary` — общие показатели и распределения;
- `GET /api/vulnerabilities` — агрегированный список уязвимостей с пагинацией;
- `GET /api/vulnerabilities/hosts` — список затронутых хостов для выбранной уязвимости и drill-down до найденных компонентов.
- `GET /api/vulnerabilities/trends` — агрегированная история totals, coverage и severity с дневными или недельными интервалами.

В показателях `findings` означает число нормализованных вхождений уязвимостей после применения фильтров, `affected_hosts` — число уникальных хостов хотя бы с одним таким вхождением, а `unique_vulnerabilities` — число уникальных ключей уязвимости. Доступны фильтры по критичности, источнику (ОС или ПО), CVE или названию уязвимости, а также по имени, IP или FQDN хоста; выбор уязвимости открывает связанные хосты и затронутые компоненты.

Основные таблицы дашборда отражают последнее сохранённое состояние карточек. Блок «Динамика риска» хранит отдельные агрегированные снимки за последние 90 дней; история начинается с миграции и не содержит drill-down до прошлых findings или хостов. Исторический scope всегда охватывает все локальные карточки и не зависит от фильтров текущего среза. Если исходная группа была усечена, точка получает `coverage.complete=false` и считается нижней оценкой фактического количества.

## Устранение и покрытие

Страница `/remediation` ведёт рабочие кейсы для каждой пары «актив + нормализованная уязвимость». Кейсу можно назначить ответственного, рабочий статус, срок, комментарий или ограниченное по времени принятие риска. Статус `resolved` устанавливается только после полного и свежего обновления карточки, в котором finding больше не присутствует; повторное обнаружение переоткрывает кейс. Все изменения сохраняются в журнале, а `expected_version` защищает от одновременной перезаписи.

SLA по умолчанию: Critical — 7, High — 30, Medium — 90, Low — 180 дней. Матрица редактируется в интерфейсе; ручной срок не пересчитывается политикой. Ежедневный дайджест просроченных и приближающихся сроков создаётся во встроенных уведомлениях и передаётся в настроенный webhook.

Страница `/coverage` сопоставляет локальный реестр активов с карточками и показывает отсутствующие, устаревшие, усечённые и неудачно обновлённые карточки. Порог свежести задаётся `MPVM_COVERAGE_STALE_DAYS` (по умолчанию 7). Обновления и повторы запускаются через существующий центр операций.

- `GET /api/remediation/cases`, `GET /api/remediation/cases/{id}` — очередь и карточка кейса;
- `PATCH /api/remediation/cases/{id}`, `POST /api/remediation/cases/bulk-update` — единичные и массовые изменения;
- `GET /api/remediation/summary`, `GET|PUT /api/remediation/policy` — KPI и SLA;
- `GET /api/coverage/summary`, `GET /api/coverage/assets` — показатели и список покрытия.

## Архитектура и проверки качества

Проект использует application factory, FastAPI lifespan, доменные `APIRouter`, контейнер процессных ресурсов, сервисный и репозиторный слои, Alembic и TanStack Query. Текущие публичные API и маршруты UI сохранены. Подробная карта модулей и правила расширения находятся в [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

Основной локальный quality-gate:

```powershell
python -m pytest
ruff check app/core app/api app/domain app/mpvm app/repositories app/services app/factory.py tests/test_architecture.py
mypy app/core app/api app/domain app/mpvm app/repositories app/services app/factory.py
npm run lint
npm test
npm run build
```

React/Vite web UI и FastAPI backend-клиент для MP VM / MP10.

Что умеет приложение:

- подключаться к MP VM через OAuth password grant или готовый Bearer token;
- защищать само приложение локальными учётными записями и ролями `admin`, `operator`, `viewer`;
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

Требуется Node.js 26 (версия закреплена в `.nvmrc`). Для воспроизводимой установки используйте lock-файл:

```powershell
npm ci
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

## Автоматизация

Раздел `/automations` позволяет создавать последовательные runbook-сценарии, публиковать неизменяемые версии, запускать dry-run и рабочее выполнение, а также задавать cron-расписания с IANA timezone. Планировщик не запускает один runbook параллельно и не догоняет пропущенные окна.

Поддерживаемые шаги: запуск задачи сканирования с ожиданием постобработки, PDQL-экспорт, синхронизация паспортов, построение карточки актива, локальная выборка и уведомление. Для PDQL с удалением активов публикация требует точного подтверждения имени runbook; допуск связан с hash опубликованной версии.

Встроенные уведомления доступны через `/api/notifications`. Для внешней доставки укажите `MPVM_AUTOMATION_WEBHOOK_URL` и `MPVM_AUTOMATION_WEBHOOK_SECRET`; webhook подписывается HMAC-SHA256 в заголовке `X-MPVM-Signature` и повторяется через 1, 5 и 30 минут.

Плановые запуски требуют server-side учётных данных `MPVM_*`. Сессия, созданная только через браузер, не считается service account и после перезапуска не используется планировщиком.

## Надёжность и центр операций

Страница `/operations` объединяет сборку карточек активов, загрузку деталей паспортов, постобработку сканирования, PDQL-импорты и удаление активов. Активные операции опрашиваются раз в 2 секунды, история — раз в 15 секунд. Состояние и хронология сохраняются в PostgreSQL и не зависят от открытой вкладки браузера.

- `GET /api/system/status` — состояние приложения, PostgreSQL, сессии MP VM и фоновых исполнителей;
- `GET /api/operations` и `GET /api/operations/{id}` — список и детальная хронология;
- `GET /api/operations/summary` — глобальные счётчики активных и требующих внимания операций;
- `POST /api/operations/{id}/cancel` — идемпотентная остановка поддерживаемой операции;
- `POST /api/operations/{id}/retry` — безопасный повтор с новой операцией и ссылкой `retry_of`;
- `GET /api/operations/{id}/diagnostics` — очищенный ZIP-архив по `trace_id` или `job_id`;
- `GET|POST|DELETE /api/saved-views` — общие сохранённые фильтры терминала.

Запуски задачи и сборки карточки принимают `X-Idempotency-Key`. Повтор запроса с тем же ключом возвращает ранее созданную операцию и не запускает удалённое действие второй раз.

После перезапуска незавершённые сборки карточек и загрузки паспортов получают статус `interrupted` и могут быть повторены из центра операций. Постобработка сканирования использует существующий механизм lease/recovery и продолжает только безопасно возобновляемые этапы.

Ошибки API возвращаются в едином формате:

```json
{
  "detail": {
    "code": "DATABASE_UNAVAILABLE",
    "message": "Database is unavailable.",
    "operator_message": "Локальная база данных недоступна. Проверьте PostgreSQL и повторите действие.",
    "component": "database",
    "retryable": true,
    "trace_id": "...",
    "request_id": "...",
    "context": {}
  }
}
```

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
- `POST /api/reports/vulnerabilities/{type}/csv` - скачать детальный CSV по локальным уязвимостям ОС (`os`) или ПО (`software`); пустой `asset_ids` включает все сохранённые хосты.
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
- `GET /api/asset-card-query/fields` - каталог индексированных листовых полей карточек с типом, количеством хостов и примером.
- `POST /api/asset-card-query` - локальная выборка карточек по дереву правил AND/OR и областям `host`/`same_entity`.
- `POST /api/asset-card-query/export` - CSV всей выборки, независимо от текущей страницы UI.

Уязвимости в сохранённой карточке содержат `passport_ids` для совместимости и компактный массив `passports` для прямого открытия одного паспорта или выбора из нескольких.

## Сортировка и выборки по карточкам

Страница `/asset-query` работает только с локальными карточками PostgreSQL и не запускает обход MP VM. После обновления приложение в фоне индексирует старые карточки; покрытие видно над конструктором. Новые и обновлённые карточки переиндексируются в той же транзакции, что и основная запись.

`match_scope: "host"` связывает условия на уровне хоста. `match_scope: "same_entity"` требует одинаковый `entity_path`, поэтому, например, порт одного firewall-правила и действие другого не образуют ложного совпадения. Допускается до 20 правил и до трёх уровней групп.

Параметры `sort_by` и `sort_dir=asc|desc` поддерживаются в `/api/operations`, `/api/assets`, `/api/asset-cards/local` и `/api/vulnerability-passports/local`. Неизвестная колонка возвращает `422`; пустые значения располагаются после заполненных, а вторичный ключ обеспечивает стабильную пагинацию.

В таблицах карточки объекты и массивы не отображаются как сериализованный JSON: контейнер раскрывается в листовые строки, а технические `raw*`, `objectId` и `type` скрываются. Исходный диагностический снимок в PostgreSQL при этом не удаляется.

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

## Авторизация в приложении

При первом запуске на пустой базе задайте `MPVM_BOOTSTRAP_ADMIN_PASSWORD` (не короче 12 символов). Имя первого администратора задаётся через `MPVM_BOOTSTRAP_ADMIN_USERNAME`, по умолчанию — `admin`. Учётная запись создаётся только при пустой таблице пользователей; последующее изменение переменных не сбрасывает пароль.

Роли:

- `admin` — управление пользователями, ролями, диагностикой и подключением MP VM;
- `operator` — просмотр данных и выполнение рабочих операций;
- `viewer` — доступ только на чтение.

Сессии хранятся в PostgreSQL в виде SHA-256 отпечатков случайных токенов, передаются в `HttpOnly`/`SameSite=Strict` cookie и отзываются при выходе, блокировке пользователя или смене пароля. Для публикации через HTTPS установите `MPVM_AUTH_COOKIE_SECURE=true`.
