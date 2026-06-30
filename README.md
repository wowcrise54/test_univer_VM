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

В UI показывается карточка с названием, CVE, score, severity, описанием, исправлением, ссылками, идентификаторами и полным raw JSON ответа.
Список паспортов можно фильтровать по CVE, названию, `internalId` и package; таблица разбита на страницы по 50 строк, а карточка открывается в отдельном модальном окне.
Список паспортов сохраняется в таблицу `vulnerability_passports` сразу после загрузки из `/assets_grid/data`. Детальный raw JSON паспорта дописывается в эту же таблицу при открытии карточки. Кнопка `Из БД` загружает уже сохранённые паспорта из локальной PostgreSQL.
Для больших выгрузок используйте поля `Сколько загрузить` и `Размер пачки`: backend принимает до 50 000 паспортов за запуск и ходит в MP VM батчами до 10 000 записей через `offset + limit`.

## Основные endpoints приложения

- `POST /api/session/connect` - подключиться к MP VM.
- `GET /api/session` - текущее состояние подключения.
- `GET /api/mpvm/lookups` - получить credentials/scopes/profiles.
- `GET /api/mpvm/scanner-tasks/remote` - получить задачи из MP VM.
- `GET /api/scanner-tasks` - локально сохранённые задачи.
- `POST /api/scanner-tasks` - создать задачу через `POST /api/scanning/v4/scanner_tasks/create`.
- `PUT /api/scanner-tasks/{id}` - изменить задачу через `PUT /api/scanning/v4/scanner_tasks/{id}`.
- `POST /api/scanner-tasks/{id}/validate` - проверить задачу.
- `POST /api/scanner-tasks/{id}/start` - запустить задачу, опционально с precheck и таймером.
- `POST /api/scanner-tasks/{id}/stop` - остановить задачу.
- `POST /api/scanner-tasks/{id}/delete` - удалить задачу в MP VM и убрать локальную строку.
- `POST /api/exports/pdql` - выполнить PDQL, скачать CSV, импортировать в PostgreSQL и при необходимости удалить активы из MP VM.
- `POST /api/import/sample` - импортировать пример `host_software_vulnerabilities_10.104.103.0_24.csv`.
- `GET /api/assets` - таблица сохранённых строк уязвимостей.
- `GET /api/assets/summary` - сводка локальной БД.
- `POST /api/vulnerability-passports/query` - получить список паспортов уязвимостей по PDQL.
- `GET /api/vulnerability-passports/local` - получить сохранённые паспорта из локальной PostgreSQL.
- `GET /api/vulnerability-passports/{internalId}` - получить детальную карточку паспорта.
- `PUT /api/vulnerability-passports/{internalId}` - принудительно обновить основные поля и детали сохранённого паспорта из MP VM.
- `DELETE /api/vulnerability-passports/{internalId}` - удалить паспорт из локальной PostgreSQL.
- `GET /api/asset-cards/local` - получить сохранённые карточки активов.
- `GET /api/asset-cards/{assetId}` - получить сохранённую карточку актива.
- `PUT /api/asset-cards/{assetId}` - заново собрать и обновить сохранённую карточку из MP VM.
- `DELETE /api/asset-cards/{assetId}` - удалить карточку актива из локальной PostgreSQL.

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
