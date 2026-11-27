# Архитектура MP VM Client

## Границы приложения

Приложение остаётся single-instance сервисом, но процессное состояние больше не должно создаваться произвольными глобальными переменными. `AppContainer` владеет сессией MP VM, репозиториями, сервисами, ограничителем запросов и `OperationRunner`. FastAPI создаётся через application factory, а запуск и остановка ресурсов выполняются lifespan-контекстом.

Поток запроса:

```text
APIRouter → service/use case → repository → PostgreSQL
                  ↓
             MP VM facade → auth + transport → MP VM API
```

- `app/api` содержит HTTP-роутеры и DTO. Здесь допустимы FastAPI и Pydantic, но не SQL.
- `app/services` содержит сценарии приложения и не формирует HTTP-ответы.
- `app/repositories` является границей доступа к данным. Во время миграции он делегирует старому `app.db`.
- `app/core` содержит настройки, контейнер и lifecycle runtime.
- `app/mpvm` содержит transport, authentication и чистые (без БД и сессии) нормализаторы данных MP VM: `common`, `asset_metadata`, `docker_vulnerabilities`, `passport_records`, `scanner_task_rows`, `scan_results`; CSV-отчёт по уязвимостям — `app/reports/vulnerability_csv.py`. Сборка карточки актива (`build_asset_card`, `AssetCardRequestExecutor`) живёт в `app/services/asset_card_builder.py`; общие ресурсы (семафор, кэш метаданных) привязываются через `configure()` при создании контейнера в `app.main`. Постобработка сканирования (`run_scan_postprocess`, `monitor_successful_scan_jobs`, обработка найденных активов) вынесена в `app/services/scan_postprocess.py`; пока она обращается к состоянию и хелперам, оставшимся в `app.main` (контейнер, сессия MP VM, очистка Docker-групп, задания сборки карточек), через ленивый прокси `host` (`app/services/main_host.py`) — это сохраняет точки подмены в тестах и убирается по мере выноса этих частей. Docker-группы сканирования (создание, ожидание готовности, отложенная очистка) — в `app/services/docker_scan_groups.py`; обновление карточек повторным сканированием (пакетное, массовое, шаги автоматизаций) — в `app/services/asset_card_refresh.py`; запуск задач сканирования, precheck, удаление задач и очистка активов после экспорта — в `app/services/scanner_task_launch.py`; фоновые задания паспортов уязвимостей (запрос по PDQL, догрузка деталей, тренды) — в `app/services/vulnerability_passport_jobs.py`; фоновые задания сборки карточек — в `app/services/asset_card_build_jobs.py`. HTTP-маршруты перенесены в `app/api/*` по роутерам (`auth`, `session`, `scanner_tasks`, `operations`, `imports_exports`, `assets`, `asset_cards`, `asset_query`, `passports`, `automations`) без изменения путей и OpenAPI-схемыи `system`; middleware и обработчики ошибок — в `app/api/middleware.py` (регистрируются в `app.main` в прежнем порядке); в `app.main` остались конфигурация и контейнер, жизненный цикл и реэкспорты. Сессия MP VM из окружения — `app/services/mpvm_session.py`, фоновая индексация карточек — `asset_search_backfill.py`, снимки уязвимостей — `vulnerability_snapshots.py`, вспомогательные вызовы VM-контура и задач команд — `vm_workflow_calls.py`. `app.main` реэкспортирует эти имена для совместимости, `MpVmClient` остаётся фасадом.
- `migrations` является единственным местом для новых изменений схемы PostgreSQL.

## Правила расширения

1. Новый endpoint добавляется в доменный `APIRouter`, DTO — в `app/api/schemas.py`.
2. Бизнес-решение реализуется сервисом; handler только валидирует ввод и вызывает сервис.
3. SQL добавляется в доменный репозиторий. Изменение схемы всегда получает Alembic revision.
4. Фоновая работа регистрируется в `OperationRunner`, использует cancellation token и сохраняет прогресс в PostgreSQL.
5. Новый frontend-сценарий размещается в `src/features/<domain>`; server-state загружается через TanStack Query.
6. Публичные paths, status codes и JSON изменяются только через отдельную версию API.

Каждый новый защищённый маршрут получает явную запись метода и шаблона пути в `app/api/permissions.py`; неизвестный маршрут запрещён всем ролям. `AppContainer.database_recovery` координирует startup, миграции и повтор незавершённых этапов после появления БД. `/api/live` проверяет процесс, `/api/ready` — актуальность схемы и завершение recovery. Контракты свидетельств риска и защиты версий описаны в [P1_CORRECTNESS.md](P1_CORRECTNESS.md).

## Переходные фасады

`app.main`, `app.db`, `app.mpvm_client` и `src/panels.jsx` пока сохраняются для обратной совместимости. Новый код не должен увеличивать эти файлы. Существующие функции переносятся вертикальными срезами; фасад удаляется только после перевода всех потребителей и контрактных тестов.

## VM workflow orchestration

`app/api/vm.py` → `VmWorkflowService` → `VmWorkflowRepository` образуют отдельный вертикальный срез. Workflow не повторяет работу существующих фоновых операций: он хранит устойчивый родительский процесс, этапы и ссылки на дочерние `operations`. Scan post-processing остаётся источником прогресса по карточкам, а workflow отвечает за идемпотентность, группировку, отмену, повтор и финальную remediation-сверку.

## Проверки

- `pytest` — backend и контрактные тесты;
- `ruff check …` и `mypy …` — новые Python-модули;
- `npm run lint`, `npm run test:coverage`, `npm run build` — frontend;
- `npm run test:e2e` — браузерный smoke-test с замоканным API;
- `npm run coverage:check` — запрет снижения зафиксированного покрытия.

Перед релизом миграция проверяется на пустой базе и копии текущей базы. Baseline revision не удаляет таблицы при downgrade, поэтому предыдущая версия приложения может быть возвращена без потери операторских данных.
