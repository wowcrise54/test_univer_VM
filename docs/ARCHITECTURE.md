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
- `app/mpvm` содержит transport и authentication; `MpVmClient` остаётся совместимым фасадом.
- `migrations` является единственным местом для новых изменений схемы PostgreSQL.

## Правила расширения

1. Новый endpoint добавляется в доменный `APIRouter`, DTO — в `app/api/schemas.py`.
2. Бизнес-решение реализуется сервисом; handler только валидирует ввод и вызывает сервис.
3. SQL добавляется в доменный репозиторий. Изменение схемы всегда получает Alembic revision.
4. Фоновая работа регистрируется в `OperationRunner`, использует cancellation token и сохраняет прогресс в PostgreSQL.
5. Новый frontend-сценарий размещается в `src/features/<domain>`; server-state загружается через TanStack Query.
6. Публичные paths, status codes и JSON изменяются только через отдельную версию API.

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
