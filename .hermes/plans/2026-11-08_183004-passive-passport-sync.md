# Пассивная синхронизация паспортов MP VM → локальная PostgreSQL

## Goal

Периодически, без открытой страницы браузера, получать паспорта из MP VM, обнаруживать новые и изменённые данные и безопасно обновлять локальные паспорта вместе с существующими связями.

## Статус плана и ограничения

Это план реализации, не выполненная реализация. В этом сеансе исходники не изменялись, тесты не запускались, удалённый MP VM не вызывался.

Рабочая директория: `D:/CIT/MP VM test`; проверенная ветка: `codex/db-fill`; на момент исследования `git status --short` и `git diff --` пусты. Дата имени файла получена командой `date '+%Y-%m-%d_%H%M%S'`.

Проверено: Docker Compose CLI доступен (`v5.3.0`), но Docker daemon сейчас недоступен: отсутствует pipe `dockerDesktopLinuxEngine`. При исполнении плана сначала восстановить доступ к Docker с участием пользователя; не запускать проверки на host Python/Node и не перезапускать рабочий стек. Команды ниже — будущие проверки с ожидаемыми, а не уже полученными результатами.

## Current context / assumptions

### Что уже есть — прочитать перед реализацией

| Файл / символ | Назначение и важные ограничения |
|---|---|
| `app/api/passports.py:create_vulnerability_passport_refresh_job` | Ручное полное обновление, `POST /api/vulnerability-passports/refresh-jobs`; формирует полный PDQL-запрос, проверяет активную загрузку деталей, создаёт operation. |
| `app/services/vulnerability_passport_jobs.py:_execute_vulnerability_passport_query` | Загружает каталог, нормализует, сохраняет, отдельно синхронизирует тренды, создаёт detail job и помещает её в `BackgroundTasks`. Это основная переиспользуемая цепочка. |
| `app/services/vulnerability_passport_jobs.py:run_vulnerability_passport_detail_job` | Ограниченная параллельность, общий `BACKGROUND_REQUEST_SEMAPHORE`, пачки, индивидуальные ошибки и закрытие HTTP-сессий. Не заменять собственным пулом. |
| `app/services/passport_refresh.py:run` | Сейчас завершает catalog operation **до** завершения detail job. Это нормально для существующего ручного контракта, но не доказывает завершение автоматической синхронизации. |
| `app/repositories/passport_refresh.py` | Хранение catalog operation, активные состояния `queued/running/cancelling`, защита терминальных состояний, interruption при старте. |
| `app/db.py:upsert_vulnerability_passports` | Уже обновляет содержимое только при различиях, отдельно трогает `last_seen`, возвращает `saved/changed/replaced/ambiguous/stale/passport_links`. При полном каталоге заменяет перевыпущенные паспорта и переносит связи. |
| `app/mpvm/passport_records.py:plan_passport_replacements` | Сопоставление по external ID + package + version; неоднозначности не склеивает. Не писать второй алгоритм сопоставления по CVE или имени. |
| `app/db.py:vulnerability_passport_detail_refresh_candidates` | TTL деталей по умолчанию 24 часа. Простое периодическое повторение ручного обновления пропустит изменения свежих деталей. |
| `app/db.py:_upsert_vulnerability_passport_details` | Сейчас безусловно перезаписывает каждый полученный detail JSON. Возвращаемый размер используется для `loaded_count` и `processed_count`. |
| `app/mpvm/scan_results.py:fetch_asset_grid_records` | Возвращает `reportedTotal`, `recordCount`, `batches`; может остановиться на короткой странице даже при несовпадении с total. Перед полным сохранением нужна отдельная проверка полноты. |
| `app/core/runtime.py:OperationRunner` | Владеет очередями, futures и cancellation registry; `shutdown()` вызывает `cancel_all()`. Не создавать сторонний scheduler/Celery/APScheduler. |
| `app/services/startup.py:database_startup_steps` | Миграции и interruption выполняются до включения scheduler. Здесь включать новый scheduler последним этапом. |
| `app/main.py:get_automation_service`, `shutdown`, `automation_service_account_ready` | В `main.py` оставить только wiring. Существующий automation scheduler не использовать для долгой синхронизации: его loop также обслуживает webhook/digest, а ошибка одного tick сейчас пропускает последующие callbacks. |
| `app/services/mpvm_session.py:require_mpvm` | Существующая серверная сессия и env reconnect; не сохранять токены в operation request. |
| `app/services/asset_card_refresh.py:execute_automation_step`, ветка `passport_sync` | Ещё один путь запуска синхронизации. Добавить в регрессии; не ограничиваться ручным endpoint. |
| `migrations/versions/20260924_0024_passport_refresh.py` | Уже есть partial unique index: одна активная `passport_catalog_refresh`. Новая таблица расписаний для MVP не нужна. |
| `tests/conftest.py:test_db` | Реальная отдельная PostgreSQL; fixtures очищают таблицы, поэтому интеграционные наборы запускать последовательно. |
| `compose.test.yml`, `Dockerfile.test`, `docs/testing.md`, `.github/workflows/quality.yml` | Источник Docker-команд, test-зависимостей и quality gates. Не менять major PostgreSQL: локальный test service — PostgreSQL 16. |

Graphify использован для поиска владельцев и зависимостей. Его номера строк частично устарели после выделения модулей: доверять прочитанным исходникам и символам, не переносить бизнес-логику обратно в `app/main.py`.

### Решения MVP — явно выбранные значения, а не требования пользователя

1. Односторонняя синхронизация: MP VM — источник истины; изменяется только локальная PostgreSQL. Никаких POST/DELETE/PUT, изменяющих паспорта или активы в MP VM.
2. `MPVM_PASSPORT_SYNC_ENABLED=false` по умолчанию: релиз не запускает неожиданную массовую выгрузку. После явного включения backend работает без вкладки браузера.
3. `MPVM_PASSPORT_SYNC_INTERVAL_SECONDS=3600`; допустимо целое число не меньше 60. Интервал считается **после окончания предыдущей автоматической попытки**, включая ошибочную или отменённую. Опрос scheduler — раз в 30 секунд; короткий цикл опроса не равен частоте полной выгрузки.
4. После первого включения — одна проверка на первом tick. После простоя — не более одной догоняющей проверки, без очереди за каждый пропущенный час.
5. MVP использует существующую backend MP VM-сессию/настройки подключения. Для работы после рестарта нужны серверные credentials или token; интерактивное подключение браузером не является надёжным unattended-доступом. Нет подключения — информативный skip без очистки локальной БД и без создания операции на каждый tick.
6. Проверяется **весь каталог и все детали** на каждом автоматическом проходе. В прочитанном коде нет доказанного remote `updated_at`/ETag/change-feed, покрывающего все поля деталей. Не выдумывать такой API и не считать `IssueTime` временем изменения.
7. Удаление отсутствующего паспорта без однозначной замены не входит в задачу. Сохранить существующую безопасную replacement-логику. Неоднозначность — счётчик/предупреждение, не догадка.
8. UI настройки интервала и новый публичный API не входят в MVP; конфигурация через env, прогресс/ошибки — существующий `/operations` и refresh/detail endpoints. Сохраняются RBAC и маршруты.
9. Рабочее развёртывание MVP — один backend process, как текущая process-local session/recovery архитектура. Атомарное резервирование не позволяет двум scheduler ticks создать параллельные операции, но не обещает полноценную поддержку нескольких Uvicorn workers: текущий startup глобально прерывает активные операции. Не включать multi-worker deployment этой задачей.

## Architecture / proposed approach

Добавить небольшой backend scheduler на существующем `OperationRunner`, отдельно от loop автоматизаций; он резервирует очередное обновление через PostgreSQL и запускает переиспользуемую цепочку загрузки каталога/деталей. Автоматическая операция остаётся активной до завершения её detail job; принудительная проверка деталей обходит TTL, а одинаковое содержимое не переписывается повторно. Расписание выводится из сохранённых автоматических catalog operations, поэтому не нужны новые зависимости, таблицы или миграции.

### Точные внутренние контракты

- Автоматическая catalog operation имеет прежний `kind='passport_catalog_refresh'` и `request.trigger='periodic'`; остальные поля request — обычный `VulnerabilityPassportQueryRequest.model_dump()`. Credentials, PDQL tokens и raw responses в request не добавлять.
- Внутренние опции исполнения — keyword-only аргументы, не новые публичные DTO-поля:
  - `_execute_vulnerability_passport_query(..., *, force_details: bool = False)`;
  - `vulnerability_passport_detail_refresh_candidates(..., ttl_hours: int, force: bool = False)`;
  - `run_vulnerability_passport_detail_job(..., parent_cancel_event: threading.Event | None = None)`;
  - `passport_refresh.run(..., *, complete_after_details: bool = False)`.
- Ручные callers без новых аргументов сохраняют старое поведение. Автоматический adapter передаёт `force_details=True` и `complete_after_details=True`.
- Автоматическая родительская операция: `queued → running → completed/completed_with_errors/failed/cancelled`; startup переводит незавершённую в `interrupted`. `completed` только после терминального успешного состояния деталей и сохранения результатов.
- Ожидание деталей не должно занимать automation scheduler thread. В periodic режиме callbacks из `BackgroundTasks` запускаются последовательно в том же worker; detail worker сам использует свой ограниченный пул. Передать ему родительский cancellation event отдельным аргументом, сохранив собственный event detail job.
- Итог операции содержит прежние `total/db/trend_sync/detail_job`, причём `detail_job` в periodic режиме перечитан после выполнения. `loaded_count` означает число успешно проверенных/загруженных деталей, **не** число изменённых JSON. Не переименовывать существующий счётчик и не ломать UI.
- Сохранение каталога — атомарная существующая транзакция; детали — атомарно по существующим пачкам. Нет обещания одной транзакции на сетевой проход: при ошибке детали последняя успешная версия сохраняется, остальные успешные паспорта обновляются.

## Правила TDD и команды

Каждый пункт ниже — отдельный небольшой шаг; сложные пункты разделены на RED и GREEN. Никаких тестов на реальном MP VM, `sleep(3600)`, SQLite или ручного запуска боевого sync для проверки.

В корне репозитория после восстановления Docker:

```bash
git status --short
git diff --
docker compose version
docker info --format '{{.ServerVersion}}'
docker compose -p mpvm-passport-sync-tests -f compose.test.yml config --services
docker compose -p mpvm-passport-sync-tests -f compose.test.yml up -d test-postgres
```

Ожидается: Docker daemon возвращает версию; services включают `tests` и `test-postgres`; test-postgres healthy. Это отдельный Compose project. Не читать `.env`, не выводить rendered Compose с секретами, не выполнять `down -v`.

Для краткости следующие shell functions можно определить **в сеансе будущего исполнителя**, не сохранять в репозиторий:

```bash
pt() {
  docker compose -p mpvm-passport-sync-tests -f compose.test.yml run --rm --build tests python -m pytest -p no:cacheprovider "$@"
}
```

`pt tests/test_passport_refresh.py -q` — точная команда через эту функцию. В RED ожидается assertion/import failure именно нового контракта, а не ошибка Docker/зависимостей/БД. В GREEN — exit 0 и `passed`, без skipped новых интеграционных тестов.

Пользователь разрешил частые коммиты в задании на план; при **реализации** после каждого законченного GREEN-блока ниже допустим указанный commit. Не коммитить падающее RED-состояние, чужие изменения или сам план без необходимости. Если последующее поручение на исполнение запретит коммиты — оставить те же контрольные точки без `git commit`. В текущем plan-only сеансе коммиты запрещены.

## Step-by-step tasks

### 1. RED: конфигурация, 2–5 минут

Файл: `tests/test_settings_and_oauth_boundaries.py`. Добавить:

```python
@pytest.mark.parametrize("value", [0, -1, 59])
def test_passport_sync_interval_rejects_too_small_values(value):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, passport_sync_interval_seconds=value)


def test_passport_sync_is_opt_in_and_has_a_configurable_interval(monkeypatch):
    monkeypatch.delenv("MPVM_PASSPORT_SYNC_ENABLED", raising=False)
    monkeypatch.delenv("MPVM_PASSPORT_SYNC_INTERVAL_SECONDS", raising=False)
    settings = Settings(_env_file=None)
    assert settings.passport_sync_enabled is False
    assert settings.passport_sync_interval_seconds == 3600
    monkeypatch.setenv("MPVM_PASSPORT_SYNC_ENABLED", "true")
    monkeypatch.setenv("MPVM_PASSPORT_SYNC_INTERVAL_SECONDS", "60")
    settings = Settings(_env_file=None)
    assert settings.passport_sync_enabled is True
    assert settings.passport_sync_interval_seconds == 60
```

Проверка: `pt tests/test_settings_and_oauth_boundaries.py -q -k passport_sync` → RED.

### 2. GREEN: конфигурация, 2–5 минут

Файл: `app/core/config.py`, добавить рядом с `passport_detail_ttl_hours`:

```python
passport_sync_enabled: bool = False
passport_sync_interval_seconds: int = Field(default=3600, ge=60)
```

Отдельный poll setting не нужен: scheduler использует существующее `automation_scheduler_poll_seconds` только как период локального опроса, не как привязку к automation service.

Проверка: `pt tests/test_settings_and_oauth_boundaries.py -q` → GREEN. Checkpoint: `git add app/core/config.py tests/test_settings_and_oauth_boundaries.py && git commit -m "feat: configure passive passport synchronization"`.

### 3. RED: проверка полноты snapshot, 2–5 минут

Новый файл: `tests/test_passport_snapshot_validation.py`:

```python
import pytest

from app.services.passport_snapshot import validate_full_catalog


def row(identifier):
    return {"@VulnerPassport": {"internalId": identifier}}


@pytest.mark.parametrize("records,summary", [
    ([], {"reportedTotal": None, "batches": []}),
    ([row("p1")], {"reportedTotal": 2, "batches": [{"reported_total": 2}]}),
    ([row("p1"), row("p1")], {"reportedTotal": 2, "batches": [{"reported_total": 2}]}),
    ([{}], {"reportedTotal": 1, "batches": [{"reported_total": 1}]}),
    ([row("p1")], {"reportedTotal": 1, "batches": [{"reported_total": 2}, {"reported_total": 1}]}),
])
def test_invalid_full_catalog_is_rejected(records, summary):
    with pytest.raises(ValueError):
        validate_full_catalog(records, summary)


@pytest.mark.parametrize("records,summary", [
    ([], {"reportedTotal": 0, "batches": [{"reported_total": 0}]}),
    ([row("p1")], {"reportedTotal": 1, "batches": [{"reported_total": 1}]}),
    ([row("p1")], {"reportedTotal": None, "batches": [{"reported_total": None}]}),
])
def test_verified_or_nonempty_exhausted_catalog_is_accepted(records, summary):
    validate_full_catalog(records, summary)
```

Проверка: `pt tests/test_passport_snapshot_validation.py -q` → import RED. Дополнительно в `tests/test_passport_sync.py` использовать существующие `PassportQueryTests` mocks: при полном default PDQL и несовпадении total `db.upsert_vulnerability_passports`, trend sync и создание detail job не вызваны. Частичный пользовательский query не получает признак полного каталога.

### 4. GREEN: проверка snapshot перед записью, 2–5 минут

Новый файл: `app/services/passport_snapshot.py`:

```python
from __future__ import annotations

from typing import Any

from ..mpvm.passport_records import normalize_vulnerability_passport_record


def validate_full_catalog(records: list[dict[str, Any]], summary: dict[str, Any]) -> None:
    totals = {
        batch["reported_total"]
        for batch in summary.get("batches", [])
        if batch.get("reported_total") is not None
    }
    if len(totals) > 1:
        raise ValueError("MP VM catalog total changed during pagination")
    total = summary.get("reportedTotal")
    if total is not None and (total < 0 or len(records) != total):
        raise ValueError("MP VM returned an incomplete passport catalog")
    if not records and total != 0:
        raise ValueError("MP VM returned an unverified empty passport catalog")
    identifiers = [normalize_vulnerability_passport_record(row).get("internal_id") for row in records]
    if any(not isinstance(value, str) or not value.strip() for value in identifiers):
        raise ValueError("MP VM returned a passport without internalId")
    if len(set(identifiers)) != len(identifiers):
        raise ValueError("MP VM returned duplicate passport identifiers")
```

В `app/services/vulnerability_passport_jobs.py` поднять вычисление существующего `full_catalog_sync` до нормализации/сохранения; **до** `dedupe_vulnerability_passports` вызвать `validate_full_catalog(records, raw_response)` только если `payload.save_to_db and full_catalog_sync`. Удалить прежнее повторное вычисление `full_catalog_sync`. Не менять generic grid fetcher, используемый сканированием и активами.

Неизвестный total при непустой выгрузке допускается по текущему контракту завершения пагинации; это не строгий remote snapshot. Пустой ответ без total запрещён. Дубликаты default catalog трактуются как неполнота/нестабильность: нельзя делать replacement на таком снимке.

Проверка: `pt tests/test_passport_snapshot_validation.py tests/test_passport_sync.py -q` → GREEN; исправлять fixtures, чтобы моделировали честные total, не удалять fail-closed проверки. Checkpoint commit: `fix: validate full passport snapshots before reconciliation`.

### 5. RED: автоматический обход TTL, 2–5 минут

Новый файл: `tests/integration/test_periodic_passport_sync_db.py`. Начать с полностью копируемого теста:

```python
import pytest

from app import db

pytestmark = pytest.mark.integration


def test_force_refresh_includes_fresh_details(test_db):
    db.upsert_vulnerability_passports([{"internal_id": "p1", "name": "one"}])
    db.upsert_vulnerability_passport_detail("p1", {"name": "one", "description": "old"})
    normal = db.vulnerability_passport_detail_refresh_candidates(["p1"], ttl_hours=24)
    assert normal["eligible"] == []
    forced = db.vulnerability_passport_detail_refresh_candidates(["p1"], ttl_hours=24, force=True)
    assert forced == {"requested": ["p1"], "eligible": ["p1"], "skipped_fresh": []}
```

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py -q -k force_refresh` → TypeError RED.

### 6. GREEN: TTL только для ручного режима, 2–5 минут

`app/db.py:vulnerability_passport_detail_refresh_candidates`: добавить keyword-only `force: bool = False`. После получения `ordered_ids` добавить:

```python
if force:
    return {"requested": ordered_ids, "eligible": ordered_ids, "skipped_fresh": []}
```

`app/services/vulnerability_passport_jobs.py:_execute_vulnerability_passport_query`: добавить после `progress` keyword-only `force_details: bool = False`; в candidates передать `force=force_details`. Публичный DTO `VulnerabilityPassportQueryRequest` не менять. Проверить существующие mocks с `assert_called_once_with`: они теперь должны учитывать явный `force=False`.

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py tests/test_passport_sync.py -q` → GREEN. Checkpoint commit: `feat: force detail verification for periodic passport sync`.

### 7. RED: не переписывать идентичные детали, 2–5 минут

В `tests/integration/test_periodic_passport_sync_db.py` добавить тесты:

- Сохранить паспорт и detail; запомнить `raw_detail_json`, `first_seen` и PostgreSQL `xmin::text`. Повторить тот же detail с переставленными ключами JSON: raw JSON остаётся прежней строкой; `first_seen` не меняется; `detail_updated_at` обновляется. `xmin` **может** измениться из-за отметки проверки — не утверждать обратное.
- Чтобы проверить отсутствие content UPDATE, в рамках теста создать временный audit trigger `AFTER UPDATE OF raw_detail_json` на `vulnerability_passports`; счётчик trigger не увеличивается при равном JSON, увеличивается при изменении `description`, удалении ключа и изменении вложенного списка. Удалить trigger в `finally`, т.к. `test_db` очищает строки, а не DDL.
- Detail job после пачки из одного равного и одного изменённого JSON: `processed_count == 2`, `loaded_count == 2`, `failed_count == 0`.
- Новый ID вставляется; malformed старый `raw_detail_json` не ломает сравнение, а заменяется валидным detail.

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py -q -k 'unchanged or content or counters'` → RED на content trigger. Не строить тест на сравнении времени с реальными sleeps: monkeypatch `db.now_utc` фиксированными последовательными timestamps.

### 8. GREEN: репозиторий сравнения деталей, 2–5 минут на функцию

Новый файл `app/repositories/passport_content.py`; весь новый SQL остаётся здесь:

```python
from __future__ import annotations

import json
from typing import Any

import psycopg


def partition_details(
    conn: psycopg.Connection[dict[str, Any]],
    details: list[tuple[str, dict[str, Any]]],
    current: str,
) -> list[tuple[str, dict[str, Any]]]:
    if not details:
        return []
    rows = conn.execute(
        "SELECT internal_id, raw_detail_json FROM vulnerability_passports WHERE internal_id = ANY(%s)",
        ([identifier for identifier, _ in details],),
    ).fetchall()
    previous = {row["internal_id"]: row["raw_detail_json"] for row in rows}
    changed: list[tuple[str, dict[str, Any]]] = []
    unchanged: list[str] = []
    for identifier, detail in details:
        raw = previous.get(identifier)
        try:
            old = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            old = None
        if isinstance(old, dict) and json.dumps(old, sort_keys=True) == json.dumps(detail, sort_keys=True):
            unchanged.append(identifier)
        else:
            changed.append((identifier, detail))
    if unchanged:
        conn.execute(
            "UPDATE vulnerability_passports SET detail_updated_at = %s, last_seen = %s WHERE internal_id = ANY(%s)",
            (current, current, unchanged),
        )
    return changed
```

В `app/db.py:_upsert_vulnerability_passport_details`:

1. Вернуть 0 сразу при пустом `details`.
2. **До чтения и partition** вызвать существующий `_lock_vulnerability_passport_writes(conn)`.
3. Сохранить `loaded_count = len(details)`; вызвать `partition_details(conn, details, current)`; только для returned changed построить `vulnerability_passport_detail_values`, сортировать и выполнять прежний SQL.
4. `reconcile_links=True`: передавать только IDs изменённых/новых деталей; при пустом changed не вызывать relink.
5. Возвращать `loaded_count`, а не число changed, чтобы не сломать счётчики batch job. Не менять одиночный принудительный PUT: он остаётся существующим явным обновлением.

Существующий detail worker выполняет один общий relink после успешно загруженной пачки/прохода. Для MVP это оставить; оптимизация полного relink на полностью неизменившемся проходе — отдельная задача, не новый счётчик схемы ради этой фичи.

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py tests/integration/test_passport_lock_order_db.py tests/test_passport_sync.py -q` → GREEN. Checkpoint commit: `perf: avoid rewriting unchanged passport detail content`.

### 9. RED: резервирование расписания, 2–5 минут на группу

В `tests/integration/test_periodic_passport_sync_db.py` добавить проверки нового `app.repositories.passport_refresh.reserve_periodic`:

| Сценарий | Точное ожидание |
|---|---|
| Истории нет, active detail/catalog нет | Возвращает `queued` operation с `request.trigger == 'periodic'`. |
| Вторая попытка в тот же момент | Возвращает `None`, всего одна active catalog operation. |
| Предыдущая automatic completed, interval не прошёл | `None`. |
| Ровно `finished_at + interval` | Новая queued operation. |
| Последняя ручная операция новее automatic | Интервал определяется automatic, не ручной. |
| Последняя automatic `failed`, `cancelled` | Не чаще configured interval, без restart storm. |
| `interrupted` после рестарта | Одна немедленная повторная попытка; следующий tick видит active и пропускает. |
| Есть active detail job | `None`, новую catalog operation не создавать. |
| Два параллельных соединения через Barrier | Только одно резервирование; нет uncaught UniqueViolation. |

Фиксированные времена: `2026-11-08T10:00:00+00:00` и interval 3600; вычислять future в тестах через `timedelta`, не строковую арифметику. Fake clock передаётся аргументом `now`.

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py -q -k reserve` → AttributeError RED.

### 10. GREEN: атомарная reservation без новой миграции, 2–5 минут

В `app/repositories/passport_refresh.py` добавить imports `datetime, timedelta`, `uuid`, `psycopg`, затем функцию:

```python
def reserve_periodic(request: dict[str, Any], *, now: datetime, interval_seconds: int) -> dict[str, Any] | None:
    db.init_db()
    try:
        with db.connect() as conn:
            acquired = conn.execute(
                "SELECT pg_try_advisory_xact_lock(hashtext(%s)) AS acquired",
                ("mpvm.passport-periodic-reservation",),
            ).fetchone()["acquired"]
            if not acquired:
                return None
            active = conn.execute(
                "SELECT 1 FROM operations WHERE kind = %s AND status = ANY(%s) LIMIT 1",
                (KIND, list(ACTIVE)),
            ).fetchone()
            details = conn.execute(
                "SELECT 1 FROM vulnerability_passport_detail_jobs WHERE status = ANY(%s) LIMIT 1",
                (list(ACTIVE),),
            ).fetchone()
            if active or details:
                return None
            previous = conn.execute(
                "SELECT status, finished_at, created_at FROM operations "
                "WHERE kind = %s AND request_json::jsonb ->> 'trigger' = %s "
                "ORDER BY created_at DESC, operation_id DESC LIMIT 1",
                (KIND, "periodic"),
            ).fetchone()
            if previous and previous["status"] != "interrupted":
                anchor = datetime.fromisoformat(previous["finished_at"] or previous["created_at"])
                if now < anchor + timedelta(seconds=interval_seconds):
                    return None
            identifier = str(uuid.uuid4())
            stamp = now.isoformat(timespec="seconds")
            return db.register_operation(
                identifier, kind=KIND, source_id=identifier, status="queued", stage="queued",
                subject_type="vulnerability_passports", subject_label="Паспорта уязвимостей",
                message="Плановая проверка паспортов поставлена в очередь.",
                request={**request, "trigger": "periodic"}, created_at=stamp, updated_at=stamp,
                _conn=conn,
            )
    except psycopg.errors.UniqueViolation:
        return None
```

Advisory lock держать только до завершения короткой транзакции reservation, не во время HTTP. Partial unique index — окончательная защита от одновременного ручного catalog refresh. `register_operation(..., _conn=conn)` существует и сохраняет operation event в той же транзакции.

Перед применением подтвердить типы `request_json/finished_at` в текущей схеме: сейчас operation payload хранится JSON-текстом, timestamps — ISO-текстом. Если на другой ветке тип поменялся, адаптировать decoder, а не приводить незнакомые типы вслепую. Историю `operations` не чистить ради расписания; при удалении последней automatic operation следующая проверка будет немедленной — документированный безопасный эффект.

Проверка: `pt tests/integration/test_periodic_passport_sync_db.py tests/integration/test_passport_catalog_state_db.py -q` → GREEN. Checkpoint commit: `feat: reserve periodic passport refreshes atomically`.

### 11. RED: parent cancellation и полное завершение, 2–5 минут на группу

В `tests/test_passport_sync.py:PassportDetailWorkerTests` добавить:

- parent event установлен до старта → ни одного detail HTTP-запроса, terminal `cancelled`;
- parent установлен после первой пачки → новые futures больше не ставятся, уже начатые безопасно завершаются;
- собственная отмена detail job продолжает работать без parent event;
- закрываются HTTP-сессии и удаляется cancellation registration при ошибке/отмене.

В `tests/test_passport_refresh.py` добавить тесты `complete_after_details=True` с injected callback и in-memory persisted job:

- callback видит родителя `running`, финальный `completed` ещё не записан;
- child `completed` → parent completed;
- child `completed_with_errors` → parent completed_with_errors;
- child `failed` → parent failed;
- parent/child cancelled → parent cancelled;
- child missing после callback → parent failed, не successful;
- trend failed + child completed → parent completed_with_errors;
- нет details/пустой подтверждённый каталог → completed;
- `complete_after_details=False` сохраняет существующий submit-путь и прежний тест `test_refresh_worker_records_completion_and_queues_detail_job`.

Проверка: `pt tests/test_passport_refresh.py tests/test_passport_sync.py -q` → RED новых опций.

### 12. GREEN: parent cancellation, 2–5 минут

`app/services/vulnerability_passport_jobs.py:run_vulnerability_passport_detail_job`: добавить keyword-only `parent_cancel_event: threading.Event | None = None`, локальную функцию:

```python
def cancelled() -> bool:
    return cancel_event.is_set() or (parent_cancel_event is not None and parent_cancel_event.is_set())
```

В пределах **этой функции** заменить проверки отмены в `submit_next`, проверке до запуска пула и выборе terminal status на `cancelled()`. Не менять существующий individual-error handling, semaphore, limits или `unregister_vulnerability_passport_detail_job`.

Проверка: `pt tests/test_passport_sync.py -q -k PassportDetailWorkerTests` → GREEN. Checkpoint commit: `feat: propagate catalog cancellation to passport detail workers`.

### 13. GREEN: periodic parent ждёт детали, 2–5 минут на ветку

`app/services/passport_refresh.py:run` добавить `*, complete_after_details: bool = False`. Сохранить default submit-путь **буквально по смыслу**. В новом режиме перед выполнением callbacks обновить родителя `running/stage='details'/percent=96`, затем:

```python
for task in tasks.tasks:
    if cancel_event.is_set():
        raise RefreshCancelled()
    kwargs = {**task.kwargs, "parent_cancel_event": cancel_event}
    task.func(*task.args, **kwargs)
```

Это допустимо, потому что `_execute_vulnerability_passport_query` сейчас кладёт в этот `BackgroundTasks` только синхронную detail-функцию. Не использовать этот код как общий исполнитель произвольных async tasks.

После callbacks перечитать detail job через `db.get_vulnerability_passport_detail_job` по `result['detail_job']['job_id']`. Если details callback был не нужен, job с `eligible_count=0` уже имеет completed. Выбор статуса в periodic режиме строго по таблице:

| Условие в порядке приоритета | Parent terminal |
|---|---|
| parent event / child cancelled | cancelled |
| child отсутствует, child failed/interrupted или остался queued/running/cancelling | failed |
| child completed_with_errors либо trend failed | completed_with_errors |
| иначе | completed |

До вызова callback добавить его `job_id` в `result.detail_job` родителя, чтобы связь видна в operations даже при interruption. Если отмена случилась **до выполнения** queued detail callback: установить его собственный event, вызвать `db.finish_vulnerability_passport_detail_job(..., status='cancelled', message='Parent refresh cancelled before detail start.')`, удалить регистрацию `passport-detail`; не оставлять вечную queued job. При исключении в periodic ветке аналогично завершить ещё не начатую дочернюю job как failed. Уже завершённый child не перезаписывать.

Чтобы не дублировать финальные сообщения/терминальные проверки, выделить из `run` маленький private helper выбора terminal status и покрыть таблицу parametrized тестом. Не менять терминальную защиту `passport_refresh.update`.

Проверка: `pt tests/test_passport_refresh.py tests/test_passport_sync.py tests/test_catalog_compliance_boundaries.py -q` → GREEN. Checkpoint commit: `feat: finish periodic passport refresh after detail synchronization`.

### 14. RED: scheduler без браузера и без storm, 2–5 минут на группу

Новый файл `tests/test_passport_scheduler.py`. Тестировать новую `PassportSyncScheduler` через injected runner/ready/execute callbacks и подменённый repository; никакого реального thread sleep.

Точные проверки:

- disabled: `start()` не submit-ит loop; `tick()` не обращается к MP VM/БД;
- два `start()` → один loop future; завершённый loop можно запустить снова;
- ready false → reservation и worker не вызываются;
- ready true, reservation None → execute не вызывается;
- queued reservation → execute получает правильный operation ID и полный default payload;
- исключение подключения/БД/execute логируется, loop живёт следующий tick;
- `stop()` выставляет stop event и отменяет текущий parent через registry;
- shutdown между reservation и execution → reserved operation становится cancelled, не queued навсегда;
- нет параллельных sync в одном loop: следующий tick только после окончания execute;
- loop использует `Event.wait(poll_seconds)`, а не `time.sleep(interval)`.

`pt tests/test_passport_scheduler.py -q` → import RED.

### 15. GREEN: scheduler и adapter, 2–5 минут на метод

Новый файл `app/services/passport_scheduler.py`. Полный исходный вариант класса для реализации через TDD:

```python
from __future__ import annotations

import logging
import os
import threading
from collections.abc import Callable
from concurrent.futures import Future
from datetime import UTC, datetime
from typing import Any

from ..api.schemas import VulnerabilityPassportQueryRequest
from ..core.config import Settings
from ..core.runtime import OperationRunner
from ..mpvm_client import VULNER_PASSPORT_PDQL
from ..repositories import passport_refresh

logger = logging.getLogger(__name__)


class PassportSyncScheduler:
    def __init__(
        self,
        *,
        settings: Settings,
        runner: OperationRunner,
        ready: Callable[[], bool],
        execute: Callable[[str, VulnerabilityPassportQueryRequest, threading.Event], None],
    ) -> None:
        self.settings = settings
        self.runner = runner
        self.ready = ready
        self.execute = execute
        self._stop = threading.Event()
        self._future: Future[Any] | None = None
        self._operation_id: str | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        if not self.settings.passport_sync_enabled:
            return
        with self._lock:
            if self._future is not None and not self._future.done():
                return
            self._stop.clear()
            self._future = self.runner.submit("passport-sync-scheduler", self._loop)

    def stop(self) -> None:
        self._stop.set()
        with self._lock:
            identifier = self._operation_id
        if identifier is not None:
            self.runner.cancellations.cancel("passport-refresh", identifier)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.tick()
            except Exception:
                logger.exception("Periodic passport synchronization tick failed")
            if self._stop.wait(self.settings.automation_scheduler_poll_seconds):
                return

    def tick(self, now: datetime | None = None) -> None:
        if not self.settings.passport_sync_enabled or self._stop.is_set():
            return
        if not self.ready():
            return
        payload = VulnerabilityPassportQueryRequest(
            pdql=VULNER_PASSPORT_PDQL,
            utc_offset=os.getenv("MPVM_UTC_OFFSET") or os.getenv("MP10_UTC_OFFSET") or "+05:00",
            limit=None, batch_size=5000, save_to_db=True, load_details=True,
        )
        operation = passport_refresh.reserve_periodic(
            payload.model_dump(), now=now or datetime.now(UTC),
            interval_seconds=self.settings.passport_sync_interval_seconds,
        )
        if operation is None:
            return
        identifier = operation["operation_id"]
        event = self.runner.cancellations.register("passport-refresh", identifier)
        with self._lock:
            self._operation_id = identifier
        try:
            if self._stop.is_set():
                event.set()
                passport_refresh.update(
                    identifier, status="cancelled", stage="cancelled", percent=0,
                    message="Плановая проверка отменена при остановке приложения.",
                )
                return
            self.execute(identifier, payload, event)
        except Exception:
            passport_refresh.update(
                identifier, status="failed", stage="failed", percent=0,
                message="Не удалось выполнить плановую проверку паспортов.",
            )
            raise
        finally:
            self.runner.cancellations.remove("passport-refresh", identifier)
            with self._lock:
                self._operation_id = None
```

Разбить добавление класса на методы по 2–5 минут, каждый раз исполняя соответствующие RED-тесты из шага 14. Требования, которые должны сохраниться при минимальных исправлениях после тестов:

1. `__init__`: сохранить Settings/OperationRunner, `Callable[[], bool] ready`, `Callable[[str, VulnerabilityPassportQueryRequest, threading.Event], None] execute`; создать `_stop=threading.Event()`, `_future: Future[Any] | None=None`, `_operation_id: str | None=None`, `_lock=threading.Lock()` для start/stop/current-id. Импортировать datetime UTC; `now` по умолчанию `datetime.now(UTC)`.
2. `start`: disabled → return; под `_lock` проверить future not done, очистить stop и submit `runner.submit('passport-sync-scheduler', self._loop)`.
3. `_loop`: выполнить первый tick без ожидания; затем `while not self._stop.wait(settings.automation_scheduler_poll_seconds): self.tick()`. Вокруг **каждого** tick `try/except Exception: logger.exception('Periodic passport synchronization tick failed')`; исключение не убивает loop. Логировать статическое сообщение и traceback через существующий redaction pipeline, не сериализовать credentials или payload ответа MP VM.
4. `tick`: disabled/stopped → return; `ready()` false → return; собрать `VulnerabilityPassportQueryRequest(pdql=VULNER_PASSPORT_PDQL, limit=None, batch_size=5000, save_to_db=True, load_details=True)`, utc_offset как в существующем refresh endpoint (`MPVM_UTC_OFFSET` → `MP10_UTC_OFFSET` → `+05:00`). `ready` проверяет/поднимает существующую MP VM-сессию, но не делает запрос каталога.
5. Вызвать `passport_refresh.reserve_periodic(payload.model_dump(), now=current, interval_seconds=settings.passport_sync_interval_seconds)`; None → return. Зарегистрировать parent event `runner.cancellations.register('passport-refresh', operation_id)`, записать current ID под lock. Ещё раз проверить stop; если остановлен — set event, пометить операцию cancelled и не выполнять execute.
6. Выполнить injected `execute(operation_id, payload, event)` **синхронно в этом loop worker**, не запускать второй future. В `finally` удалить cancellation registration и очистить current ID под lock. Никаких сетевых запросов или выполнения callback под `_lock`.
7. `stop`: установить stop; получить current ID под lock, снаружи вызвать `runner.cancellations.cancel('passport-refresh', id)` при наличии. Родительский event останавливает detail worker согласно шагу 12.

Добавить в `app/services/vulnerability_passport_jobs.py` полноценный adapter:

```python
def run_periodic_vulnerability_passport_refresh_job(
    operation_id: str,
    payload: VulnerabilityPassportQueryRequest,
    cancel_event: threading.Event,
) -> None:
    def execute_query(query, tasks, progress):
        return _execute_vulnerability_passport_query(query, tasks, progress, force_details=True)

    passport_refresh_service.run(
        operation_id,
        payload,
        execute_query,
        host.CONTAINER.operation_runner.submit,
        cancel_event,
        complete_after_details=True,
    )
```

Scheduler владеет removal parent registration, detail worker — removal child registration. Явно тестировать cleanup при исключении; не удалять чужой token.

Проверка: `pt tests/test_passport_scheduler.py tests/test_passport_refresh.py -q` → GREEN. Checkpoint commit: `feat: run passive passport synchronization on a backend schedule`.

### 16. RED → GREEN: lifecycle wiring, 2–5 минут

Файлы: `tests/test_database_recovery.py`, `app/services/startup.py`, `app/main.py`, `app/core/container.py`.

Сначала добавить тест startup stage: `passport_sync_scheduler` выполняется **после** `passport_jobs`, `passport_refresh`, `automation_resume`; до успешной database readiness не вызывается. Shutdown вызывает `stop()` до `CONTAINER.shutdown()`.

Проверка RED: `pt tests/test_database_recovery.py tests/test_passport_scheduler.py -q`.

Затем wiring:

- В `app/core/container.py` добавить queue limit `'passport-sync-scheduler': 1`; общие request semaphore и detail workers оставить прежними.
- В `app/main.py` импортировать класс и adapter; после определения session readiness helpers создать singleton `PASSPORT_SYNC_SCHEDULER = PassportSyncScheduler(settings=SETTINGS, runner=CONTAINER.operation_runner, ready=mpvm_session_connected, execute=run_periodic_vulnerability_passport_refresh_job)`. Убедиться, что `mpvm_session_connected` уже импортирован/привязан в этой точке, и что singleton создан до любого startup вызова. Не копировать сюда scheduler body.
- В конце списка `database_startup_steps` после существующего `scheduler` добавить `('passport_sync_scheduler', lambda: runtime.PASSPORT_SYNC_SCHEDULER.start())`.
- В `shutdown()` перед `CONTAINER.shutdown()` вызвать `PASSPORT_SYNC_SCHEDULER.stop()`.
- Сохранить existing startup interruption: `interrupted` periodic operation reservation повторит один раз; checkpoints recovery не должны создавать дубликаты loop.

GREEN: `pt tests/test_database_recovery.py tests/test_passport_scheduler.py tests/test_architecture.py -q`. Checkpoint commit: `feat: wire passport synchronization into application lifecycle`.

### 17. RED → GREEN: end-to-end backend сценарии на fake MP VM, 2–5 минут на сценарий

Дополнить `tests/integration/test_periodic_passport_sync_db.py`; настоящий PostgreSQL, но fake transport/client и детерминированный clock. Через `scheduler.tick(now=...)` выполнить реальный query service и detail batch path; заглушить только внешнюю сеть и тренды при необходимости. Не подменять `db.upsert_*` в этих тестах.

1. Первый проход: remote `p1(description='old')`; локально появляется p1, parent/child completed.
2. До interval: fake remote вызовов не добавилось.
3. После interval: тот же p1 с **изменением только detail description**, плюс новый p2; p1 обновлён несмотря на свежий TTL, p2 добавлен, total 2, нет дублей.
4. Третий проход без изменений: `db.changed == 0` для каталога, content trigger деталей не сработал, отметки проверки обновлены.
5. Перевыпуск p1 → p1-new с тем же external ID/package: existing replacement переносит findings и remediation, старого p1 нет, свежие details загружаются для p1-new. Не копировать устаревшие детали как окончательно успешные.
6. Два возможных successor: не склеивать, ambiguous > 0; никаких потерянных ссылок.
7. HTTP timeout/401/404/неполная страница: parent failed либо completed_with_errors по этапу; старые details не стираются, успешные пачки остаются, следующее расписание не блокируется навсегда.
8. Обрыв после queued catalog / после queued detail: существующий startup interruption + tick создают одну повторную попытку, успешные записи не дублируются.
9. Ручной refresh/detail уже running: periodic пропускается без лишнего remote catalog request; ручной endpoint сохраняет 202/409 контракты.
10. Отмена parent во время detail: child и parent cancelled, next automatic attempt не немедленно, а по interval.
11. Query через существующую automation `passport_sync` и ручной query сохраняет default TTL; periodic force не является глобальной настройкой, протекающей на соседний вызов.

RED каждого сценария подтвердить командой `pt tests/integration/test_periodic_passport_sync_db.py -q -k '<имя_сценария>'`; затем только минимальное исправление, GREEN тем же selector и всем файлом. Не «чинить» тесты отключением ограничений полноты, отмены, транзакций и RBAC. Checkpoint после группы GREEN: `test: cover passive passport synchronization and recovery`.

### 18. Документация и полная проверка, отдельные шаги по 2–5 минут

`README.md`, раздел паспортов: добавить конфигурацию, работу без браузера, задержку до 30 секунд относительно interval, immediate first run, поведение после рестарта/ошибки, необходимость unattended подключения, стоимость полной detail-проверки, команды просмотра `/operations`/logs. Пример конфигурации — без реальных credentials:

```dotenv
MPVM_PASSPORT_SYNC_ENABLED=true
MPVM_PASSPORT_SYNC_INTERVAL_SECONDS=3600
```

Не редактировать рабочий `.env` и не включать фичу на реальном стенде без отдельного поручения. `docker-compose.yml` менять не требуется: текущий сервис уже использует `env_file`. Не читать файл `.env` ради проверки.

В `docs/testing.md` добавить новые тестовые сценарии, не обновлять исторические итоги прогонов вымышленными числами.

Последовательные команды из корня; ожидается exit 0, новые интеграционные тесты не skipped:

```bash
pt tests/test_passport_snapshot_validation.py tests/test_passport_scheduler.py tests/test_passport_refresh.py tests/test_passport_sync.py tests/test_passport_replacement_plan.py tests/test_settings_and_oauth_boundaries.py tests/test_database_recovery.py tests/test_catalog_compliance_boundaries.py -q
pt tests/integration/test_periodic_passport_sync_db.py tests/integration/test_passport_catalog_state_db.py tests/integration/test_passport_reconcile_perf_db.py tests/integration/test_passport_lock_order_db.py tests/integration/test_migrations_db.py tests/integration/test_rbac_matrix_db.py -q

docker compose -p mpvm-passport-sync-tests -f compose.test.yml run --rm --build tests ruff check app/core app/api app/automations app/domain app/mpvm app/repositories app/services app/factory.py mcp_server tests/test_architecture.py tests/test_automations.py tests/mcp_server tests/test_passport_scheduler.py tests/test_passport_snapshot_validation.py tests/integration/test_periodic_passport_sync_db.py

docker compose -p mpvm-passport-sync-tests -f compose.test.yml run --rm --build tests mypy app/core app/api app/automations app/domain app/mpvm app/repositories app/services app/factory.py mcp_server

docker compose -p mpvm-passport-sync-tests -f compose.test.yml run --rm --build tests python -m pytest -p no:cacheprovider --cov=app --cov-branch --cov-report=term-missing --cov-report=json:output/coverage-python.json

docker compose -p mpvm-passport-sync-tests -f compose.test.yml --profile frontend run --rm --build --no-deps frontend-tests

docker compose -p mpvm-passport-sync-tests -f compose.test.yml run --rm --no-deps tests sh -c 'python scripts/check_coverage_thresholds.py --report output/coverage-python.json && python scripts/check_coverage_ratchet.py --python output/coverage-python.json --frontend output/coverage-js/coverage-summary.json'

git diff --check
git diff --stat
git status --short
```

Ruff: `All checks passed!`; mypy: `Success: no issues found ...`; pytest: passed, без новых skip; frontend container выполняет свой Vitest/lint/format/build pipeline. Пороги coverage не снижать. `app/core/config.py`, `app/repositories/passport_refresh.py` и `app/services/passport_refresh.py` уже находятся под строгими module floors: покрыть все добавленные ветки, а не ослабить конфиг.

Frontend/e2e интерфейс не меняется; при обнаружении изменений маршрутов/операций/UI выполнить также:

```bash
docker compose -p mpvm-passport-sync-tests -f compose.test.yml --profile frontend run --rm --build --no-deps e2e
```

Если старые unrelated тесты уже падают, зафиксировать baseline отдельно, но не объявлять всю задачу проверенной. Не запускать backend-наборы параллельно против одной test DB. Не останавливать рабочий Compose project и не удалять volumes.

Финальный checkpoint: `docs: describe passive passport synchronization`. В отчёте перечислить изменённые файлы, реальные выполненные команды/результаты, оставшиеся ограничения; отдельно отметить, что production sync не включался и live MP VM не проверялся.

## Tests / validation: критерии приёмки

- [ ] При включённой фиче backend сам начинает проверку, даже если браузер не открыт.
- [ ] Интервал валидируется, работает по сохранённой истории и не превращается в бесконечную очередь пропущенных запусков.
- [ ] Новые паспорта добавляются; изменения каталога и **только деталей** обнаруживаются в ближайшем успешном проходе.
- [ ] TTL ручных операций сохранён, автоматические проверки его обходят явно.
- [ ] Равное detail-содержимое не получает content UPDATE; JSON object key order не считается изменением, порядок списков считается.
- [ ] Неполный/непроверенный пустой catalog response не запускает replacement и не повреждает последнюю локальную версию.
- [ ] Перевыпуск паспорта сохраняет links/remediation и существующие правила неоднозначности.
- [ ] Parent automatic operation не completed до завершения details; progress/cancel/errors видны через прежние operations APIs.
- [ ] Отмена/shutdown/restart не оставляют вечную queued/running работу, повтор идемпотентен.
- [ ] Нет сетевых операций, изменяющих удалённые паспорта или активы, нет токенов в request/results/logs.
- [ ] Unit/integration/lint/type-check/coverage/build выполнены только в Docker, против отдельной PostgreSQL.
- [ ] Поведение существующих ручных и automation `passport_sync` вызовов покрыто регрессиями.

## Risks, tradeoffs, and open questions

1. **Нагрузка полной проверки деталей.** Без remote revision/checksum изменение description невозможно гарантированно вывести из каталога. MVP сознательно выполняет N detail GET на проход; лимитирует существующим semaphore и worker count. Если проход длится дольше часа, новый начнётся через час после его окончания. Для больших инсталляций согласовать более редкий интервал; не вводить недоказанный incremental API.
2. **Интервал и включение — продуктовые defaults.** Пользователь не задал частоту и способ управления. В плане выбран opt-in + 3600 секунд + env. Это не блокирует реализацию; если требуется UI или включение сразу после установки — отдельное подтверждение/изменение scope.
3. **Согласованность snapshot.** Проверка total/duplicates обнаруживает ряд неполных снимков, но при неизвестном total не может доказать snapshot isolation remote API. Нет массового удаления несопоставленных локальных записей. При нестабильном каталоге безопаснее failed и повтор, чем агрессивная очистка.
4. **Процессная модель.** Reservation конкурентно защищена PostgreSQL, но текущая global startup interruption/session архитектура рассчитана не на независимые backend workers. Для HA потребуется отдельный lease/heartbeat и owner-aware recovery; не заявлять это реализованным.
5. **Доступ после рестарта.** Runtime browser connection может исчезнуть; unattended credentials должны быть настроены на сервере. Не сохранять пароли/токены в scheduler operation. Существующий token-refresh transport проверять по текущему коду, не писать параллельную auth-систему.
6. **История операций как расписание.** Очистка последней periodic operation делает следующую проверку немедленной. Для MVP безопасно; если нужна независимость от retention/clear-history, понадобится singleton schedule table и Alembic, а не скрытая зависимость от памяти процесса.
7. **Метки свежести против содержимого.** Даже неизменившиеся паспорта получают отметки проверки; это ожидаемые служебные writes, не изменение паспорта. `loaded_count` не использовать как `changed_count`.
8. **Старые детали при remote ошибке.** Если каталог обновился, а detail запрос упал, локальная запись может временно содержать новый summary и прежний detail. Не стирать рабочую detail-версию; показывать child errors, повторять по расписанию. Полная двухфазная staging-замена всей БД не входит в MVP.
9. **Новый endpoint и RBAC.** Новый API не добавляется, существующая backend авторизация остаётся обязательной. Если позднее появится настройка в UI, ограничить изменения admin и добавить `expected_version`/audit; одного скрытия кнопки недостаточно.
10. **Текущий blocker проверок.** Docker daemon при исследовании не работал. Пока проверки реально не выполнены в Docker, никакую реализацию не объявлять завершённой.
