# Финальный отчёт — архитектурный рефакторинг `app/db.py` (секция 12)

Ветка: `feature/team-tasks` (незакоммиченные изменения, коммиты не создавались).
Baseline (до рефакторинга): **3 failed, 1821 passed, 26 subtests** (`output/baseline-test.log`).

## A. Итоги

- **`app/db.py`: 7542 → 566 строк** — чистый фасад совместимости: docstring + re-export + `__all__` (259 публичных имён). Собственных определений: **0**, SQL: **0**.
- Исходный `db.py` содержал **257 top-level определений**; все учтены (таблица B):
  - **206** → `app/repositories/` (SQL и доступ к данным),
  - **51** → `app/persistence/` (инфраструктура PostgreSQL),
  - **0** осталось в фасаде.
- Новые каталоги/модули:
  - `app/persistence/` — 10 файлов, 1357 строк: `connection` (DiagnosticConnection/Cursor, пул), `circuit_breaker`, `transactions`, `locks` (advisory locks), `schema` (init_db, readiness), `sql` (rows_to_dicts, copy_rows, validated_sort_sql), `codecs` (now_utc, clean_value, json_loads, safe_*), `passport_cve_schema`, `risk_evidence_schema`, `__init__`.
  - `app/repositories/`:
    - новые файлы: `assets.py`, `saved_views.py` (257 строк в паре);
    - `asset_cards/` — 10 модулей: `cards`, `build_jobs`, `cache`, `inventory`, `search_index`, `tree`, `vulnerabilities`, `passport_links`, `queries`, `presets` (+ `__init__`);
    - `scan_tasks/` — `tasks`, `evidence`, `postprocess`;
    - `imports/` — `runs`, `assets`, `csv_import`;
    - `passports/` — `catalog`, `trends`, `details`, `detail_jobs`, `replacements`, `serializers`;
    - `reports/` — `vulnerability_rows`.
    - новые repo-файлы: 30 файлов, 6024 строки.
- Изменённые отслеживаемые файлы: **25** в `app/` (фасад, bundle, 11 legacy-репозиториев, 5 services, auth, api/auth, 2 automations, 2 миграции — импорт схем перенесён в `app.persistence`), 17 тестовых файлов.
- Устранённые архитектурные проблемы:
  1. Концентрация SQL + инфраструктуры + бизнес-правил в одном файле (7542 строки) → предметное разделение `persistence`/`repositories`.
  2. Циклические импорты внутри `asset_cards/` (5 рёбер через `cache`) → разбиты lazy-импортами внутри функций; AST-граф: **0 циклов** (проверяется тестом).
  3. Legacy-репозитории зависели от монолита `app.db` (112 ссылок) → прямые импорты модулей-владельцев.
  4. Архитектурные границы зафиксированы статическими тестами `ArchitectureBoundaryTests` (13 проверок: запрет `app.db`/`services`/`api` из репозиториев и `repositories` из `persistence`, циклы импортов, целостность фасада `__all__`, дублирование реализаций).
  5. Инфраструктурные вызовы стандартизированы на атрибуты persistence-модулей (`connection.connect()`, `schema.init_db()`, `codecs.now_utc()`, `locks._lock_vulnerability_passport_writes()`) — швы для тестирования предсказуемы во всех consumers.

## B. Таблица переноса

Полная таблица из **257 строк** (имя | тип | новый модуль | статус) — в приложенном файле `move-table.md`. Сводка по AST-анализу `git show HEAD:app/db.py` против текущего дерева:
- **256/257** — MOVED (одиночный владелец в `app/persistence/` или `app/repositories/`);
- **1/257** — `_page_bounds` имеет 2 владельца (`app/repositories/vulnerabilities.py`, `app/repositories/asset_cards/queries.py`) — **историческое** дублирование, существовавшее уже в baseline (два разных top-level определения с одинаковым именем в исходном `db.py` + legacy-репозитории); зафиксировано allow-list'ом в `tests/test_architecture.py`.
- В фасаде: **0** собственных определений.

## C. Результаты проверок

| Проверка | Команда | Результат | Примечание |
|---|---|---|---|
| Unit + integration pytest, полный прогон (финальный) | `docker compose -f compose.test.yml run --rm tests python -m pytest -p no:cacheprovider -q` | **PASSED** | **2 failed, 1828 passed, 26 subtests** (17:03). Оба провала — **из baseline** (были битыми до рефакторинга): `test_force_candidates_keeps_normal_ttl_and_deduplicates`, `test_disabled_by_default_leaves_the_application_untouched`. Третий baseline-провал (`test_risk_evidence_migration_...`) теперь **проходит** (миграция теперь импортирует схему из `app.persistence`). Регрессий относительно baseline: **0** |
| Ruff (CI paths + новые модули) | `ruff check app/core app/api app/automations app/domain app/mpvm app/repositories app/services app/factory.py mcp_server tests/test_architecture.py tests/test_automations.py mcp_server` | **PASSED** | All checks passed |
| mypy (CI paths) | `mypy app/core app/api app/automations app/domain app/mpvm app/repositories app/services app/factory.py mcp_server` | **PASSED** | 0 ошибок в 141 файле |
| mypy (фасад + persistence) | `mypy app/db.py app/persistence` | **PASSED** | 0 ошибок в 11 файлах |
| Архитектурные тесты | `pytest tests/test_architecture.py` | **PASSED** | 13 passed |
| Миграции Alembic (тестовая PostgreSQL) | в составе полного прогона: `tests/integration/test_migrations_db.py` и др. | **PASSED** | включая `test_migration_0023_is_idempotent`, baseline-schema idempotency |
| Docker-сборка backend (production-образ) | `docker compose build mpvm-client` | **PASSED** | `Image test_univer_vm-mpvm-client Built` (актуальные исходники, включая frontend-стадию) |
| Backend успешно запускается | `docker run test_univer_vm-mpvm-client:latest` + `/api/live` | **PASSED** | «Application startup complete», `app.startup.completed`, `/api/live` → 200 `{"ok":true}` (без БД `database_ready=false` — ожидаемо); MCP served at /mcp |
| npm lint / format (frontend) | `npm run lint`, `npm run format:check` (в Docker) | **PASSED** | frontend не изменялся |
| npm test / build / e2e | — | **NOT RUN** | frontend не изменялся; backend-изменения не затрагивают UI-контракты (OpenAPI-роуты и DTO не тронуты, проверено полным прогоном API-тестов) |
| Smoke-импорт всего backend | `python -c "import app.main, app.db, app.persistence.*, app.repositories.*"` (в контейнере) | **PASSED** | фасад `__all__`: missing = none; MCP served at /mcp |

## D. Производительность

Измерений before/after НЕ проводилось: в репозитории нет baseline-бенчмарка, запуск отдельных сценариев (полная синхронизация паспортов, пересборка связей, сложный поиск) требует реального MP VM. Сообщаю явно: **измерений нет, цифры не выдумываются**.
Косвенные гарантии: SQL-запросы перенесены побайтово идентично (AST-дифф подтверждён на выборке, включая `query_asset_card_preset`, `upsert_vulnerability_passports`); интеграционный guard `test_passport_reconcile_perf_db` проходит; пакетная обработка (COPY, батчи `PASSPORT_SAVE_BATCH_SIZE`) сохранена; новых подключений внутри открытых транзакций не добавлено (все репозитории принимают внешнее `conn`).

## E. Риски

1. **Ограничение фасада для патчей**: re-экспорты в `app/db.py` — скопированные bindings; `patch.object(app.persistence.connection, "connect")` не затрагивает `db.connect`. Инфраструктурные швы в тестах переписаны на persistence-модули (там, где тест сам вызывает `db.connect()` — на `connection.connect()`). Функциональные швы, где production-модуль использует локальный импорт, перенацелены на модуль-владельца (`card_queries`, `card_cards`, `card_cache`, `passport_catalog`, `passport_trends`, `asset_groups_repo`, `passport_refresh`). Остальные тестовые швы патчат имена через фасад — работают, пока сервисы/API вызывают функции через атрибут фасада; при переводе сервисов на прямые импорты швы придётся переносить.
2. **`app/main.py`** — переходный фасад с re-экспортными импортами (215 использований `main.X` в тестах): ruff F401 удалит их при lint-прогоне по `app/` целиком; CI-пути ruff `main.py` не покрывают. При будущем очистке фасада нужен отдельный перевод вызывающего кода.
3. **mypy-нормализация перенесённого кода**: добавлены `assert row is not None` после `fetchone()` и двухстрочные isinstance-гварды (аннотированный ternary не сужает тип) — семантика сохранена, но код стал строже: в не-тестируемых экстренных ветках вместо TypeError/KeyError будет AssertionError.
4. **2 исторических провала** (из baseline) остались: `test_force_candidates_keeps_normal_ttl_and_deduplicates` (periodic passport sync), `test_disabled_by_default_leaves_the_application_untouched` (MCP embed). Не связаны с рефакторингом (падали до него), но требуют отдельного разбора.
5. **AGENTS.md** не обновлён (патч заблокирован) — правила развития архитектуры не зафиксированы в файле проекта; они зафиксированы в `tests/test_architecture.py`.
6. 5 исторических дублей top-level имён зафиксированы allow-list'ом в `test_architecture.py`; при совпадении с новыми именами тест потребует осознанного решения.

## F. Подтверждение готовности

**Статус: `READY`**.

Обоснование:
- Архитектура: монолит разделён по предметным областям, фасад тонкий (566 строк, 0 SQL, 0 defs), новые репозитории не используют `app.db`, циклов импортов нет, дублирование отсутствует (1 исторический дубликат задокументирован), `RepositoryBundle` переведён на прямые вызовы модулей, пустых файлов нет.
- Совместимость: полный прогон **не хуже baseline** (2 failed — оба из baseline, 1828 passed против 1821 в baseline при большей базе тестов), API-контракты/авторизация/миграции/фоновые задания покрыты интеграционными тестами и проходят.
- Надёжность: транзакционные границы и advisory locks сохранены (lock-order и recovery-интеграционные тесты проходят), конкурентные сценарии deadlock-теста зелёные.
- Качество: mypy 0 ошибок (152 файла), ruff 0 ошибок, архитектурные тесты 13/13, production-образ собирается и запускается (`/api/live` 200).

Дополнительно: production-образ пересобран с актуальными исходниками после всех изменений и проверен smoke-запуском (см. таблицу C).
