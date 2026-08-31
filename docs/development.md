# Разработка и развёртывание

Этот документ описывает подтверждённый текущей конфигурацией способ разработки и запуска MP VM REST API Client. Для границ модулей и правил расширения смотрите [архитектуру](ARCHITECTURE.md), а для сценариев продукта и публичных API — [README](../README.md).

## Требования

- Python 3.14 — целевая версия для Ruff и mypy в `pyproject.toml`.
- Node.js 26.x. Версия `26` закреплена в [`.nvmrc`](../.nvmrc), а допустимый диапазон в `package.json` — `>=26.0.0 <27`.
- PostgreSQL: для локального Compose используется образ PostgreSQL 16; приложение подключается по DSN PostgreSQL.
- Docker Engine с Docker Compose — для контейнерного запуска.

Установки ниже выполняются из корня репозитория. Не добавляйте реальные учётные данные или токены в Git: создайте локальный `.env` по [`.env.example`](../.env.example).

## Локальный запуск

### PostgreSQL и backend

Поднимите только локальную базу данных из стандартного Compose-файла:

```powershell
docker compose up -d postgres
```

Создайте виртуальное окружение, установите backend-зависимости и укажите DSN к проброшенному порту PostgreSQL:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MPVM_DATABASE_URL="postgresql://mpvm:mpvm@localhost:55432/mpvm"
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend доступен по `http://127.0.0.1:8000`. При старте `app.main` вызывает инициализацию БД; она запускает Alembic до ревизии `head`. При пустой базе укажите безопасный `MPVM_BOOTSTRAP_ADMIN_PASSWORD` длиной не менее 12 символов, иначе первичный администратор не будет создан.

### Frontend

В отдельном PowerShell-окне:

```powershell
npm ci
npm run dev
```

Vite слушает `http://127.0.0.1:5173` и проксирует `/api` на backend `http://127.0.0.1:8000`. Production-сборка выполняется командой `npm run build` и записывается в `app/static`.

## Контейнерный запуск

Полный локальный контур запускается так:

```powershell
docker compose up --build
```

Стандартный `docker-compose.yml` запускает `mpvm-client` на порту `8000` и PostgreSQL на `55432`; backend ждёт успешный healthcheck PostgreSQL. Данные базы сохраняются в именованном volume `mpvm_postgres`, а `./exports` и `./output` монтируются в контейнер приложения. Не удаляйте этот volume при обновлении PostgreSQL: текущий Compose закреплён на PostgreSQL 16 и предупреждает, что major-upgrade требует отдельной процедуры `pg_upgrade`.

[`docker-compose.corpnet.example.yml`](../docker-compose.corpnet.example.yml) — вариант для корпоративной сети: он задаёт адрес MP VM и пути к данным в контейнере. Секреты из комментариев файла должны передаваться только через локальный `.env` или интерфейс приложения.

## Конфигурация

`app/core/config.py` загружает переменные с префиксом `MPVM_` из процесса и `.env`; неизвестные поля игнорируются. Образец всех доступных значений находится в [`.env.example`](../.env.example). Основные группы настроек:

| Группа | Переменные | Назначение |
| --- | --- | --- |
| Подключение к MP VM | `MPVM_API_URL`, `MPVM_TOKEN_URL`, `MPVM_USERNAME`, `MPVM_PASSWORD`, `MPVM_CLIENT_ID`, `MPVM_CLIENT_SECRET`, `MPVM_SCOPE`, `MPVM_ACCESS_TOKEN`, `MPVM_INSECURE`, `MPVM_TIMEOUT` | OAuth/password-grant либо готовый Bearer-токен и параметры TLS/timeout. `MPVM_INSECURE=true` допустим только для лабораторных/self-signed сертификатов. |
| PostgreSQL и файлы | `MPVM_DATABASE_URL`, `MPVM_EXPORTS_DIR`, `MPVM_LOG_DIR` | DSN локального состояния, каталоги экспортов и JSONL-диагностики. |
| Параллелизм и таймауты | `MPVM_BACKGROUND_REQUEST_LIMIT`, `MPVM_ASSET_CARD_REQUEST_WORKERS`, `MPVM_ASSET_CARD_REFRESH_WORKERS`, `MPVM_SCAN_POSTPROCESS_WORKERS`, `MPVM_SCAN_ASSET_PROCESS_WORKERS`, `MPVM_SCAN_TARGET_RESOLUTION_WORKERS`, `MPVM_RECONCILIATION_WORKERS` | Лимиты фоновой обработки; значения должны быть положительными. |
| Docker-группы и паспорта | `MPVM_DOCKER_DYNAMIC_GROUP_*`, `MPVM_PASSPORT_DETAIL_*`, `MPVM_ASSET_METADATA_TTL_SECONDS` | Ожидания, retention и кеширование удалённых данных. |
| Автоматизация | `MPVM_AUTOMATION_SCHEDULER_POLL_SECONDS`, `MPVM_AUTOMATION_WEBHOOK_URL`, `MPVM_AUTOMATION_WEBHOOK_SECRET`, `MPVM_COVERAGE_STALE_DAYS` | Планировщик и необязательный HTTPS webhook с HMAC-подписью. |
| Доступ в приложение | `MPVM_BOOTSTRAP_ADMIN_USERNAME`, `MPVM_BOOTSTRAP_ADMIN_PASSWORD`, `MPVM_BOOTSTRAP_ADMIN_DISPLAY_NAME`, `MPVM_AUTH_SESSION_HOURS`, `MPVM_AUTH_COOKIE_SECURE` | Начальная учётная запись и cookie-сессии. Для HTTPS включите `MPVM_AUTH_COOKIE_SECURE=true`. |

Не публикуйте пароль, client secret, access token, webhook secret или готовый `.env`. Для хостового backend DSN по умолчанию использует `localhost:5432`; при запуске базы из Compose нужен порт `55432`.

## Структура проекта

```text
app/                 FastAPI, API-роутеры, сервисы, репозитории и MP VM-клиент
app/core/            настройки, контейнер и lifecycle
app/api/             HTTP-роутеры и Pydantic DTO
app/services/        сценарии приложения и фоновые операции
app/repositories/    слой доступа к данным (в переходный период делегирует app/db.py)
app/mpvm/            транспорт и аутентификация MP VM
migrations/          Alembic-ревизии PostgreSQL
src/                 React/Vite интерфейс, features и frontend-тесты
tests/               pytest и контрактные тесты
tests/e2e/           Playwright smoke-тесты
```

`app.main`, `app.db`, `app.mpvm_client` и `src/panels.jsx` — переходные фасады для совместимости. Новый код следует добавлять в доменные слои, не расширяя эти фасады.

## База данных и миграции

Alembic настроен через [`alembic.ini`](../alembic.ini), а ревизии расположены в `migrations/versions`. Обычный запуск приложения автоматически применяет миграции. Для явного применения миграций к DSN из окружения:

```powershell
alembic upgrade head
```

Новые изменения схемы добавляйте только отдельной Alembic revision в `migrations/versions`; миграции следует проверять как на пустой БД, так и на копии текущей БД. Не используйте downgrade как способ очистки операторских данных: baseline revision намеренно не удаляет таблицы при downgrade.

## Тесты, lint и сборка

Backend-тесты определены в `pyproject.toml` (`tests/`); marker `integration` требует доступный PostgreSQL:

```powershell
python -m pytest
python -m pytest -m integration
```

Frontend и браузерные проверки:

```powershell
npm test
npm run test:coverage
npm run test:e2e
```

Playwright запускает Vite на `http://127.0.0.1:4173`; отчёты и артефакты сохраняются в `output/playwright/`. Проверки качества и production-сборка:

```powershell
ruff check app/core app/api app/domain app/mpvm app/repositories app/services app/factory.py tests/test_architecture.py
mypy app/core app/api app/domain app/mpvm app/repositories app/services app/factory.py
npm run lint
npm run format:check
npm run build
```

`npm run quality` объединяет frontend lint, unit-тесты и сборку. `npm run coverage:check` требует предварительно созданные отчёты `output/coverage-python.json` и `output/coverage-js/coverage-summary.json`.

## Подтверждённые проблемы и диагностика

- **Vitest `ERR_REQUIRE_ESM`.** В текущем окружении зафиксирована зависимостная проблема цепочки `jsdom` → `html-encoding-sniffer` → `@exodus/bytes`; переход на Node 26 сам по себе её не устраняет. Не интерпретируйте это как успешный frontend-тест и не отключайте тесты для зелёного результата.
- **Нет подключения к PostgreSQL.** Проверьте, что сервис `postgres` здоров (`docker compose ps`), и что host-DSN указывает на `localhost:55432`, а контейнерный — на `postgres:5432`. Приложение ограничивает время подключения и временно открывает circuit breaker после ошибки.
- **Планировщик после перезапуска не действует от browser-сессии.** Для плановых запусков нужны server-side `MPVM_*` учётные данные; сессия, созданная только в браузере, не сохраняется как service account.
- **Ошибки интеграции с MP VM.** Проверяйте `GET /api/system/status`, JSONL в `MPVM_LOG_DIR` (по умолчанию `output/logs`) и корреляционные заголовки `X-Trace-ID`/`X-Request-ID`. Для self-signed TLS используйте `MPVM_INSECURE=true` только в лабораторном контуре.
