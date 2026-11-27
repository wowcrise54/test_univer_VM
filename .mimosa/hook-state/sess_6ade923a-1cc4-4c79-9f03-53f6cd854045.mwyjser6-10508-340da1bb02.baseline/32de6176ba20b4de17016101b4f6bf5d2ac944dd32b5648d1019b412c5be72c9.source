# Тестовые demo-данные MP VM

Тестовый профиль использует отдельный Compose-проект `mpvmtest-tests` и временную PostgreSQL 16 (`tmpfs`). Рабочий `docker-compose.yml` и его постоянный volume не используются.

Запустить миграции и идемпотентную загрузку:

```powershell
docker compose -f compose.test.yml --profile demo run --rm seed-demo
```

Для очистки только demo-записей:

```powershell
docker compose -f compose.test.yml --profile demo run --rm seed-demo python scripts/seed_demo.py --clean
```

Запустить приложение для ручной проверки:

```powershell
docker compose -f compose.test.yml --profile demo up -d demo-app
```

Откройте `http://127.0.0.1:18000` и войдите как `demo-admin` с паролем `demo-only-pass`. Учётная запись задана только в профиле `demo-app`; MP VM endpoint и credentials не подключаются, а сценарии удаления представлены локальными записями операций.

Фикстуры `archive_response_samples.json` включают обезличенные формы ответов, извлечённые из архива поддержки; связка request/response выполнена по `remote_request_id`. Две паспортные записи в `passport_query_response.json` извлечены из реального ответа `assets_grid/data`, где присутствуют поля `@VulnerPassport` и compact CVE. В них заменены названия, внешние ID, версии и временные метки; CVE и структура ответа сохранены. Повторный запуск сохраняет фиксированные demo-ID и не создаёт дубли.

## Масштабный профиль

Для нагрузки 500 карточек, 500 000 паспортов и 1 000 000 находок используется отдельная PostgreSQL 16 в persistent volume `mpvmtest_scale_postgres`:

```powershell
# Быстрая проверка логики на 2 карточках, 10 паспортах и 20 находках
docker compose -f compose.test.yml --profile scale run --rm scale-seed python scripts/seed_scale.py --profile small

# Полный набор 500 / 500000 / 1000000
docker compose -f compose.test.yml --profile scale run --rm scale-seed

# Продолжить прерванную загрузку по детерминированным ID
docker compose -f compose.test.yml --profile scale run --rm scale-seed

# Удалить только scale-demo данные из scale-БД
docker compose -f compose.test.yml --profile scale run --rm scale-seed python scripts/seed_scale.py --clean

# Большая версия приложения слушает только localhost:18001
docker compose -f compose.test.yml --profile scale up -d scale-app
docker compose -f compose.test.yml --profile scale run --rm scale-ui-smoke
```

Scale seed выполняет пакетный `COPY`, сверяет количество находок, links, root nodes и group members; resume разрешён только когда существующие ID образуют непрерывный префикс. Иначе он просит сначала выполнить `--clean`. Scale login: `scale-admin` / `scale-only-pass`.
