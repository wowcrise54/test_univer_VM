# План развития MP VM Client до MVP

## Цель MVP

MVP должен позволять оператору безопасно выполнить полный цикл:

1. войти в систему с корректно применёнными правами;
2. найти объект расследования;
3. запустить или повторить сканирование;
4. получить карточку актива и результаты обработки;
5. увидеть требующие действий ошибки, уязвимости и remediation-кейсы;
6. восстановить работу после сбоя приложения, PostgreSQL или MP VM без скрытых дублей и потери состояния;
7. развернуть и обновить систему по проверяемой процедуре.

Уже реализованные сканирование, precheck, группы активов, карточки, remediation, операции, автоматизации и базовые уведомления не нужно переписывать. План укрепляет эти контуры и закрывает два главных операторских пробела.

## Принципы приоритизации

- **P0 — блокирует выпуск MVP:** безопасность, восстановление, миграции и работоспособный quality gate.
- **P1 — обязательный операторский контур:** единая очередь действий и быстрый поиск.
- **P2 — эксплуатационная зрелость:** наблюдаемость, аудит и проверка полного live-stack.
- **После MVP:** функции с высокой стоимостью или не обязательные для первого рабочего выпуска.

Оценки: **S** — несколько дней, **M** — примерно одна итерация, **L** — несколько итераций или отдельный проектный этап. Это относительные оценки; перед реализацией каждый пункт требует отдельной декомпозиции.

## Этап 0. Зафиксировать исходную точку

### 0.1. Восстановить frontend quality gate — P0, S

**Проблема.** Vitest блокируется цепочкой `jsdom` → `html-encoding-sniffer` → `@exodus/bytes` с `ERR_REQUIRE_ESM`; переход на Node 26 сам по себе проблему не устраняет.

**MVP-объём.** Подобрать совместимые версии или официальный dependency override, обновить lockfile, не меняя test environment и не отключая тесты.

**Критерии приёмки.** На чистом Node 26 проходят `npm ci`, `npm test`, `npm run test:coverage` и `npm run build`; существующие DOM-контракты сохранены.

**Зависимости и риск.** Нужен доступ к npm registry. Изменение `jsdom` может повлиять на браузерную семантику, поэтому требуется полный frontend regression run.

### 0.2. Ввести единый release quality gate — P0, M

**Проблема.** Локальные и CI-проверки не образуют один воспроизводимый контракт; CI использует PostgreSQL 18, а Compose — PostgreSQL 16.

**MVP-объём.** Одна локальная/CI-команда для backend и frontend; обязательная PostgreSQL 16 lane; сборка контейнера и readiness smoke; сохранение текущего coverage ratchet; отдельные проверки критичных auth/scan/remediation-модулей.

**Критерии приёмки.** Обязательные PR checks воспроизводятся локально; контейнер собирается и становится ready; общий coverage не падает; результаты публикуются как CI artifacts.

## Этап 1. Безопасный запуск и доступ

### 1.1. Fail-closed RBAC и реальные тесты сессий — P0, S/M

**Проблема.** Неизвестный `GET` сейчас может автоматически получить `system.read`, а значительная часть auth-тестов подменяет получение пользователя.

**MVP-объём.** Запрещать любой unmapped route; зафиксировать permission matrix для каждого API route; добавить PostgreSQL-backed тесты входа, выхода, смены роли, блокировки пользователя и отзыва сессии.

**Критерии приёмки.** Новый unmapped `GET` и любой unmapped write возвращают `403`; viewer/operator/admin проходят явную матрицу критичных маршрутов; смена пароля, роли или `is_active=false` отзывает действующие сессии.

**Риск.** После включения fail-closed обнаружатся забытые маршруты; перед переключением нужен полный inventory.

### 1.2. Production-профиль конфигурации — P0, S/M

**Проблема.** Текущий Compose удобен для разработки, но допускает default credentials, небезопасную cookie, публикацию PostgreSQL и нестрогие TLS-настройки.

**MVP-объём.** Отдельный production overlay/profile: обязательные secrets, secure cookie, закрытый или loopback-bound PostgreSQL, запрет TLS bypass, HTTPS registry или корпоративный CA.

**Критерии приёмки.** Production startup завершается ошибкой при default/пустых credentials, insecure cookie или TLS bypass; секреты отсутствуют в image, выводе Compose и логах; dev-профиль остаётся отдельным и удобным.

### 1.3. Разделить liveness и readiness — P0, S

**Проблема.** Текущий `/api/health` всегда возвращает HTTP 200 и может раскрывать внутренние сведения; application healthcheck в Compose отсутствует.

**MVP-объём.** Минимальный `/api/live`; sanitised `/api/ready`, проверяющий PostgreSQL, Alembic revision и завершённое восстановление startup-состояния; Docker healthcheck приложения.

**Критерии приёмки.** Liveness не раскрывает DSN, host или MP VM URL; readiness возвращает `503` при недоступной БД или неприменённой миграции и `200` после готовности; недоступная внешняя MP VM означает degraded, но не restart loop.

## Этап 2. Данные и восстановление

### 2.1. Восстановление после возврата PostgreSQL без рестарта — P0, M

**Проблема.** Если БД недоступна на старте, приложение пропускает миграции, RBAC/bootstrap, reconciliation, scheduler и resume; поздняя проверка `SELECT 1` не выполняет эти шаги заново.

**MVP-объём.** Идемпотентный `recover_after_database_available()` под lock, запускаемый на переходе `DB down → ok`: миграции, bootstrap, reconciliation операций, remediation, scheduler, resume и backfill.

**Критерии приёмки.** При старте без БД live=`200`, ready=`503`; после появления БД recovery выполняется ровно один раз без рестарта и дублей jobs; ready становится `200` только после завершения recovery.

### 2.2. Проверяемые миграции, backup и restore — P0, M

**Проблема.** Миграции автоматически применяются на старте, но нет полного upgrade-теста на предыдущей схеме и воспроизводимого backup/restore rehearsal.

**MVP-объём.** Integration gate для пустой и предыдущей поддерживаемой схемы; runbook и скрипты `pg_dump`/`pg_restore`; schema-aware readiness; контрольные записи users/cards/operations/remediation.

**Критерии приёмки.** `upgrade head` проходит на пустой и восстановленной предыдущей схеме; контрольные данные остаются читаемыми; при migration failure workers не запускаются; backup имеет checksum, retention и подтверждённый restore в чистый PostgreSQL 16.

### 2.3. Безопасные retry изменяющих MP VM-запросов — P0, M

**Проблема.** Общий transport может автоматически повторять `POST`, `PUT` и `DELETE` после неопределённой сетевой ошибки, создавая риск двойного запуска или повторного side effect.

**MVP-объём.** Автоматические transport retries только для безопасных чтений. Для mutations — сохранённый request context, reconciliation по фактическому состоянию MP VM и статус `attention_required`, если исход невозможно определить.

**Критерии приёмки.** `GET` повторяется на `429/503`; mutation после read-timeout не повторяется вслепую; потерянный ответ после успешного `POST` не создаёт второй run; подтверждённый `DELETE 404` считается завершённым; неопределённый исход виден оператору.

### 2.4. Долговечные leases критичных jobs — P0/P1, L

**Проблема.** Часть jobs после рестарта становится `interrupted`, а scan postprocess leases не имеют heartbeat и срока действия.

**MVP-объём.** Ограничить первый этап operator-critical jobs: asset-card build, passport details и scan postprocess. Добавить `lease_owner`, `lease_expires_at`, heartbeat, attempt/backoff, failure class, атомарный claim, sweeper и идемпотентные checkpoints.

**Критерии приёмки.** Убитый worker переclaim-ится после TTL; две копии worker не получают одну job; сохранённые items не обрабатываются повторно; terminal failure не зацикливается; отменённая job после restart остаётся отменённой.

**Риск.** Самый крупный пункт MVP. Если срок ограничен, выполнить сначала leases для scan postprocess и asset-card build, а passport details перенести в следующий релиз.

## Этап 3. Главные операторские улучшения

### 3.1. Единая очередь «Требует действия» — P1, M

**Проблема.** Срочные remediation-кейсы, failed/retryable операции, stale coverage и пропущенные scheduled runs находятся в разных разделах.

**MVP-объём.** Расширить attention-очередь типами `case`, `operation`, `coverage`, `automation`. Для элемента показывать причину, приоритет, владельца/срок, разрешённое действие и deep-link.

**Критерии приёмки.** Каждый элемент имеет стабильный тип, приоритет и ссылку; закрытие, retry или refresh обновляет очередь; одна причина не дублируется; RBAC скрывает недоступные сущности и действия.

**Ценность.** Оператор начинает смену с одного приоритизированного списка.

### 3.2. Глобальный поиск расследования — P1, M

**Проблема.** IP/FQDN, `asset_id`, CVE, task/run, remediation case и operation приходится искать в разных экранах.

**MVP-объём.** Поиск в topbar; read-only агрегирующий API; категории результатов; RBAC-фильтрация; deep-link в карточку, кейс, задачу или операцию. На первом релизе искать только точные идентификаторы и prefix-текст, без сложного полнотекстового движка.

**Критерии приёмки.** Поиск поддерживает шесть основных типов; возвращает только разрешённые записи; результат открывает нужный объект; пустое состояние и ошибка доступны и понятны; запрос имеет лимит и измеряемый latency budget.

**Риски.** Метаданные нельзя возвращать до RBAC-фильтрации; leading-wildcard поиск не должен стать нагрузочным обходом БД.

## Этап 4. Наблюдаемость и live-stack проверка

### 4.1. Телеметрия очередей и зависших операций — P2, S/M

**MVP-объём.** Защищённый diagnostics/status snapshot: active/queued по очередям, возраст старейшей операции, interrupted/stuck, MP VM retries/errors/429, DB circuit/pool state. Без DSN, токенов, PDQL и высококардинальных labels.

**Критерии приёмки.** Искусственно зависшая операция видна по queue, age и operation ID; заданы degraded-пороги; payload проходит redaction-тест.

### 4.2. Полный security audit критичных действий — P2, M

**MVP-объём.** Расширить каталог audit events на scan/cancel/retry, remediation, exports, users/roles и automation execution; сделать audit write failure видимым и повторяемым через небольшой persistent outbox; настроить retention.

**Критерии приёмки.** Allow/deny события имеют actor и trace ID; временный сбой записи не теряет событие; audit details не содержат секретов.

### 4.3. Authenticated live-stack E2E — P2, M

**MVP-объём.** Отдельный небольшой Playwright project с настоящими FastAPI и PostgreSQL и детерминированным MP VM stub.

**Критерии приёмки.** Проверены login/logout, viewer=`403` на write, один operator preflight/run workflow и запись audit event. Ограничить suite тремя-четырьмя критичными сценариями, чтобы сохранить стабильность CI.

## После MVP

Следующие улучшения полезны, но не должны задерживать первый рабочий выпуск:

- исторический drill-down риска со снимками findings — **L**;
- maintenance windows и resource locks между runbooks — **M**;
- подписки и маршрутизация actionable-уведомлений — **M**;
- SLA по критичности или группе активов — **L**;
- очищенный пакет передачи расследования — **M**;
- PostgreSQL connection pool после измерения реальной нагрузки — **M**;
- Pydantic response models/OpenAPI snapshot для всех критичных API — **M**;
- keyset pagination и `pg_trgm` только после benchmark на 50k cards/500k findings — **M/L**;
- step-up re-authentication для особо чувствительных действий — **M**.

## Рекомендуемая последовательность итераций

| Итерация | Результат | Пункты |
| --- | --- | --- |
| 1 | Воспроизводимый baseline и безопасный доступ | 0.1, 0.2, 1.1 |
| 2 | Production-ready запуск и health contract | 1.2, 1.3, 2.1 |
| 3 | Безопасность данных и MP VM side effects | 2.2, 2.3 |
| 4 | Восстанавливаемые критичные jobs | 2.4, ограниченный scope |
| 5 | Единое рабочее место оператора | 3.1, 3.2 |
| 6 | Наблюдаемость и выпускной live-stack gate | 4.1, 4.2, 4.3 |

## Definition of Done для MVP

MVP готов к выпуску, когда одновременно выполнено следующее:

- fail-closed RBAC подтверждён реальными session/RBAC integration tests;
- production profile не стартует с небезопасными defaults;
- live/readiness корректно отражают БД, миграции и recovery;
- приложение восстанавливается после позднего появления PostgreSQL без рестарта и дублей;
- mutations MP VM не повторяются вслепую после неопределённого результата;
- критичные jobs переживают остановку worker либо получают явный безопасный статус;
- backup/restore и upgrade предыдущей схемы воспроизводимо проверены;
- frontend и backend quality gates проходят на заявленных Node 26 и PostgreSQL 16;
- оператор видит единую очередь действий и может найти ключевую сущность глобальным поиском;
- live-stack E2E подтверждает login, RBAC и один критичный workflow;
- документация запуска, восстановления и операторских сценариев обновлена вместе с реализацией.

## Подтверждённые основания плана

- startup и восстановление БД: `app/main.py`, `app/db.py`;
- retry transport и MP VM mutations: `app/mpvm/transport.py`, `app/mpvm_client.py`;
- jobs, leases и operations: `app/main.py`, `app/db.py`, `app/core/runtime.py`;
- RBAC, sessions и audit: `app/auth.py`, `tests/test_auth.py`, RBAC migrations;
- health и deployment: `app/main.py`, `app/core/config.py`, `docker-compose.yml`, `Dockerfile`;
- frontend test blocker и команды: `package.json`, `package-lock.json`, `docs/development.md`;
- operator gaps: `src/pages/VmManagementPage.jsx`, `src/pages/AutomationsPage.jsx`, `docs/operator-guide.md`, `README.md`.

Graphify использовался как первичный индекс связей; отрицательные утверждения и точные ограничения дополнительно проверены по текущим исходникам и конфигурации.
