# Инструкция по работе с секретами для разработчиков

## Executive summary
Секреты (пароли, токены, ключи, криптоматериалы) **запрещено** хранить в git — ни в коде, ни в `test/`, ни в `docs/`, ни в “пример-конфигах”. Если секрет оказался в репозитории, он считается **потенциально скомпрометированным** и требует действий **в источнике секрета** (отзыв/ротация), а не только удаления из файла. Это базовая гигиена управления доступами и ключами: централизованное хранение, минимальные права, аудит и ротация. citeturn0search0turn0search3

**Политика (2 строки)**  
Запрещено коммитить секреты любого типа и для любой среды, включая test/mock.  
Найденный секрет удаляется из HEAD немедленно и подлежит отзыву/ротации по процедуре.

**Важное про “squash”**: squash-merge упрощает историю main, но **не отменяет** факт, что секрет мог быть запушен в удалённую ветку/PR и сохранён в клонах/бэкапах. Поэтому ориентируемся не на “как выглядит main”, а на факт публикации секрета в remote. citeturn0search3

## Область применения и определения
**Область:** все репозитории, ветки, PR/MR, CI-логи и артефакты, шаблоны конфигураций, примеры, `values.yaml`, `helm charts`, `k8s/*.yaml`.

**Секрет** — значение или файл, который предоставляет доступ (аутентификация/авторизация), позволяет подписывать/расшифровывать или управлять инфраструктурой. Рекомендация OWASP: централизовать хранение и управление секретами (provisioning, auditing, rotation) и избегать “размазывания” секретов по сервисам и репозиториям. citeturn0search0

**Классификация по среде (environment):**
- **prod**: продуктив (максимальный ущерб).
- **stage/test**: стенды (часто есть реальные интеграции/данные — риск высокий).
- **dev**: общая разработка/интеграция.
- **local**: только машина разработчика.
- **mock/example**: невалидная заглушка (не даёт доступа).

**Правило маскирования:** значения секретов **не публикуем** в Jira/ASOC/чатах. В тикете — путь/коммит/тип секрета и (опционально) “короткий отпечаток” (например первые/последние 4 символа или fingerprint), но не полный секрет.

## Полная классификация секретов
Все примеры ниже **вымышленные и/или намеренно невалидные** (их нельзя использовать как рабочие).

| Тип (из алертов) | Категория | Как выглядит | Безопасный пример (маска/невалидно) |
|---|---|---|---|
| private key | криптоматериал | PEM-блок | `-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----` |
| pkcs12-file (.p12/.pfx) | криптоматериал | контейнер с ключом | `keystore.example.p12` |
| JWT | токен | `base64.base64.base64` | `eyJhbGciOiJub25lIn0.INVALID.INVALID` |
| service account token | токен (K8s) | JWT с `iss: kubernetes/serviceaccount` | “JWT с issuer kubernetes/serviceaccount” citeturn1search6 |
| vault service token | токен | Vault token | `VAULT_TOKEN=hvs.<redacted>` citeturn0search2 |
| db_password | credential | пароль/логин | `DB_PASSWORD=<redacted>` |
| password in URL | credential | `user:pass@host` | `jdbc:postgresql://u:<redacted>@db/app` |
| JDBC connection | конфиг | URL без пароля допустим | `JDBC_URL=jdbc:postgresql://db:5432/app` |
| generic api key | API key | строковый ключ | `API_KEY=<redacted>` |
| consumer_key | API key/secret | key + часто secret | `CONSUMER_KEY=<redacted>` |
| aws/gcp keys | инфраструктурный ключ | cloud key formats | `AKIA<redacted>` / `AIza<redacted>` |
| hive credentials / hive2 | credential | user/pwd в thrift/jdbc | `hive2://h:10000;user=u;password=<redacted>` |
| CI tokens | токен | токен CI/CD | `CI_TOKEN=<redacted>` |

## Triage правила, severity и матрица действий
**TP (True Positive):** значение реально может дать доступ или является валидным криптоматериалом/токеном/паролем. Это TP даже если файл лежит в `test/`, потому что риск определяется валидностью и доступами, а не папкой. citeturn0search0  
**FP (False Positive):** заглушка/пример (`YOUR_API_KEY_HERE`), невалидный формат, или секрет уже деактивирован/ротирован и добавлен в allowlist строго после подтверждения (иначе сканер будет “шуметь” на историю). citeturn1search8

**Decision-tree (Mermaid, вставляйте как есть):**
```mermaid
flowchart TD
A[Найдена строка/файл] --> B{Похоже на секрет по формату?}
B -- нет --> FP[FP: закрыть / улучшить правило]
B -- да --> C{Может дать доступ / валиден?}
C -- да --> TP[TP: определить среду и права]
C -- нет --> D{Это mock/example заглушка?}
D -- да --> FP
D -- нет --> TPL[TP-Low: удалить из кода; ротация по оценке]
TP --> E{Среда}
E -- prod --> CR[Critical: удалить + немедл. отзыв/ротация]
E -- stage/dev/local --> HR[High/Medium: удалить + отзыв/ротация по риску]
```

**Severity модель (по умолчанию):**
- **Critical:** private key / pkcs12; Vault token; cloud keys; prod-секреты; K8s SA токен с правами выше “read-only”. citeturn0search0turn0search2turn1search6  
- **High:** stage/test credentials; CI tokens; API keys; K8s SA token из реального кластера. citeturn1search6turn0search1  
- **Medium:** dev/local реальные секреты (при отсутствии признаков prod-использования).  
- **Low:** исторические/истёкшие значения при подтверждении отсутствия использования (но удалить из кода всё равно). citeturn1search8

**Матрица «Тип → Severity → Действие» (минимальный стандарт):**

| Тип | Default severity | Что сделать (обязательно) |
|---|---:|---|
| private key / pkcs12 | Critical | удалить из HEAD + перевыпуск ключа/серта/keystore + обновить секреты/деплой |
| vault token | Critical | удалить + `vault token revoke` + выпуск нового + проверить зависимости citeturn0search2 |
| K8s service account token | High/Critical | удалить + инвалидация (см. команды ниже) + проверить RBAC citeturn0search1turn1search2 |
| db_password / hive creds | High | удалить + сменить пароль учётки + обновить секреты/деплой |
| password in URL | High | убрать credential из URL + сменить пароль (URL часто попадает в логи/прокси) |
| JDBC connection | Medium/High | без пароля — ок; c паролем — как db_password |
| generic api key / consumer_key | High | перевыпуск key/secret + ограничить права/скоуп + удалить из git |
| aws/gcp keys | Critical | немедленно деактивировать/удалить + ротация + аудит “last used” |
| CI tokens | High | перевыпуск/замена в CI + обновить пайплайны |

## Правила хранения, проверка и ротация по типам
Ниже — практический “playbook”. Принцип один: **удаление из кода ≠ отзыв**. Отзыв/ротация делаются в системе-источнике секрета.

**Private key (PEM)**
- Хранение: вне git. Для тестов — генерация на runtime или mock (невалидный формат).
- Проверка (не печатать ключ):  
  ```bash
  openssl pkey -in key.pem -check -noout
  ```
  Флаг `-check` проверяет согласованность ключевой пары, `-noout` не выводит ключ. citeturn8view0
- Ротация: перевыпуск ключа и всех артефактов, которые им подписываются (TLS/JWT/SSH), затем деплой.

**PKCS#12 (.p12/.pfx)**
- Хранение: вне git; выдавать приложению на runtime из секрет‑хранилища.
- Проверка структуры/метаданных без вывода приватного ключа:  
  ```bash
  openssl pkcs12 -in keystore.p12 -info -nokeys
  ```
  Опции `-info` и `-nokeys` описаны в man page. citeturn9view0
- Ротация: перевыпуск контейнера/серта; заменить в секрет‑хранилище; деплой.

**JWT**
- Хранение: JWT (access token) не должен лежать в репо ни как “пример”. Для тестов: mock-значения или генерация в тесте.
- Если утёк валидный JWT: зависит от системы — либо дождаться истечения + обеспечить короткий TTL, либо внедрить revocation/blacklist, либо сменить signing key (если утекла инфраструктура подписи).

**Vault token**
- Отзыв токена выполняется через `vault token revoke` (по умолчанию — каскадно для “детей”). citeturn0search2  
  ```bash
  vault token revoke <TOKEN>
  vault token revoke -self
  ```
- Проверка факта ротации KV (если KV v2): смотреть metadata/version. citeturn2search2  
  ```bash
  vault kv metadata get -mount=secret <path>
  ```

**Kubernetes ServiceAccount token**
- ServiceAccount — идентичность для процессов в Pod; токены и их администрирование описаны в официальных гайдах. citeturn1search6turn0search1  
- Проверка SA и прав (RBAC) через impersonation:
  ```bash
  kubectl -n <ns> get sa <sa>
  kubectl auth can-i list pods -n <ns> --as=system:serviceaccount:<ns>:<sa>
  kubectl auth can-i get configmaps -n <ns> --as=system:serviceaccount:<ns>:<sa>
  ```
  `kubectl auth can-i` специально предназначен для проверки разрешений и хорошо работает с `--as`. citeturn1search2
- Получить short-lived токен для диагностики (не сохранять, не коммитить):
  ```bash
  kubectl -n <ns> create token <sa> --duration=10m
  ```
  Команда и её параметры официально документированы. citeturn1search3
- Инвалидация/“ротация”:
  - Если в кластере есть legacy long-lived SA token Secret — удалить Secret.
  - Для bound / short-lived токенов: чтобы “сжечь” все старые токены, применяется подход “пересоздать объект, к которому токен привязан” (в т.ч. SA), либо использовать bound-object при выпуске токена. Это описано в админ-гайде по SA и в документации `kubectl create token` (токен может быть bound к объекту и истекает при удалении bound-object). citeturn0search1turn1search3  
  Практический шаблон:
  ```bash
  # legacy:
  kubectl -n <ns> delete secret <sa-token-secret>

  # bound/short-lived:
  kubectl -n <ns> delete sa <sa>
  kubectl -n <ns> create sa <sa>
  # затем восстановить rolebinding/clusterrolebinding
  ```

**db_password / hive credentials / password in URL / JDBC**
- Пароли не хранятся в git; password-in-URL запрещён (часто попадает в логи).
- Правильно: строка подключения без пароля + пароль через env/secret store.
  ```properties
  JDBC_URL=jdbc:postgresql://db.internal:5432/app
  DB_USER=app_user
  DB_PASSWORD=${DB_PASSWORD}
  ```
- Ротация: сменить пароль пользователя в источнике (DB/Hive), обновить секреты, деплой.

**generic api key / consumer_key**
- Хранение: вне git (CI variables / secret store).  
- Ротация: перевыпуск ключа/secret и ограничение прав/скоупа. (Если это GCP API key — ограничения и best practices есть в guidance по API keys.) citeturn0search0turn1search27

**CI tokens**
- Хранение: только в CI secret store/variables.
- Ротация: перевыпуск токена, обновить pipelines, проверить, что старый не работает.

## Что делать при обнаружении секрета в git
GitHub подчёркивает: **сначала** нужно отозвать/ротировать секрет, потому что переписывание истории — сложная координационная операция и не всегда обязательна после отзыва. citeturn0search3

**Пошаговый план (коротко, но по делу):**
1) Зафиксировать: тип секрета, путь, коммит, ветку/PR, среду (prod/stage/dev/local/unknown).  
2) Удалить секрет из HEAD: заменить на env/secret store, добавить `.gitignore` при необходимости.  
3) Инициировать отзыв/ротацию в источнике секрета (Vault/DB/K8s/CI/IAM).  
4) Подтвердить отзыв: дата, идентификатор (user/key id/sa name), и факт “старое значение невалидно”.  
5) Проверить историю: найти все появления, чтобы не пропустить повтор.
   ```bash
   git grep -n "PRIVATE KEY\|password=\|VAULT_TOKEN\|AKIA\|AIza\|hive2://"
   git log -S "<фрагмент>" --all --patch
   ```
   `git grep` — официальный инструмент поиска в репозитории. citeturn1search2turn0search3  
   (Pickaxe-поиск `-S` в практике Git описывается как поиск коммитов, где строка добавлялась/удалялась; в обучающих материалах Git это называется “pickaxe”. citeturn4search11turn4search27)
6) Решить вопрос с историей: если политика требует “полной очистки” — использовать `git-filter-repo`, но только согласованно со всеми клонами/форками (иначе секрет возвращается). citeturn0search3turn3search2  
   ```bash
   git-filter-repo --invert-paths --path path/to/secret.file
   git push --force --mirror origin
   ```

**Шаблон тикета (для Jira/ASOC)**
```text
[SEC][Secrets] Обнаружен <type> в <repo>/<path>
ENV: prod|stage|dev|local|unknown
Commit: <hash> | Branch/PR: <id>
Риск: какие доступы даёт (роль/RBAC/сервис)
Действия:
- Удалено из HEAD (PR/commit <hash>)
- Отзыв/ротация в <system> (дата, идентификатор)
- Проверка: старое значение не работает
- Повторный gitleaks scan: PASS
```

## Локальная разработка, тесты и автоматизация
**Локальная разработка**
- Разрешено хранить секреты только локально: `.env` / env vars / локальный credential store.
- `.env`, `*.pem`, `*.p12`, `secrets/` всегда в `.gitignore`.

Пример `.gitignore`:
```gitignore
.env
.env.*
*.pem
*.key
*.p12
*.pfx
secrets/
```

**Тесты**
- Для криптографии: runtime keygen (генерируем ключи в тесте), либо валидируем только public key, либо мокируем компонент (если тест про бизнес-логику).
- Нельзя: класть “настоящие по формату” private keys / Vault tokens / K8s SA tokens в `test/fixtures`.

**Gitleaks и предотвращение повторов**
- Gitleaks — инструмент для поиска секретов в git и файлах. citeturn1search5  
- Официальный pre-commit hook (id `gitleaks`) описан в `.pre-commit-hooks.yaml`. citeturn1search1  

`.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.24.2
    hooks:
      - id: gitleaks
```

CI scan (пример):
```bash
gitleaks git --redact --verbose --log-opts="--all"
```

Allowlist: применять только для FP или для уже ротированных/деактивированных значений, иначе вы “узакониваете” активную утечку; рекомендация держать allowlist в `.gitleaks.toml` в корне репозитория. citeturn1search8turn1search0  

`.gitleaks.toml` (шаблон):
```toml
[allowlist]
description = "FP / rotated (track ticket id)"
regexes = ['YOUR_API_KEY_HERE', '(?i)example[_-]?token']
paths = ['^docs/', '^testdata/']
```

**Шаблоны triage-комментариев (ASOC)**
- TP / Critical: “В репо обнаружен <type> (commit <hash>, path <path>). Удалить из HEAD и выполнить немедленный отзыв/ротацию в источнике секрета. Allowlist запрещён до подтверждения ротации.” citeturn0search3  
- TP / High: “Секрет валидного формата. Удалить из кода и ротировать/отозвать. После деплоя — повторный gitleaks scan.” citeturn0search0  
- FP: “Mock/example, не даёт доступа. Закрыто как FP, добавлено правило allowlist/уточнение конфигурации.” citeturn1search8