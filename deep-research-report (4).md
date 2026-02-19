# Инструкция по работе с секретами для разработчиков

## Executive summary
Любой секрет (ключ, токен, пароль и т.д.), оказавшийся в Git, считается потенциально скомпрометированным. Такой секрет нужно **удалить из кода и ротировать в системе-источнике** (Vault, база данных, IAM и т.д.), а не только закоммитить новое значение. Оптимальная практика — централизованное хранение секретов и выдача на runtime【0†L7-L11】【2†L1-L4】. 

**Политика (2 строки):**  
1. Никогда не коммитим секреты (любого типа и для любой среды) в репозиторий.  
2. Любой обнаруженный секрет удаляется из HEAD немедленно и подлежит отзыву/ротации в системе-источнике.

Если секрет хотя бы раз был запушен в удалённый репозиторий (в ветку или PR), он считается утёкшим **даже при squash-merge или удалении ветки**【3†L1-L6】.  

---

## Определения и среда

- **Секрет** — любое значение, дающее доступ (аутентификация/авторизация) или выполняющее криптографическую функцию (подпись, шифрование)【0†L7-L11】.  
- **Среды:**
  - **prod** (production) — реальные пользователи и данные. Утечка критична.  
  - **stage/test** — интеграционные/тестовые стенды с реальными сервисами. Утечка серьёзна.  
  - **dev** — среда разработки. Нет лёгких оправданий для секретов в коде.  
  - **local** — локальная машина разработчика. Секреты только локально (`.env`, env vars).  
  - **mock** — заглушки/примерные данные. Допускаются **только невалидные** значения (например `YOUR_API_KEY_HERE`).  

**Ключевое правило:** валидный секрет **никогда** не хранится в репозитории, даже в `test/` или `dev`.  

---

## Классификация секретов

| Тип секретов | Категория | Пример (вымышленный, безопасный) |
|---|---|---|
| **Private key** (PEM, SSH) <br> **PKCS#12** (.p12/.pfx) | Криптоключ | `-----BEGIN PRIVATE KEY-----\n<REDACTED>\n-----END PRIVATE KEY-----` |
| **JWT** (access token) | Токен аутентификации | `eyJhbGciOiJub25lIn0.INVALID.INVALID` |
| **ServiceAccount token (K8s)** | Токен (Kubernetes) | JWT с `iss: kubernetes/serviceaccount` |
| **Vault token** | Токен (Vault) | `VAULT_TOKEN=hvs.<redacted>` |
| **db_password** / **hive credentials** | Учетные данные | `DB_PASSWORD=<redacted>` |
| **Password in URL** | Учетные данные | `jdbc:postgresql://user:<redacted>@db:5432/app` |
| **JDBC connection string** | Конфигурация/среда | `JDBC_URL=jdbc:postgresql://db:5432/app` (без пароля) |
| **generic API key** | API key | `API_KEY=<redacted>` |
| **consumer_key** (+ secret) | API key/secret | `CONSUMER_KEY=<redacted>` |
| **AWS/GCP access keys** | Инфраструктурные ключи | `AWS_ACCESS_KEY_ID=AKIA<redacted>` / `GCP_API_KEY=AIza<redacted>` |
| **CI tokens** | Системные токены | `CI_TOKEN=<redacted>` |

Каждый тип секрета имеет свои правила хранения и обработки (см. разделы ниже). Например, **private key** и **Vault token** всегда Critical, **пароль DB** — минимум High. 

---

## Triage (TP/FP) и модель серьёзности

- **TP (True Positive):** секрет выглядит валидным и может дать доступ — это TP.  
- **FP (False Positive):** явно фиктивный/заглушечный формат (например `YOUR_API_KEY_HERE`) или уже ротированный/деактивированный секрет после валидации.  

**Severity:**
- **Critical:** реальные секреты в prod; частные ключи; Vault/JWT/TLS ключи; AWS/GCP ключи; SA токен с широкими правами【0†L7-L11】.  
- **High:** stage/test токены и ключи; CI токены; API keys; SA токен из “боевого” кластера【2†L1-L4】.  
- **Medium:** секреты в dev/local (если реальны).  
- **Low:** mock/expired/локальные тестовые значения.

**Решение:** важно как можно быстрее удалить секрет из кода и инициировать ротацию. До ротации **никакой allowlist** для него недопустим.

**Decision-tree (Mermaid):**

```mermaid
flowchart TD
A[Найдена строка/файл] --> B{Соответствует ли формату секрета?}
B -- нет --> FP[FP: закрыть/исключить правило]
B -- да --> C{Может ли дать доступ?}
C -- да --> TP[TP: определить среду]
C -- нет --> D{mock/example?}
D -- да --> FP
D -- нет --> TPL[TP (Low): удалить из кода]
TP --> E{Среда}
E -- prod --> CR[Critical: удалить + немед. ротация]
E -- stage/dev/local --> HR[High/Medium: удалить + ротация по риску]
```

---

## Матрица «Тип→Severity→Действие»

| Тип секрета | Default severity | Что делать (минимум) |
|---|---:|---|
| **Private key / PKCS#12** | Critical | удалить из репо + перевыпустить ключ/сертификат + обновить хранилище/конфиг |
| **Vault token** | Critical | удалить + `vault token revoke <TOKEN>` + выпустить новый + проверить зависимости ([developer.hashicorp.com](https://developer.hashicorp.com/vault/docs/commands/token/revoke)) |
| **Kubernetes SA token** | High/Critical | удалить + инвалидация (см. ниже) + проверить RBAC ([kubernetes.io](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin)) |
| **db_password / Hive creds** | High | удалить + сменить пароль в БД + обновить конфиг/секрет |
| **Password in URL** | High | удалить + убрать пароль из URL + сменить пароль |
| **JDBC Connection** | Medium/High | без пароля — ок; с паролем — как db_password |
| **generic API key / consumer_key** | High | удалить + перевыпустить ключ/secret + ограничить scope/domain |
| **AWS/GCP keys** | Critical | немедленно деактивировать/удалить + перевыпустить + аудит использования ([docs.aws.amazon.com](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [docs.cloud.google.com](https://docs.cloud.google.com/docs/authentication/api-keys-best-practices)) |
| **CI tokens** | High | перевыпустить + обновить CI-переменные/ващплайны |

---

## Хранение и ротация по типам

**Private key / PKCS#12:**  
- Хранить **только** в секр.-хранилище/Keystore, не в коде.  
- Проверка:  
  ```bash
  openssl pkey -in key.pem -check -noout
  ```  
  (опции `-check`/`-noout` в man-странице `openssl-pkey`【22†L8-L14】).  
- Ротация: перевыпустить ключ/сертификат, обновить конфиг сервера/приложения, отозвать старый.

**JWT:**  
- Не хранить в репозитории. Использовать динамически (логин, OIDC).  
- Если JWT утёк и валиден: ротация signing key или сессий (в зависимости от архитектуры).

**K8s ServiceAccount токен:**  
- Генерируется автоматически в Pod. Можно вручную получить (для отладки):  
  ```bash
  kubectl -n <ns> create token <sa> --duration=10m
  ```  
- Проверка прав SA:  
  ```bash
  kubectl auth can-i get pods -n <ns> --as=system:serviceaccount:<ns>:<sa>
  ```  
  (имперсонация `--as` описана в документации【2†L1-L4】).  
- Инвалидация: для legacy Secret — `kubectl -n <ns> delete secret <sa-token-secret>`.  
  Для bound токенов: пересоздать ServiceAccount (тк old token будет недействителен после удаления SA)【2†L1-L4】:
  ```bash
  kubectl -n <ns> delete sa <sa>
  kubectl -n <ns> create sa <sa>
  ```  
  затем восстановить RoleBinding.

**Vault Token:**  
- Отзыв:  
  ```bash
  vault token revoke <TOKEN>
  ```  
  (открутит токен и дочерние【19†L1-L4】).  
- Проверка ротации KV:  
  ```bash
  vault kv metadata get -mount=secret <path>
  ```  
  (возвращает версии и time-to-live【25†L3-L10】).

**DB password / Hive password:**  
- В репо не хранить. Пароль менять в СУБД или Hive и обновлять секрет.  
- Пример безопасного хранения: `DB_PASSWORD=${DB_PASSWORD}` из env.

**Password in URL:**  
- Строгий запрет: URL с логином/паролем в репо.  
- Вынести пароль в переменную/хранилище; rотация как db.

**JDBC connection string:**  
- Без пароля допустим. С паролем — как db_password.

**Generic API key / consumer_key:**  
- Хранить через env/CI-vars.  
- Ротация: выпустить новый ключ, ограничить референсами/совместимость (см. гайды API-провайдеров).

**AWS / GCP ключи:**  
- Использовать временные креды или KMS. Если access key скомпрометирован — деактивировать и создать новый【18†L3-L10】【25†L3-L10】.  
- Для GCP API Key — ограничить по рефереру/IP и rotation срокам (best practice).

**CI tokens:**  
- Только в CI/CD secret store.  
- Ротация: новый токен, обновление переменных, пересборка.

---

## Что делать при обнаружении секрета в Git

**Главное:** удаление из кода и коммита недостаточно. Сначала ротируем/отзываем секрет в источнике, потом занимаемся Git.

**Шаги:**

1. **Stop gap:** ограничить вред: приостановить сервис/пересоздать ключ, если возможно.  
2. **Удалить из HEAD:** коммитить код без секрета, добавить в `.gitignore`.  
3. **Ротация/отзыв:** выполнить в Vault/БД/K8s/CI.  
4. **Проверить историю:** найти все вхождения:
   ```bash
   git grep -n "PRIVATE KEY\|password=\|VAULT_TOKEN\|AKIA\|AIza\|hive2://"
   git log -S "<фрагмент>" --all --patch
   ```  
5. **История:** если политика требует, использовать `git-filter-repo` (координировать с коллегами):
   ```bash
   git-filter-repo --path path/to/secret.file --invert-paths
   git push --force
   ```
   (При этом все копии репо должны быть пересинхронизированы.)  
6. **Закрыть тикет:** приложить доказательства ротации (дата, идентификатор нового ключа/пароля).

**Пример тикета:**
```text
[SEC][Secret] Hardcoded API key in repo/example/config.json
ENV: stage, Owner: dev-team
Commit: abc1234 on branch feature/login
-- 
Действия:
- Удалено из HEAD (commit def5678)
- Ротирован в сервисе auth (новый ключ сгенерирован 2026-02-19, старый деактивирован)
- Проверено: старый ключ не валиден
- Последующий gitleaks scan прошёл успешно
```

---

## Локальная разработка и тесты

- Локально секреты могут храниться в `.env` или env vars, но **никогда не коммитятся**. Файлы `.env`, `*.pem`, `*.p12` всегда в `.gitignore`.  
- В тестах: допустима генерация секретов на лету или использование mock-данных. Никаких real-форматных ключей в `test/`. Например, вместо реального RSA-ключа генерируем новый в setup:
  ```java
  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
  kpg.initialize(2048);
  KeyPair kp = kpg.generateKeyPair();
  ```
- Проверять конфигурацию: не должно быть секретов в `src/test/resources` или аналогах.

Пример `.gitignore`:
```gitignore
.env
.env.*
*.pem
*.key
*.p12
secrets/
```

---

## Автоматизация (pre-commit, CI, gitleaks)

**Gitleaks** — стандартный инструмент для обнаружения секретов в Git. ([github.com](https://github.com/gitleaks/gitleaks)).  

**Pre-commit hook:**
```yaml
repos:
- repo: https://github.com/gitleaks/gitleaks
  rev: v8.24.2
  hooks:
  - id: gitleaks
```
(P.S. С версиями и ID см. `gitleaks/.pre-commit-hooks.yaml` в репо.)【7†L12-L18】  

**CI скан:** запускать `gitleaks scan --redact` по PR/merge.  
Пример команды:
```bash
gitleaks git --redact --log-opts="--all"
```

**Allowlist:** Только для подтверждённых FP или уже ротированных секретов. Никогда не включаем активный секрет! (Смотри гайд по allowlist.)【4†L13-L20】  

`.gitleaks.toml` (пример):
```toml
[allowlist]
regexes = ['YOUR_API_KEY_HERE','(?i)example[_-]?token']
paths = ['^docs/','^testdata/']
```

**Triage-сообщения (ASOC):**
- **TP / Critical:** “Обнаружен секрет `<type>` в `<path>` (commit `<hash>`). Удалить из HEAD и выполнить немедленный отзыв/ротацию в источнике. До ротации allowlist запрещён.”  
- **TP / High:** “Секрет валидного формата в dev/stage. Удалить из кода, инициировать ротацию, затем повторный gitleaks-scan.”  
- **FP:** “Значение mock/пример. Закрыть как FP, добавить правило/allowlist.”

---

# Ссылки и источники

- Гайд OWASP по управлению секретами【0†L7-L11】.  
- Официальная документация Kubernetes (ServiceAccount)【2†L1-L4】.  
- HashiCorp Vault (token revoke)【19†L1-L4】, (KV metadata)【25†L3-L10】.  
- GitHub — удаление чувствительных данных из репозитория【3†L1-L6】.  
- Gitleaks доки: конфигурация и pre-commit【4†L13-L20】【7†L12-L18】.  
- AWS/GCP best practices по ключам【18†L3-L10】【25†L3-L10】.  

Все рекомендации основаны на официальных гидах и опыте AppSec.