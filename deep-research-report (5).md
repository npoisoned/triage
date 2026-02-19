# Инструкция по работе с секретами

## Executive summary  
Коммитить секреты (пароли, токены, ключи) в код нельзя — даже в **test** или **dev**. Секрет считается скомпрометированным, если хоть раз попал в удалённый Git (в ветке или PR). В этом случае нужно **немедленно** удалить секрет из кода и выполнить его **отзыв/ротацию** в системе-источнике. Лучшие практики AppSec требуют централизованного хранения (Vault, Secrets, CI variables) и минимальных прав【0†L7-L11】【3†L1-L6】.  

**Политика (2 строки):**  
`Запрещено` коммитить секреты любых сред (prod/stage/dev/mock) в репозиторий.  
При обнаружении — удалить из HEAD и немедленно ротировать/отзывать через Vault/CI/ключевое хранилище.

---

## Термины и среды  
**Секрет** — значение или файл, позволяющий получить доступ (аутентификация/авторизация) или осуществлять криптооперации. Например, учётные данные, API-ключи, токены, приватные ключи. ([OWASP](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)【0†L7-L11】)  

**Среды:** prod (реальные сервисы/данные), stage/test (интеграционные стенды), dev (разработка), local (машина разработчика), mock (заглушки). Среда лишь влияет на степень ущерба и скорость реакции; **правило неизменно**: валидные секреты не в Git, даже в dev. Mock-значения должны быть явно фиктивными.

---

## Классификация секретов

| Тип секрета                      | Категория              | Пример (вымышленный)                    |
|----------------------------------|------------------------|-----------------------------------------|
| **Private key** (PEM, SSH)       | Криптоключ             | `-----BEGIN PRIVATE KEY-----\n<редактировано>\n-----END PRIVATE KEY-----` |
| **PKCS#12** (`.p12/.pfx`)        | Криптоключ             | `keystore.example.p12`                  |
| **JWT (access token)**           | JWT-токен              | `eyJhbGciOiJub25lIn0.INVALID.INVALID`   |
| **K8s ServiceAccount token**     | Токен Kubernetes       | JWT с `iss: kubernetes/serviceaccount`  |
| **Vault token**                  | Токен HashiCorp Vault  | `VAULT_TOKEN=hvs.<редактировано>`       |
| **db_password / hive credentials** | Пароли БД             | `DB_PASSWORD=<редактировано>`           |
| **Password in URL**              | Пароль в URL           | `jdbc:postgresql://user:<redактировано>@db/app` |
| **JDBC connection**              | Конфиг/среда           | `JDBC_URL=jdbc:postgresql://db:5432/app` (без пароля) |
| **Generic API key**              | API-ключ               | `API_KEY=<редактировано>`              |
| **Consumer key (+ secret)**      | API-ключ + Secret      | `CONSUMER_KEY=<редактировано>`         |
| **AWS/GCP access keys**          | Инфраструктурный ключ  | `AWS_ACCESS_KEY_ID=AKIA<redактировано>` / `GCP_API_KEY=AIza<редактировано>`【18†L3-L10】 |
| **CI token**                     | Токен CI/CD            | `CI_TOKEN=<редактировано>`             |

**Замечание:** для каждого типа ниже описаны правила хранения, примеры (фейковые) и команды проверки/ротации.

---

## Классификация по среде использования

Среда влияет на приоритет и степень воздействия, **но не отменяет запрет коммитить секреты**.

- **Production (prod):** реальные сервисы и данные. Утечка критична, требует **немедленной ротации**. Critical.  
- **Stage/Test:** интеграционные стенды. Часто подключены к реальным БД/сервисам. Утечка серьёзна – ротация обязательно. High.  
- **Dev:** среда разработки. Ключи dev не хранятся в Git. Любая утечка предупреждается ротацией. Medium–High.  
- **Local:** локальная машина. Секреты хранят только локально: `.env` (включён в `.gitignore`), системное хранилище. Нельзя их коммитить. Medium.  
- **Mock:** заглушки и тестовые примеры. Допускаются **только явно невалидные** данные. Например, `API_KEY="example_do_not_use"`. Если формат валидный — секрет, а не mock. Low.

---

## Triage (TP/FP) и Severity

**TP (True Positive):** секрет валидного формата, реально может дать доступ.  
**FP (False Positive):** явно фиктивная строка (например, `"YOUR_API_KEY_HERE"`), невычисляемая в формате секрета, либо уже деактивированная строка, добавленная в allowlist после ротации.  

**Severity:**
- **Critical:** Production-секреты; приватные ключи; Vault token; AWS/GCP ключи; K8s SA токен с высокими правами【0†L7-L11】【18†L3-L10】.  
- **High:** Stage/Test токены; CI/CD токены; API keys; K8s SA токен из “боевого” кластера【2†L1-L4】.  
- **Medium:** dev-пароли/ключи при отсутствии угрозы для prod.  
- **Low:** mock-значения, истёкшие или неиспользуемые данные.

**Decision-tree:**

```mermaid
flowchart TD
A[Найдено значение/файл] --> B{Похоже на секрет по формату?}
B -- нет --> FP[FP: закрыть / уточнить правило]
B -- да --> C{Это рабочий доступ?}
C -- да --> TP[TP: определить среду и риск]
C -- нет --> D{Заглушка/mokc/example?}
D -- да --> FP
D -- нет --> TP-low[TP (Low): удалить из кода, ротировать по ситуации]
TP --> E{Среда}
E -- prod --> CR[Critical: удалить + немедленная ротация]
E -- stage/dev/local --> HR[High/Medium: удалить + ротация по риску]
```

---

## Матрица «Тип→Severity→Действие»

| Тип секрета          | Default severity | Действие (минимум)                          |
|----------------------|-----------------:|---------------------------------------------|
| Private key / PKCS#12 | Critical        | Удалить из Git + перевыпустить ключ/сертификат + обновить хранилище и деплой |
| Vault token          | Critical        | Удалить + `vault token revoke <TOKEN>` + выпустить новый + аудит ([Vault docs](https://developer.hashicorp.com/vault/docs/commands/token/revoke)) |
| K8s SA token         | High/Critical   | Удалить + инвалидация (см. ниже) + проверить RBAC ([k8s docs](https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin)) |
| db_password / hive   | High            | Удалить + сменить пароль БД + обновить конфиг/секрет |
| Password in URL      | High            | Удалить + убрать пароль из URL + сменить пароль |
| JDBC connection      | Medium/High     | Без пароля — ок; с паролем — как db_password |
| API key / consumer_key| High           | Удалить + перевыпустить ключ/секрет + ограничить scope/домен |
| AWS/GCP keys         | Critical        | Деактивировать + перевыпустить + аудит «last used» ([AWS Docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [GCP Docs](https://cloud.google.com/docs/authentication/api-keys-best-practices)) |
| CI token             | High            | Перевыпустить + обновить CI-variables и пайплайны |

---

## Правила хранения и ротации по типам

- **Private key (PEM/SSH)**: хранить только вне Git. Для тестов — runtime-генерация ключей. Проверка:
  ```bash
  openssl pkey -in key.pem -check -noout
  ```
  ([ман стр. openssl-pkey](https://www.mankier.com/1/openssl-pkey.1ossl)). Ротация: перевыпустить ключ/сертификат, обновить приложение.

- **PKCS#12 (.p12)**: хранить вне Git, отдавать на runtime из CI/Vault. Проверка:
  ```bash
  openssl pkcs12 -in keystore.p12 -info -nokeys
  ```
  ([ман стр. openssl-pkcs12](https://www.mankier.com/1/openssl-pkcs12.1ossl)). Ротация: перевыпустить контейнер, обновить хранилище.

- **JWT**: не хранить. Генерировать динамически (login flow). Если JWT утёк: перевыпустить signing key или инвалидировать сессии.

- **Vault token**: хранить только в Vault или CI. Отзыв:
  ```bash
  vault token revoke <TOKEN>
  ```
  ([Vault docs](https://developer.hashicorp.com/vault/docs/commands/token/revoke)). Проверка: `vault kv metadata get -mount=secret <path>` покажет дату/версию.

- **K8s SA token**: **короткоживущий** с TokenRequest. Проверка:
  ```bash
  kubectl -n <ns> get sa <sa>
  kubectl auth can-i create pods -n <ns> --as=system:serviceaccount:<ns>:<sa>
  kubectl -n <ns> create token <sa> --duration=10m
  ```
  ([k8s docs](https://kubernetes.io/docs/concepts/security/service-accounts)). Инвалидация: для legacy-secret — `kubectl -n <ns> delete secret <sa-token-secret>`. Для short-lived: удалить/пересоздать SA:
  ```bash
  kubectl -n <ns> delete sa <sa>
  kubectl -n <ns> create sa <sa>
  ```
  (после этого старые токены перестанут работать).

- **DB/Hive пароли**: хранить вне Git (CI/Secret Store). Ротация: сменить пароль пользователя в БД/Hive, обновить все конфиги.

- **Password in URL**: строго запрещено (логируется/кэшируется). Вынести пароль в переменную/секрет.

- **Generic API key / consumer_key**: хранить в секрет-хранилище. Ротация: перевыпустить, ограничить привязки (IP/реферер).

- **AWS/GCP ключи**: использовать временные креды через STS. При утечке — немедленно деактивировать ключ и создать новый (см. [AWS](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html), [GCP](https://cloud.google.com/docs/authentication/api-keys-best-practices)).

- **CI tokens**: хранить в CI как secret var. Ротация: перевыпустить, обновить пайплайны.

Везде **отзыв старого** — отключить старую credential/токен, чтобы он больше не валидировал.

---

## Что делать при обнаружении секрета в Git

1. **Удалить секрет из кода** (HEAD) незамедлительно.  
2. **Ротировать/отозвать** в системе-источнике (Vault, DB, IAM и т.д.).  
3. **Проверить историю**: найти повторения в репозитории и коммитах:
   ```bash
   git grep -n "PRIVATE KEY\|password=\|VAULT_TOKEN\|AKIA\|AIza\|hive2://"
   git log -S "<fragment>" --all --patch
   ```
4. **Решить вопрос с историей:** 
   - Если политика требует удаления из истории, используем `git-filter-repo` (force-push и оповестить команду)【3†L1-L6】.  
   - В противном случае достаточно ротации.

5. **Закрыть finding**: упомянуть в тикете удаление из HEAD и детали ротации (дата, кто, новый токен/ключ).

**Пример тикета:**
```
[SEC][Gitleaks] SHA256 hash потока Пароля в repo/config.yaml
ENV: stage (dev-окружение)
Commit: 89f8a7b (ветка feature/auth)
Описание: найден пароль БД
Действия:
- Удалён из HEAD (коммит 3af4b2c)
- Ротирован: пароль изменён на БД-сервере 20.02.2026
- Проверка: старый пароль не работает
- Сделан новый скан (gitleaks clean)
```

---

## Проверка секрета по коммиту (ASOC)

Если ASOC указывает коммит и путь, а в текущей ветке файла нет, нужно достать файл из нужного коммита.

1. **Получить файл из коммита:**
   ```bash
   git show <commit>:<path> 
   # Например:
   git show 9af0a707:webservice/src/main/java/com/example/Config.java
   ```
2. **Вывести нужные строки:**
   ```bash
   git show <commit>:<path> | sed -n '1,80p'
   git show <commit>:<path> | sed -n '6p'
   ```
3. **Если файл не найден в коммите:**
   ```bash
   git ls-tree -r <commit> --name-only | grep -i <часть_имени>
   ```
   — возможно, путь поменялся. Найдите точный путь и повторите `git show`.

4. **Бинарные файлы (ODT/PDF):**  
   ```bash
   git show <commit>:docs/openapi/file.odt > file.odt
   odt2txt file.odt | head -n 80
   ```
   Выгружаем файл и открываем локально.

Этот процесс гарантирует, что мы видим именно то значение, которое сканер нашёл, а не текущее состояние ветки.

---

## Локальная разработка и тесты

- Секреты в коде: **только mock-значения**. Настоящие ключи/токены не держат в коде.
- `.env` и конфиги с секретами — всегда вне git, через `.gitignore`.
- Генерировать секреты на лету в тестах: 
  ```java
  KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
  kpg.initialize(2048);
  KeyPair kp = kpg.generateKeyPair();
  ```
- Для бизнес-тестов можно мокать компоненты авторизации, не используя реальные секреты.

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

---

## Автоматизация и инструменты

- **Gitleaks** для pre-commit и CI. ([gitleaks](https://github.com/gitleaks/gitleaks) repo).  
- **Pre-commit**: добавим хук:
  ```yaml
  repos:
    - repo: https://github.com/gitleaks/gitleaks
      rev: v8.24.2
      hooks:
        - id: gitleaks
  ```
- **CI-скан**:  
  ```bash
  gitleaks git --redact --log-opts="--all"
  ```
- **Allowlist:** только для подтверждённых FP или уже ротированных значений【4†L13-L20】. Пример `.gitleaks.toml`:
  ```toml
  [allowlist]
  regexes = ['YOUR_API_KEY_HERE','(?i)example[_-]?token']
  paths = ['^docs/','^testdata/']
  ```
- **Triage-сообщения (ASOC):**  
  - TP/Critical:  
    > „Обнаружен секрет `<type>` в `<path>`. Удалить из HEAD + немедленно ротировать. Allowlist запрещён до подтверждения ротации.”【3†L1-L6】  
  - TP/High:  
    > „Удалить из кода, ротировать по регламенту, затем повторный скан.”【0†L7-L11】  
  - FP:  
    > „Mock/пример. Закрыть как FP, добавить в allowlist.”【4†L13-L20】

---

## Ссылки на источники

- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)【0†L7-L11】  
- Kubernetes: ServiceAccount и токены (официальная документация)【2†L1-L4】  
- HashiCorp Vault: `token revoke`, `kv metadata`【19†L1-L4】【25†L3-L10】  
- GitHub: Removing sensitive data from a repository【3†L1-L6】  
- Gitleaks: pre-commit hook, allowlist (docs/Community)【4†L13-L20】【7†L12-L18】  
- AWS/GCP best practices по ключам【18†L3-L10】【25†L3-L10】

Все рекомендации основаны на официальных гидах и опыте AppSec.