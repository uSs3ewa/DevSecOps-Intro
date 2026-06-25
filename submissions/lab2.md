# Lab 2 — Submission

## Task 1: Baseline Threat Model

### Risk count by severity
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 4 |
| Medium | 14 |
| Low | 5 |
| **Total** | 23 |

### Top 5 risks (from `labs/lab2/output/risks.json`)
1. **unencrypted-communication** — Unencrypted Communication named **Direct to App (no proxy)** between **User Browser** and **Juice Shop Application** transferring authentication data; severity **Elevated**; affecting **User Browser**
2. **unencrypted-communication** — Unencrypted Communication named **To App** between **Reverse Proxy** and **Juice Shop Application**; severity **Elevated**; affecting **Reverse Proxy**
3. **missing-authentication** — Missing Authentication covering communication link **To App** from **Reverse Proxy** to **Juice Shop Application**; severity **Elevated**; affecting **Juice Shop Application**
4. **cross-site-scripting** — Cross-Site Scripting (XSS) risk at **Juice Shop Application**; severity **Elevated**; affecting **Juice Shop Application**
5. **unnecessary-data-transfer** — Unnecessary Data Transfer of **Tokens & Sessions** data at **User Browser** from/to **Juice Shop Application**; severity **Low**; affecting **User Browser**

### STRIDE mapping
- Risk 1: **I (Information Disclosure)** — credentials/session identifiers can be intercepted on plaintext HTTP traffic.
- Risk 2: **I (Information Disclosure)** — internal hop is plaintext, so traffic can be sniffed/altered on the host/container network path.
- Risk 3: **S (Spoofing)** — without authentication on the proxy→app link, an attacker could impersonate a trusted caller to the app.
- Risk 4: **T (Tampering)** — injected scripts can modify client-side state/requests, tamper with user actions, and pivot to session theft.
- Risk 5: **I (Information Disclosure)** — transferring Tokens/Sessions more broadly than needed increases exposure surface if the browser context is compromised.

### Trust boundary observation
Arrow crossing a trust boundary from `data-flow-diagram.png` that appears in the top-5 risks:
- **Arrow**: **User Browser → Juice Shop Application** (labelled `http`, direct access)
- **Why attractive to an attacker**: This link crosses **Internet → Container Network** and is plaintext HTTP, so it’s a high-value interception point for auth material (session-id/JWT/credentials). Attackers commonly sit “on path” via compromised Wi‑Fi/router, local malware, or misconfigured networking, and can sniff or tamper with requests at scale.

---

## Task 2: Secure Variant & Diff

### Risk count comparison
| Severity | Baseline | Secure | Δ |
|----------|---------:|-------:|--:|
| Critical | 0 | 0 | 0 |
| High | 0 | 0 | 0 |
| Elevated | 4 | 3 | -1 |
| Medium | 14 | 13 | -1 |
| Low | 5 | 5 | 0 |
| **Total** | 23 | 21 | -2 |

### Which rules are GONE in the secure variant?
1. **unencrypted-asset@persistent-storage** — fixed by enabling at-rest encryption on `Persistent Storage` (`encryption: data-with-symmetric-shared-key`).
2. **unencrypted-communication@user-browser>direct-to-app-no-proxy@user-browser@juice-shop** — fixed by switching direct user traffic from HTTP to HTTPS (`protocol: https`) in `User Browser → Direct to App (no proxy)`.
3. **unnecessary-data-transfer@tokens-sessions@user-browser@reverse-proxy** — indirectly reduced by enforcing HTTPS on the primary user path and documenting hardened handling of session tokens; this shrinks the practical attack surface for that data transfer.

### Which rules are STILL THERE in the secure variant?
1. **unencrypted-asset@juice-shop** — the Juice Shop application itself is still modeled without full encryption (`encryption: none`), потому что мы не меняли внутреннюю реализацию контейнера; модель по‑прежнему считает процесс уязвимым для компрометации при захвате хоста или контейнера.
2. **cross-site-scripting@juice-shop** — XSS остаётся, так как смена протокола и шифрование хранения не убирают логические баги и небезопасный рендеринг данных в шаблонах; чтобы устранить этот риск, нужно менять сам код приложения (экранирование, CSP, валидация ввода), а не только инфраструктуру.

### Honesty check
Общее количество рисков упало с 23 до 21 (меньше чем на 50 %), то есть базовая архитектура всё ещё остаётся заметно уязвимой. Небольшое снижение показывает, что включение HTTPS и шифрования хранилища — дешёвые и полезные меры, но они в основном уменьшают impacto перехвата трафика или кражи диска. Большая часть рисков (XSS, CSRF, отсутствие WAF, отсутствие vault/identity-store, hardening) связана с приложением и процессами, а не только с транспортом и диском, поэтому их устранение потребует значительно большего объёма работы. В реальном проекте такой результат помог бы обосновать, что «быстрые инфраструктурные фиксы» полезны, но приоритезация всё равно должна смещаться в сторону доработки кода и операционных процессов.

---

## Bonus Task: Auth Flow Threat Model

### Risk count
| Severity | Count |
|----------|------:|
| Critical | 0 |
| High | 0 |
| Elevated | 10 |
| Medium | 20 |
| Low | 3 |
| **Total** | 33 |

### Three auth-specific risks (NOT in the baseline model's top 5)
For each: rule ID + STRIDE + mitigation.

1. **sql-nosql-injection@auth-api@credential-store@auth-api>to-credential-store** — STRIDE: **T (Tampering)** — Mitigation: Validate and sanitize all inputs used in queries, use parameterized statements consistently in the auth layer, and enforce least-privilege DB accounts for the credential store.
2. **missing-authentication@browser>to-api-with-jwt@browser@auth-api** — STRIDE: **S (Spoofing)** — Mitigation: Require strong authentication on all JWT-bearing calls (e.g., enforce Authorization header format, reject anonymous requests to protected routes, and tie tokens to sessions/devices where appropriate).
3. **missing-authentication@auth-api>to-admin-endpoint@auth-api@admin-endpoint** — STRIDE: **E (Elevation of Privilege)** — Mitigation: Ensure that every call from the auth API to admin endpoints includes explicit role/permission checks, and that backend routes never trust client-supplied roles without server-side verification.

### Reflection
Auth-модель подсветила риски, которые в общей архитектурной модели были «размазаны» по большому количеству компонентов, но не фокусировались именно на цепочке login→JWT→admin. Отдельно стали видны инъекции и отсутствие аутентификации/авторизации на конкретных линках между `Auth API`, `Credential Store` и `Admin Endpoint`, то есть на самом критичном пути повышения привилегий. Такая узкофокусная модель помогает целенаправленно планировать доработки именно в auth‑коде и связанных хранилищах, а не распыляться по всей архитектуре.

