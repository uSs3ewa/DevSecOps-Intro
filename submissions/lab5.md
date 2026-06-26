# Lab 5 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan
- Duration: ~1 minute
- Total alerts: 10

| Severity | Count |
|----------|------:|
| High | 0 |
| Medium | 2 |
| Low | 5 |
| Informational | 3 |

### Authenticated full scan
- Duration: ~2 minutes (active scan) + spider time
- Total alerts: 11

| Severity | Count |
|----------|------:|
| High | 1 |
| Medium | 4 |
| Low | 3 |
| Informational | 3 |

### The "10–20× more" claim (Lecture 5 slide 11)
- Ratio (auth alerts / baseline alerts): 1.1× (11 vs 10)
- The ratio is much lower than the 10–20× claimed in the lecture. This is because Juice Shop is intentionally vulnerable across many surfaces — even unauthenticated access exposes a large attack surface (public REST APIs, static assets with security misconfigurations). The 10–20× ratio typically applies to applications where authentication gates most meaningful functionality. Here, the key difference is not the *quantity* of alerts but their *severity*: the authenticated scan found a **High-severity SQL Injection** that the baseline completely missed, along with Medium-severity issues like Missing Anti-clickjacking Headers and Session ID in URL Rewrite that require authenticated session state to detect.

### Two alerts only the authenticated scan found

1. **SQL Injection** [High]
   - ZAP detected SQL injection on `/rest/products/search?q='(` and `/rest/user/login` (POST, param: `email`). Both returned HTTP 500, indicating the injected payload broke the query. The unauthenticated baseline spider does not submit POST requests to the login endpoint with arbitrary email values, and the search endpoint's injection requires crafting specific payloads that the passive baseline spider doesn't attempt.

2. **Missing Anti-clickjacking Header** [Medium]
   - Found on Socket.IO endpoints (`/socket.io/?EIO=4&transport=polling&...`) that are only reachable after an authenticated session establishes a WebSocket connection. The unauthenticated spider never triggers these polling endpoints because they require an active session SID.

---

## Task 2: SAST with Semgrep

### Semgrep severity breakdown
| Severity | Count |
|----------|------:|
| ERROR | 12 |
| WARNING | 10 |
| INFO | 0 |
| **Total** | **22** |

### Top 10 rules by frequency
| Rule ID | Count | OWASP category |
|---------|------:|----------------|
| `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` | 6 | A01 - Injection |
| `yaml.github-actions.security.run-shell-injection.run-shell-injection` | 5 | A03 - Injection |
| `javascript.express.security.audit.express-check-directory-listing.express-check-directory-listing` | 4 | A06 - Security Misconfiguration |
| `javascript.express.security.audit.express-res-sendfile.express-res-sendfile` | 4 | A04 - Insecure Design |
| `javascript.express.security.audit.express-open-redirect.express-open-redirect` | 1 | A01 - Broken Access Control |
| `javascript.jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret` | 1 | A07 - Identification and Authentication Failures |
| `javascript.lang.security.audit.code-string-concat.code-string-concat` | 1 | A03 - Injection |

### Triage shortcut (Lecture 5 slide 8)
The rule I would fix first is `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection` (6 findings). It has the highest frequency among the application-code rules (excluding CI workflow findings which are lower priority). All 6 findings stem from the same pattern: raw string interpolation into `models.sequelize.query()`. A single module-level fix — switching to Sequelize parameterized queries with bind parameters — would close all 6 findings at once. The affected files (`routes/search.ts`, `routes/login.ts`, and the codefix challenge files) all use the same vulnerable pattern, so a centralized query helper or consistent refactor eliminates the entire class.

### False-positive sample
- **File**: `labs/lab5/semgrep/juice-shop/data/static/codefixes/dbSchemaChallenge_1.ts:5`
- **Rule**: `javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`
- **Reason**: This file is a deliberately vulnerable code snippet used as part of Juice Shop's coding challenges (the "Database Schema" challenge) — it is static reference material shown to users as a "find the bug" exercise, not executable production code served by the application. Suppressing it avoids noise from intentional training artifacts.

---

## Bonus: SAST/DAST Correlation

### Correlation table
| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection (High) | `/rest/products/search?q='(` | `sequelize-injection-express` | `routes/search.ts:23` | High (both agree) |
| 2 | A03 Injection | SQL Injection (High) | `/rest/user/login` (POST, param: email) | `sequelize-injection-express` | `routes/login.ts:34` | High (both agree) |

### Strongest correlation deep-dive

**Vulnerable code** from Semgrep (`routes/search.ts:23`):
```typescript
models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)
```

**Working payload** from ZAP (`auth-report.json`):
```
GET /rest/products/search?q='(
→ HTTP/1.1 500 Internal Server Error
```

The payload `'(` breaks the SQL syntax by injecting a single quote and open parenthesis, causing a database error that confirms injectability.

**Proposed fix** — use Sequelize parameterized queries:
```typescript
models.sequelize.query(
  `SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`,
  { replacements: { criteria: `%${criteria}%` } }
)
```

**Why both tools caught it**: Semgrep performs static analysis and detects that user-controlled input (`req.query.q`) flows directly into a SQL string via template literal interpolation — a textbook taint pattern. ZAP performs dynamic analysis by sending crafted payloads (`'(`) to the live endpoint and observing the 500 error response, which indicates the injected input reached the database engine unescaped. Static analysis sees the code pattern; dynamic analysis sees the runtime consequence. Their agreement on this finding makes it the highest-confidence vulnerability in the report.

### Reflection (2-3 sentences)
In a real PR review, I would want the **SAST finding first**. Semgrep identifies the exact file, line, and code pattern before the code is ever deployed — it's cheaper to fix and prevents the vulnerability from reaching production. The DAST evidence from ZAP then serves as powerful confirmation that the finding is exploitable in the running application, not just a theoretical pattern. Together, they form a complete story: "here's the bad code" (SAST) and "here's proof it's exploitable" (DAST).
