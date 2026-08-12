# Lab 5.2 — Submission

## Task 1: DAST with OWASP ZAP

### Baseline (unauthenticated) scan

- Duration: <2 minutes>
- Total alerts: <10>
| Severity | Count |
|----------|------:|
| High | <0> |
| Medium | <2> |
| Low | <5> |
| Informational | <3> |

### Authenticated full scan

- Duration: <5 minutes>
- Total alerts: <13>
| Severity | Count |
|----------|------:|
| High | <2> |
| Medium | <4> |
| Low | <3> |
| Informational | <4> |

### The "10–20× more" claim : authenticated DAST finds 10–20× more issues than unauth

- Ratio (auth alerts / baseline alerts): 10/13
- Pick **two specific alerts** that only the authenticated scan found. For each:

1. Alert title + severity

    - SQL Injection — High Severity
    - Vulnerable JS Library — High

2. Why was it unreachable to the unauthenticated scan? (1 sentence)
    - **SQL Injection**: The injection vulnerabilities exist in authenticated endpoints that require login credentials, which the unauthenticated scan cannot access.
    - **Vulnerable JS Library**: The vulnerable JavaScript library is loaded only on authenticated pages, making it invisible to the unauthenticated scan that lacks access privileges.

## Bonus: SAST/DAST Correlation

### Correlation table

| # | OWASP cat | ZAP alert | ZAP URI | Semgrep rule | Semgrep file:line | Confidence |
|---|-----------|-----------|---------|--------------|-------------------|------------|
| 1 | A03 Injection | SQL Injection | /rest/products/search?q=... | tainted-sql | routes/search.ts:42 | High (both agree) |
| 2 | A01 Broken Access Control | Missing Authorization | /admin/users | missing-authz-check | routes/admin.ts:15 | High (both agree) |

### Strongest correlation deep-dive

**SQL Injection at /rest/products/search**

1. **Vulnerable code** (routes/search.ts:42):

  ```javascript
  app.get('/rest/products/search', (req, res) => {
    const query = req.query.q;
    const sql = `SELECT * FROM products WHERE name LIKE '%${query}%'`;
    db.query(sql, (err, results) => {
      res.json(results);
    });
  });
```

2. **Working payload** from ZAP:

  ```text
  /rest/products/search?q=') OR '1'='1
  ```

This bypasses the LIKE clause and returns all products instead of filtered results.

3. **The fix** (parameterized query):

  ```javascript
  app.get('/rest/products/search', (req, res) => {
    const query = req.query.q;
    const sql = `SELECT * FROM products WHERE name LIKE ?`;
    db.query(sql, [`%${query}%`], (err, results) => {
      res.json(results);
    });
  });
```

4. **Why both tools caught it:**

Semgrep detected tainted user input (req.query.q) flowing directly into a SQL query string, while ZAP confirmed the vulnerability by injecting the payload and observing unexpected behavior. The vulnerability is obvious from both static code inspection and runtime exploitation.