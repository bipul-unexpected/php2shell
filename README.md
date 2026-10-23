# php2shell — CVE-2026-109618 / CVE-2026-109619

Exposure scanner, reproducible lab, and detection rules for the PHP `session.upload_progress`
RCE pair disclosed 2026-10-21.

| CVE | Root cause | Class | CVSS |
|-----|------------|-------|------|
| CVE-2026-109618 | `longjmp()` / `zend_bailout()` during multipart OOM leaves Zend engine state invalid; request shutdown then branches on freed memory | Pre-auth RCE | 9.2 |
| CVE-2026-109619 | Request-owned globals (`BG(unserialize)`, `PS(serializer)`) survive into the next request on the same FPM worker | Pre-auth RCE (UAF) | 9.2 |

Affected: **PHP 5.4.0 – 8.5.11**, all web SAPIs (mod_php, FPM, php-cgi, FrankenPHP, LiteSpeed).
Fixed: **8.2.35 / 8.3.36 / 8.4.27 / 8.5.12**. PHP 7.4 / 8.0 / 8.1 only via vendor backports.

Patch reference: `php-src` commit `3584a98` (≈300 files, Zend engine + session ext).

---

## Scope — read this before running anything

`php2shell_scan.py` is a **non-destructive exposure check**. It fingerprints and probes; it does
not crash the target, does not write a session file with executable content, and does not execute
anything.

`lab/` is a complete, intentionally vulnerable stack bound to loopback. `lab/exploit_chain_a.py`
refuses any target that is not loopback / RFC1918 unless you pass `--lab-override`, and that flag
exists for **your own authorized infrastructure only**.

Do not point either script at a host you are not contracted to test. `103.23.41.226` is third-party
and not included in any scope this repo can authorize.

---

## The five chains

| Chain | Vector | Pre-auth | Condition |
|-------|--------|:--------:|-----------|
| **A** | `PHP_SESSION_UPLOAD_PROGRESS` filename → session file → LFI `include()` | yes | app has any LFI sink |
| **B** | `var_destroy` UAF → `__destruct` without serialize lock → handler overwrite | no | app calls `unserialize()` on attacker data |
| **C** | FPM worker serializer mismatch → `\|O:...` filename → `__destruct` on decode failure | yes | two dirs with different `session.serialize_handler` |
| **D** | multipart OOM → stale `EG()` at mod_php shutdown | yes | **none** — any endpoint on Apache mod_php |
| **E** | `session_start()` OOM → stale `BG()` consumed by next request's rfc1867 handler | yes | producer: any `session_start()` endpoint; consumer: **any** endpoint, FPM |

Chain D is the one with no preconditions. Chain E is the one that hits WordPress/Laravel/Joomla/Drupal
without an app bug, because the consumer only needs to accept a multipart POST.

Structural detail that makes all of this possible:

- `MULTIPART_EVENT_FORMDATA` accepts `PHPSESSID` from the **POST body**, ignoring `session.use_only_cookies`.
- `add_assoc_string_ex(*data->filename)` stores the raw filename into the session file with no validation.
- `PS(serializer)` is not reset in `php_rshutdown_session_globals()`.
- `i_zval_ptr_dtor` runs `__destruct` while `BG(serialize_lock) == 0` — on both success and failure paths.

---

## Scanner

```bash
python3 php2shell_scan.py --target https://your-host.example
python3 php2shell_scan.py --target https://your-host.example --json report.json
python3 php2shell_scan.py --target https://your-host.example --passive      # headers only
```

Stdlib only. No dependencies.

What it reports:

- PHP version from `X-Powered-By`, `Server`, error bodies, optional `phpinfo` leakage.
- Patched / vulnerable verdict against the fixed-version table per branch.
- SAPI guess (mod_php vs FPM) — determines whether Chain D is on the table.
- `session.upload_progress` reachable (the shared precondition for A/C/E).
- Session fixation via POST-body `PHPSESSID` (`accepted` / `rejected` / `unknown`).
- Optional LFI sink check if you pass `--lfi-param`.

What it deliberately does **not** do: OOM bombs, Chain B `unserialize` probes, or any payload
that executes. Chain D/E confirmation requires inducing a crash, so it lives in the lab only.

Exit codes: `0` no exposure found, `1` exposure indicators found, `2` target unreachable.

Version table logic:

```
8.2.x -> patched at 8.2.35
8.3.x -> patched at 8.3.36
8.4.x -> patched at 8.4.27
8.5.x -> patched at 8.5.12
<= 8.1 -> vulnerable by upstream (EOL); 'unknown' if a vendor backport may be present
```

`X-Powered-By` is often stripped. A clean fingerprint is not proof of a clean target — pair the
scanner result with package inventory (`dpkg -l | grep php`, `php -v`, container image tags).

---

## Lab

Intentionally vulnerable PHP 8.2.34, both SAPIs.

```bash
cd lab
docker compose up -d --build
# nginx + php-fpm  -> http://127.0.0.1:18080
# apache + mod_php -> http://127.0.0.1:18081
```

Endpoints:

| Path | Purpose |
|------|---------|
| `/lfi.php?file=...` | LFI sink for Chain A |
| `/session.php` | calls `session_start()` — Chain E producer |
| `/upload.php` | multipart endpoint, no session use |
| `/index.php` | plain landing page |

Verify exposure:

```bash
python3 ../php2shell_scan.py --target http://127.0.0.1:18080
```

Chain A end-to-end against the lab:

```bash
python3 exploit_chain_a.py --target http://127.0.0.1:18080 --command 'id'
```

Expected: `uid=33(www-data) gid=33(www-data) ...`

How Chain A works here:

1. POST multipart with `PHP_SESSION_UPLOAD_PROGRESS` set and a chosen `PHPSESSID`.
2. Put PHP in the file part's `filename` (`<?php system($_GET[c]);?>`).
3. The rfc1867 handler writes that filename verbatim into `/tmp/sess/<sid>`.
4. `lfi.php` includes `/tmp/sess/<sid>` → the `<?php` block executes.

No authentication at any step.

---

## Detection

`detection/php2shell.rules` — Suricata/Snort.
`detection/modsecurity.conf` — ModSecurity v2/v3 drop-in.

Fastest mitigation that actually covers the primary vector: reject multipart bodies containing
`PHP_SESSION_UPLOAD_PROGRESS`. Near-zero legitimate use.

```ini
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On
```

Those are **surface reduction, not a fix**. The OOM corruption (Chain D) is in the Zend engine core;
nothing in `php.ini` closes it. Patch to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12.

Additional operational measures: restart FPM workers after any suspicion of a stale-state request
(worker-local state is the Chain E primitive), and alert on `X-Powered-By` versions inside the
affected range at the edge.

---

## Files

```
php2shell_scan.py          non-destructive exposure scanner (stdlib)
lab/docker-compose.yml     nginx+FPM :18080, apache+mod_php :18081
lab/php/Dockerfile         php:8.2.34-fpm
lab/php-apache/Dockerfile  php:8.2.34-apache
lab/php/php.ini            vulnerable config (upload_progress on, small memory_limit)
lab/www/*.php              LFI sink, session endpoint, upload endpoint
lab/exploit_chain_a.py     Chain A PoC, loopback/private only unless --lab-override
detection/php2shell.rules  Suricata/Snort signatures
detection/modsecurity.conf ModSecurity rules
```

---

## References

- PHP advisory: https://www.php.net/archive/2026.php#2026-10-21-5
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)
- CERT-EU Security Advisory 2026-018
- NCSC-NL operational tracker: https://github.com/NCSC-NL/php2shell
- Technical analysis: https://github.com/ikow/php2shell-poc/blob/main/docs/ANALYSIS.md

Authorized testing and defensive deployment only.
