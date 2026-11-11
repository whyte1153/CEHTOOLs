# CEH Toolkit

A modular, pure-bash toolkit for **authorized** security assessment and defensive auditing, built around the reconnaissance, scanning, enumeration and hardening phases covered in CEH-style training.

> **Legal notice:** Only use this against systems you own or have *written* permission to test. Unauthorized scanning can be illegal. The toolkit enforces a scope file to help you stay inside your authorization.

## Quick start

```bash
unzip ceh-toolkit.zip && cd ceh-toolkit
./install.sh            # chmod + dependency check (add --link for a `ceh` command)
./ceh.sh                # interactive menu
./ceh.sh help           # CLI usage
./tests/run-tests.sh    # self-test
```

Requires: `bash` 4+, `curl`, `openssl`, `coreutils`. Optional: `dig`/`host`/`nslookup` (richer DNS), `ss`.

## Modules

| Command | What it does |
|---|---|
| `portscan <host> [ports\|top\|all]` | Parallel TCP connect scan, service names, risky-port notes |
| `banner <host> <port>` | Service banner / version disclosure check |
| `dns <domain> [--brute]` | A/AAAA/MX/NS/TXT/SOA, SPF & DMARC audit, AXFR misconfig check, subdomain wordlist enumeration |
| `web <url\|host>` | Security headers, info disclosure, cookie flags, HTTP methods, exposed sensitive files |
| `tls <host> [port]` | Certificate expiry, signature algorithm, deprecated protocol detection |
| `hashid <hash>` | Identify likely hash algorithm and judge its suitability for password storage |
| `passcheck [--pwned]` | Hidden-input password strength and entropy check; optional k-anonymity breach lookup |
| `sysaudit` | Local Linux hardening audit (accounts, SSH, permissions, listeners, firewall, sysctl, sudo) |
| `logs <file> [threshold]` | Brute-force detection from auth logs |
| `fim baseline\|check <dir>` | File integrity monitoring using SHA-256 baselines |
| `report [txt\|html]` | Severity-ranked report from all recorded findings |
| `scope` | View / add authorized targets |

## Customization

- `config/ceh.conf` — timeouts, thread count, default ports, thresholds, report location.
- `config/user.conf` — optional overrides (create it; it is sourced after `ceh.conf` and survives upgrades).
- `config/scope.txt` — authorized targets (supports wildcards like `*.example.org`).
- `wordlists/` — swap in larger subdomain or password lists.
- **Add a module:** drop `modules/mytool.sh` defining `run_mytool()`, use `finding SEVERITY mytool "message"` to feed the report, and add a case line in `ceh.sh`.

## Layout

```
ceh.sh            launcher (menu + CLI)
lib/common.sh     logging, validation, scope gate, helpers
modules/          portscan, dnsrecon, web, credentials, defensive, report
config/           ceh.conf, scope.txt
wordlists/        subdomains.txt, common-passwords.txt
reports/          findings log, generated reports, FIM baselines
tests/            run-tests.sh
```

## Notes

- Targets are validated against a strict character set before use, blocking shell injection.
- Passwords are read silently and are never written to disk or logs.
- Findings are logged per-day to `reports/findings-YYYYMMDD.log` and rolled up by `report`.
