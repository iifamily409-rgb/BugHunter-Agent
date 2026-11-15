# 🐞 Bug Hunter Agent

An autonomous, 24/7-capable bug-hunting agent for **authorized** web application
targets. It performs reconnaissance, deep crawling, passive hygiene checks, and
non-destructive active exploitation probes, then writes an investigative
Markdown + HTML report.

## ⚠️ Authorization

The agent performs **active security testing**. It refuses to run unless you:

1. Pass the exact attestation flag:
   ```bash
   python main.py --authorized "I confirm I am authorized to perform security testing against every target in scope" ...
   ```
2. Define explicit `scope_allow` wildcards so it can never stray off-target.
3. Only test targets you own or that are covered by a bug-bounty program whose
   policy you have read (some programs exclude subdomains, certain vuln classes,
   or automated scanning — check before running).

## Install

```bash
pip install -r requirements.txt
```

## Quick start

```bash
# single scan
python main.py -t https://target.com --allow "*.target.com" \
  --authorized "I confirm I am authorized to perform security testing against every target in scope"

# heavier pass (time-based blind SQLi, RCE timing, rate-limit tests)
python main.py -c hunter.yaml --aggressive --authorized "..."

# 24/7 daemon: rescan every 6 hours, track new findings in state/, re-report
python main.py -c hunter.yaml --daemon --interval 21600 --authorized "..."
```

Config file: copy `hunter.yaml.example` → `hunter.yaml` and edit targets/scope.

## Pipeline

| Phase | What it does |
|---|---|
| **Recon** | crt.sh certificate-transparency subdomain enum, DNS brute of ~80 common subs, port scan of 35 high-value services, HTTP tech fingerprinting, TLS cert metadata, robots/sitemap, ~120 sensitive-path probes (`.git`, `.env`, actuator, phpMyAdmin, GraphQL, backups…) |
| **Crawl** | BFS crawler with scope enforcement; extracts pages, HTML forms, URL parameters, and JS-referenced API endpoints |
| **Passive checks** | Security headers, cookie flags, verbose errors/stack traces, secrets in responses (AWS/Google/Slack keys, private keys), directory listings, CORS misconfig (incl. reflected-origin test), plaintext HTTP, security.txt |
| **Active checks** | Reflected XSS (6 payload families), DOM XSS sinks, SQLi error-based, SQLi boolean-based differential, SQLi time-based blind, OS command injection (timing), SSTI (Jinja/Twig/ERB eval markers), open redirect (server + client-side), path traversal/LFI, SSRF (incl. cloud metadata), Host-header injection, CRLF injection, XXE, GraphQL introspection, IDOR heuristics, auth-bypass headers, login rate-limiting |
| **Report** | Markdown + self-contained HTML: executive summary, risk score, attack surface, per-finding evidence → impact → remediation, CWE refs |

## Design guarantees

- **Scope enforcement on every request** — anything outside `scope_allow` (minus
  `scope_deny`) is never touched.
- **Private-network guard** — refuses to scan RFC1918/loopback/link-local targets
  unless `allow_private_hosts: true` (lab mode).
- **Non-destructive payloads** — markers, boolean differentials, and time delays
  only. No data destruction, no DoS, no account brute force.
- **State tracking** — `state/findings.json` remembers prior findings; the daemon
  reports new/changed ones each cycle.

## Extending

Add a check to `hunter/detectors/passive.py` or `active.py`:

```python
def check_my_new_bug(ctx):
    for url in ctx.param_urls:
        ...
        yield Finding(title, Severity.MEDIUM, url, evidence, description, impact, remediation)
```

It is auto-registered (functions listed in `PASSIVE_CHECKS` / `ACTIVE_CHECKS`).

## Limitations

- No browser engine: DOM XSS is heuristic (sink analysis), not executed.
- Blind XSS / OOB callbacks require pointing `COLLAB` in `detectors/active.py`
  at your own collaborator host.
- Authenticated scanning: run behind a session by adding cookies to the
  `HttpClient` session in code before scanning (future: `--cookie` flag).
- Tentative findings (e.g. IDOR heuristics) require manual confirmation before
  you report them to a program.

## Legal

Use only on systems you are authorized to test. Unauthorized access to computer
systems is illegal in most jurisdictions.
