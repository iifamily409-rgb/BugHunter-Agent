"""Passive checks: misconfigurations, header hygiene, information disclosure."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from ..core import Finding, Severity, AWS_KEY_RE, GOOGLE_KEY_RE, SLACK_TOKEN_RE, \
    PRIVATE_KEY_RE, JWT_RE

SECURITY_HEADERS = {
    "strict-transport-security": ("Missing HSTS", Severity.LOW,
        "The site does not force HTTPS via Strict-Transport-Security.",
        "Browsers may be downgraded to HTTP, enabling MITM interception and cookie theft.",
        "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"),
    "content-security-policy": ("Missing Content-Security-Policy", Severity.MEDIUM,
        "No CSP is defined, leaving the app reliant on ad-hoc output encoding.",
        "Increases the impact of any XSS by allowing arbitrary script sources.",
        "Deploy a CSP restricting script/style/object sources; start in report-only mode."),
    "x-content-type-options": ("Missing X-Content-Type-Options", Severity.LOW,
        "MIME sniffing is not disabled.",
        "User-generated content can be interpreted as scripts (drive-by XSS).",
        "Add: X-Content-Type-Options: nosniff"),
    "x-frame-options": ("Missing frame protection (X-Frame-Options / CSP frame-ancestors)", Severity.LOW,
        "The page can be framed by any origin.",
        "UI redress / clickjacking attacks against authenticated users.",
        "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'."),
    "referrer-policy": ("Missing Referrer-Policy", Severity.INFO,
        "Full referrer URLs leak to third-party sites.",
        "Sensitive tokens in URLs may leak via the Referer header.",
        "Add: Referrer-Policy: strict-origin-when-cross-origin"),
}

ERROR_SIGS = [
    ("SQL syntax.*?MySQL|mysql_fetch|MySQLSyntaxErrorException", "SQL error traces (MySQL)"),
    ("ORA-[0-9]{4,5}|Oracle.*Exception", "SQL error traces (Oracle)"),
    ("PostgreSQL.*ERROR|psycopg2|pg_query", "SQL error traces (PostgreSQL)"),
    ("Microsoft.*ODBC|SQLServer JDBC Driver|Unclosed quotation mark", "SQL error traces (MSSQL)"),
    ("Warning: include\\(|Fatal error: Uncaught|Parse error:", "PHP errors with paths/stack traces"),
    ("Traceback \\(most recent call last\\)", "Python stack traces"),
    ("at (java|org|com)\\.[a-z]+\\.[A-Za-z]+\\(|Exception in thread", "Java stack traces"),
    ("System\\.NullReferenceException|at System\\.", ".NET stack traces"),
    ("Stack trace:|Debug: |Notice: Undefined", "Generic debug output"),
]

INTERESTING_BODY_PATTERNS = [
    (AWS_KEY_RE, "AWS access key ID in response", Severity.CRITICAL),
    (GOOGLE_KEY_RE, "Google API key in response", Severity.HIGH),
    (SLACK_TOKEN_RE, "Slack token in response", Severity.HIGH),
    (PRIVATE_KEY_RE, "Private key material in response", Severity.CRITICAL),
    (JWT_RE, "JWT exposed in page body", Severity.LOW),
]


def check_security_headers(ctx):
    seen = {}
    for url, page in list(ctx.pages.items())[:40]:
        if page.status >= 400:
            continue
        lower = {k.lower(): v for k, v in page.headers.items()}
        for h, (title, sev, desc, impact, fix) in SECURITY_HEADERS.items():
            if h not in lower and h not in ("x-frame-options",) and title not in seen:
                seen[title] = Finding(title, sev, url, f"Response from {url} lacks {h}",
                                      desc, impact, fix, cwe="CWE-693",
                                      category="Security Misconfiguration")
            if h == "x-frame-options" and h not in lower and \
                    "frame-ancestors" not in lower.get("content-security-policy", "") and \
                    title not in seen:
                seen[title] = Finding(title, sev, url, f"Response from {url} can be framed",
                                      desc, impact, fix, cwe="CWE-1021",
                                      category="Security Misconfiguration")
    yield from seen.values()


def check_cookies(ctx):
    flagged = set()
    for url, page in ctx.pages.items():
        for cookie in page.headers.get("set-cookie", "").split(",") if page.headers.get("set-cookie") else []:
            if not cookie.strip():
                continue
            name = cookie.split("=")[0].strip()
            low = cookie.lower()
            issues = []
            if "httponly" not in low:
                issues.append("missing HttpOnly")
            if "secure" not in low:
                issues.append("missing Secure")
            if "samesite" not in low:
                issues.append("missing SameSite")
            key = (name, tuple(issues))
            if issues and key not in flagged and name.lower() not in ("cf-ray",):
                flagged.add(key)
                yield Finding(
                    f"Cookie '{name}' without protection flags ({'; '.join(issues)})",
                    Severity.LOW, url, cookie[:200],
                    "Session cookies without flags are exposed to JS (XSS exfiltration), "
                    "sent over plaintext, or usable in CSRF.",
                    "Session hijacking via XSS or network interception.",
                    "Set HttpOnly, Secure, and SameSite=Lax/Strict on all session cookies.",
                    confidence="Firm", cwe="CWE-1004", category="Session Management",
                )


def check_error_disclosure(ctx):
    for url, page in ctx.pages.items():
        for pattern, label in ERROR_SIGS:
            m = re.search(pattern, page.body)
            if m:
                start = max(0, m.start() - 80)
                yield Finding(
                    f"Verbose error disclosure: {label}", Severity.LOW, url,
                    page.body[start:m.end() + 120].strip()[:400],
                    "Application errors reveal stack traces, file paths, or SQL details.",
                    "Aids attackers in mapping internals and crafting targeted exploits.",
                    "Disable debug mode in production; return generic error pages.",
                    cwe="CWE-209", category="Information Disclosure",
                    response_snippet=page.body[m.start():m.end()])
                break


def check_secret_in_body(ctx):
    for url, page in ctx.pages.items():
        for pattern, title, sev in INTERESTING_BODY_PATTERNS:
            m = pattern.search(page.body)
            if m:
                match_text = m.group(0)
                yield Finding(
                    title, sev, url, f"Matched pattern: {match_text[:8]}***",
                    "Hard-coded credentials or keys are exposed in client-reachable content.",
                    "Direct account/cloud compromise if the key is valid.",
                    "Revoke and rotate the secret; remove it from client-side code.",
                    confidence="Tentative", cwe="CWE-798", category="Sensitive Data Exposure")


def check_directory_listing(ctx):
    for url, page in ctx.pages.items():
        if page.status == 200 and re.search(
                r"<title>Index of /|Directory listing for /", page.body, re.I):
            yield Finding("Directory listing enabled", Severity.MEDIUM, url,
                          "Server returns a browsable file index.",
                          "Attackers can enumerate and download source, backups, or uploads.",
                          "Disable autoindex (Options -Indexes) and remove sensitive files.",
                          cwe="CWE-548", category="Security Misconfiguration")


def check_cors_misconfig(ctx):
    for url, page in ctx.pages.items():
        acao = page.headers.get("access-control-allow-origin", "")
        acac = page.headers.get("access-control-allow-credentials", "")
        if acao in ("*",) and acac.lower() == "true":
            yield Finding(
                "CORS: wildcard origin with credentials", Severity.HIGH, url,
                f"Access-Control-Allow-Origin: {acao} with Allow-Credentials: true",
                "Any origin can read credentialed responses cross-origin.",
                "Full account data theft from any malicious website the victim visits.",
                "Reflect a strict origin allowlist; never combine '*' with credentials.",
                cwe="CWE-942", category="Access Control")
        elif acao and "origin" not in ctx.http.session.headers.get("origin", "") and urlparse(url).scheme == "https":
            probe = ctx.http.get(url, headers={"Origin": "https://evil-attacker.example"})
            if probe.headers.get("access-control-allow-origin") == "https://evil-attacker.example":
                yield Finding(
                    "CORS: arbitrary origin reflected", Severity.HIGH, url,
                    "Origin https://evil-attacker.example reflected with ACAO header",
                    "The server reflects any Origin, allowing cross-origin reads.",
                    "Sensitive data readable by attacker-controlled sites.",
                    "Validate Origin against a strict allowlist.",
                    cwe="CWE-942", category="Access Control")


def check_tls(ctx):
    asset = ctx.asset
    if urlparse(ctx.target_url).scheme != "https":
        yield Finding(
            "Target served over plaintext HTTP", Severity.MEDIUM, ctx.target_url,
            "Base URL uses http:// scheme",
            "All traffic, including credentials and session cookies, is unencrypted.",
            "MITM capture/alteration of any user session.",
            "Serve HTTPS only and redirect HTTP with HSTS.",
            cwe="CWE-319", category="Transport Security")
        return
    cert = asset.notes and next((n for n in asset.notes if "TLS issuer" in n), "")
    if cert and "expires" in cert:
        yield Finding(
            "TLS certificate details", Severity.INFO, ctx.target_url, cert,
            "Certificate metadata collected during recon.",
            "Informational.", "Ensure automated renewal is in place.",
            cwe="", category="Transport Security")


def check_security_txt(ctx):
    page = ctx.pages.get(ctx.target_url.rstrip("/") + "/.well-known/security.txt")
    if page and page.status == 200:
        yield Finding("security.txt present", Severity.INFO,
                      page.url, page.body[:300],
                      "A security contact policy exists.",
                      "Informational — read the policy and align testing with it.",
                      "N/A", cwe="", category="Program Policy")


PASSIVE_CHECKS = [
    check_security_headers,
    check_cookies,
    check_error_disclosure,
    check_secret_in_body,
    check_directory_listing,
    check_cors_misconfig,
    check_tls,
    check_security_txt,
]
