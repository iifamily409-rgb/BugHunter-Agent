"""Reconnaissance: subdomains, DNS, ports, technology fingerprinting, sensitive paths."""
from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import json
import socket
import ssl
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin

try:
    import dns.resolver  # optional
except ImportError:
    pass

from .core import HttpClient, Page, hostname_of, is_private_ip, EMAIL_RE

COMMON_SUBS = [
    "www", "api", "app", "dev", "staging", "stage", "test", "qa", "uat", "demo",
    "admin", "portal", "mail", "vpn", "cdn", "assets", "static", "img", "media",
    "blog", "shop", "store", "pay", "payment", "auth", "sso", "login", "id",
    "git", "jira", "confluence", "jenkins", "ci", "grafana", "kibana", "elastic",
    "db", "sql", "mysql", "postgres", "redis", "rabbitmq", "mq", "kafka",
    "internal", "intranet", "corp", "vpn2", "old", "legacy", "backup", "beta",
    "sandbox", "docs", "help", "support", "status", "monitor", "nagios",
    "webmail", "smtp", "ftp", "ns1", "ns2", "gateway", "gw", "proxy", "lb",
    "uploads", "files", "download", "share", "cloud", "s3", "bucket", "v2", "v1",
]

ADMIN_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login", "/wp-admin/",
    "/manager/html", "/phpmyadmin/", "/pma/", "/adminer.php", "/console/",
    "/dashboard", "/cpanel", "/jenkins/", "/actuator", "/actuator/env",
    "/solr/", "/elasticsearch/", "/_cat/indices", "/api", "/graphql",
    "/graphiql", "/swagger", "/swagger-ui.html", "/swagger.json", "/openapi.json",
    "/api-docs", "/api/v1", "/debug", "/debug/vars", "/trace", "/metrics",
    "/server-status", "/server-info", "/.git/config", "/.git/HEAD",
    "/.env", "/.env.local", "/.env.production", "/.env.bak", "/.htaccess",
    "/.htpasswd", "/.DS_Store", "/web.config", "/config.php.bak",
    "/composer.json", "/package.json", "/yarn.lock", "/requirements.txt",
    "/backup.zip", "/backup.tar.gz", "/site.tar.gz", "/dump.sql", "/db.sql",
    "/database.sql", "/db.sqlite", "/app.db", "/id_rsa", "/.ssh/id_rsa",
    "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/.well-known/security.txt",
    "/cgi-bin/", "/phpinfo.php", "/info.php", "/test.php",
    "/wp-config.php.bak", "/.svn/entries", "/.aws/credentials", "/Dockerfile",
    "/docker-compose.yml", "/.dockerenv", "/kubernetes", "/.kube/config",
]

INTERESTING_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"), (53, "dns"),
    (80, "http"), (110, "pop3"), (143, "imap"), (443, "https"), (445, "smb"),
    (1433, "mssql"), (1521, "oracle"), (2049, "nfs"), (3000, "node-dev"),
    (3306, "mysql"), (3389, "rdp"), (5432, "postgres"), (5601, "kibana"),
    (5900, "vnc"), (6379, "redis"), (8000, "http-dev"), (8080, "http-alt"),
    (8443, "https-alt"), (8888, "http-alt2"), (9000, "http-alt3"),
    (9200, "elasticsearch"), (9300, "es-cluster"), (11211, "memcached"),
    (27017, "mongodb"), (50000, "sap"),
]


@dataclass
class Asset:
    url: str
    host: str
    ips: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    technologies: dict = field(default_factory=dict)
    interesting_paths: list = field(default_factory=list)
    emails: list = field(default_factory=list)
    notes: list = field(default_factory=list)


def resolve_host(host: str) -> list:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None) if ai[0] in (socket.AF_INET, socket.AF_INET6)})
    except socket.gaierror:
        return []


def enumerate_subdomains(domain: str, http: HttpClient, timeout: int = 20) -> list:
    """crt.sh certificate transparency + DNS brute force of common subdomains."""
    found = {domain}
    try:
        resp = http.get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=timeout)
        if resp.status_code == 200 and resp.text.strip().startswith("["):
            for entry in json.loads(resp.text):
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(domain) and "*" not in name:
                        found.add(name)
    except Exception:
        pass

    def check(sub):
        fqdn = f"{sub}.{domain}"
        return fqdn if resolve_host(fqdn) else None

    with cf.ThreadPoolExecutor(max_workers=20) as pool:
        for res in pool.map(check, COMMON_SUBS):
            if res:
                found.add(res)
    return sorted(found)


def scan_ports(host: str, timeout: float = 1.2) -> list:
    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port
        except OSError:
            return None

    with cf.ThreadPoolExecutor(max_workers=60) as pool:
        open_ports = [p for p in pool.map(probe, [p for p, _ in INTERESTING_PORTS]) if p]
    return [(p, dict(INTERESTING_PORTS)[p]) for p in open_ports]


def fingerprint(resp, body: str) -> dict:
    tech = {}
    headers = {k.lower(): v for k, v in resp.headers.items()}
    server = headers.get("server", "")
    if server:
        tech["Server"] = server
    powered = headers.get("x-powered-by", "")
    if powered:
        tech["Framework"] = powered
    if "wp-content" in body or "wp-includes" in body:
        tech["CMS"] = "WordPress"
    if "__NEXT_DATA__" in body or "/_next/static" in body:
        tech["Framework"] = "Next.js"
    if "X-Powered-CMS" in headers or "drupal" in body.lower():
        tech["CMS"] = tech.get("CMS", "Drupal")
    if "Shopify" in body or "cdn.shopify.com" in body:
        tech["Platform"] = "Shopify"
    if "laravel_session" in body or "XSRF-TOKEN" in headers:
        tech["Framework"] = tech.get("Framework", "Laravel")
    if "JSESSIONID" in headers.get("set-cookie", ""):
        tech["Runtime"] = "Java"
    if "ASP.NET" in headers.get("x-aspnet-version", "") + headers.get("x-aspnetmvc-version", ""):
        tech["Runtime"] = "ASP.NET"
    if "cloudflare" in headers.get("server", "").lower() or "cf-ray" in headers:
        tech["WAF/CDN"] = "Cloudflare"
    if "x-sucuri-id" in headers:
        tech["WAF/CDN"] = "Sucuri"
    if headers.get("x-generator", ""):
        tech["Generator"] = headers["x-generator"]
    return tech


def probe_paths(base_url: str, http: HttpClient, limit: int) -> list:
    hits = []
    with cf.ThreadPoolExecutor(max_workers=12) as pool:
        futures = {pool.submit(http.get, urljoin(base_url, p), allow_redirects=False): p
                   for p in ADMIN_PATHS[:limit]}
        for fut, path in futures.items():
            try:
                resp = fut.result()
            except Exception:
                continue
            if resp.status_code in (200, 401, 403):
                marker = ""
                if resp.status_code == 200:
                    snippet = resp.text[:400].lower()
                    if any(x in snippet for x in ("not found", "error 404", "page cannot")):
                        continue
                    marker = f" ({len(resp.text)} bytes)"
                hits.append((path, resp.status_code, marker))
    return hits


def tls_certificate(host: str, port: int = 443) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
        return {
            "subject": dict(x[0] for x in cert.get("subject", ())).get("commonName", ""),
            "issuer": dict(x[0] for x in cert.get("issuer", ())).get("organizationName", ""),
            "not_after": cert.get("notAfter", ""),
            "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:50],
        }
    except Exception:
        return {}


def recon_target(base_url: str, http: HttpClient, cfg) -> Asset:
    host = hostname_of(base_url)
    asset = Asset(url=base_url, host=host, ips=resolve_host(host))
    if asset.ips:
        try:
            asset.notes.append(f"IP {asset.ips[0]} ({ipaddress.ip_address(asset.ips[0]).version}-address)")
        except ValueError:
            pass

    resp = http.get(base_url)
    asset.technologies = fingerprint(resp, resp.text)
    asset.emails = sorted(set(EMAIL_RE.findall(resp.text)))[:25]

    for path in ("/robots.txt", "/sitemap.xml"):
        try:
            r = http.get(urljoin(base_url, path), allow_redirects=False)
            if r.status_code == 200 and len(r.text) > 10:
                asset.interesting_paths.append((path, 200, ""))
                if path == "/robots.txt":
                    for line in r.text.splitlines():
                        if line.lower().startswith("disallow:"):
                            asset.notes.append(f"robots.txt disallow: {line.split(':', 1)[1].strip()}")
        except Exception:
            pass

    asset.interesting_paths.extend(probe_paths(base_url, http, cfg.wordlist_size))
    asset.open_ports = scan_ports(host)
    if urlparse(base_url).scheme == "https":
        cert = tls_certificate(host)
        if cert:
            asset.notes.append(f"TLS issuer: {cert['issuer']} expires: {cert['not_after']}")
    return asset
