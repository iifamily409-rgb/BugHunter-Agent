"""Core data structures, HTTP client, and shared utilities."""
from __future__ import annotations

import json
import random
import re
import socket
import string
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional
from urllib.parse import urlparse, urljoin, parse_qsl, urlencode, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


@dataclass
class Finding:
    title: str
    severity: Severity
    url: str
    evidence: str
    description: str
    impact: str
    remediation: str
    confidence: str = "Firm"          # Firm / Tentative / Certain
    cwe: str = ""
    category: str = "General"
    param: str = ""
    payload: str = ""
    request: str = ""
    response_snippet: str = ""
    discovered_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        d = dict(d)
        d["severity"] = Severity(d["severity"])
        return cls(**d)


@dataclass
class Form:
    url: str
    method: str
    action: str
    inputs: list = field(default_factory=list)

    def absolute_action(self) -> str:
        return urljoin(self.url, self.action or self.url)

    def injectable_params(self) -> list:
        return [i.get("name") for i in self.inputs if i.get("name")]


@dataclass
class Page:
    url: str
    status: int
    headers: dict
    body: str
    forms: list = field(default_factory=list)
    links: list = field(default_factory=list)
    params: dict = field(default_factory=dict)
    scripts: list = field(default_factory=list)


def random_string(n: int = 8) -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def normalize_url(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme or "http"
    netloc = p.netloc.lower()
    path = p.path or "/"
    return urlunparse((scheme, netloc, path, "", p.query, ""))


def get_params(url: str) -> dict:
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


def set_params(url: str, params: dict) -> str:
    p = urlparse(url)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, urlencode(params), p.fragment))


def hostname_of(url: str) -> str:
    return urlparse(url).netloc.split(":")[0].lower()


def is_private_ip(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return True
    for info in infos:
        ip = info[4][0]
        if ip.startswith(("10.", "192.168.", "169.254.")) or ip.startswith("172."):
            try:
                second = int(ip.split(".")[1])
                if 16 <= second <= 31:
                    return True
            except (ValueError, IndexError):
                pass
        if ip == "::1" or ip.startswith("fc") or ip.startswith("fd") or ip.startswith("fe80"):
            return True
        if ip.startswith("127."):
            return True
    return False


class HttpClient:
    """Thread-safe HTTP client with rate limiting, retries, and session reuse."""

    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        self.session.verify = False
        self._last_request = 0.0

    def _throttle(self):
        delay = self.config.rate_limit_delay
        if delay > 0:
            now = time.time()
            wait = delay - (now - self._last_request)
            if wait > 0:
                time.sleep(wait)
            self._last_request = time.time()

    def request(self, method: str, url: str, *, allow_redirects: bool = True,
                timeout: Optional[int] = None, **kwargs) -> requests.Response:
        self._throttle()
        kwargs.setdefault("timeout", timeout or self.config.request_timeout)
        kwargs.setdefault("allow_redirects", allow_redirects)
        for attempt in range(self.config.max_retries):
            try:
                resp = self.session.request(method, url, **kwargs)
                if resp.status_code < 500 or attempt == self.config.max_retries - 1:
                    return resp
            except requests.RequestException:
                if attempt == self.config.max_retries - 1:
                    raise
                time.sleep(1.5 * (attempt + 1))
        raise requests.RequestException(f"unreachable: {url}")

    def get(self, url: str, **kw) -> requests.Response:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> requests.Response:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw) -> requests.Response:
        return self.request("HEAD", url, **kw)


def fuzz_url(url: str, param: str, payload: str) -> str:
    params = get_params(url)
    if not params:
        params = {param or "q": payload}
    else:
        params[param] = payload
    return set_params(url, params)


def wrap_marker(payload: str) -> str:
    return f"{payload}"


def extract_json_values(text: str, limit: int = 20) -> list:
    out = []
    try:
        data = json.loads(text)
        stack = [data]
        while stack and len(out) < limit:
            item = stack.pop()
            if isinstance(item, dict):
                stack.extend(item.values())
            elif isinstance(item, list):
                stack.extend(item)
            elif isinstance(item, str):
                out.append(item)
    except (json.JSONDecodeError, TypeError):
        pass
    return out


EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
GOOGLE_KEY_RE = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
SLACK_TOKEN_RE = re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}?")
