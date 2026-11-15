"""Crawler: breadth-first site discovery of pages, forms, parameters, JS endpoints."""
from __future__ import annotations

import concurrent.futures as cf
import re
from collections import deque
from urllib.parse import urljoin, urlparse, parse_qsl, urlencode, urlunparse

from bs4 import BeautifulSoup

from .core import HttpClient, Page, Form, hostname_of, normalize_url

LINK_RE = re.compile(r"""["'`](/[^"'`\s]{2,200})["'`]""")
API_PATH_RE = re.compile(r"""["'`]/((?:api|v[0-9]|rest|ajax|json|service|endpoint)[^"'`\s]{0,150})["'`]""")

SKIP_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".css", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".webm", ".pdf", ".zip", ".gz", ".tar",
)


def looks_like_asset(url: str) -> bool:
    return url.lower().split("?", 1)[0].endswith(SKIP_EXT)


def extract_forms(html: str, page_url: str) -> list:
    forms = []
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return forms
    for tag in soup.find_all("form"):
        inputs = []
        for inp in tag.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if name:
                inputs.append({
                    "name": name,
                    "type": (inp.get("type") or "text").lower(),
                    "value": inp.get("value", ""),
                })
        forms.append(Form(
            url=page_url,
            method=(tag.get("method") or "GET").upper(),
            action=tag.get("action") or "",
            inputs=inputs,
        ))
    return forms


def extract_links(html: str, base: str) -> set:
    links = set()
    try:
        soup = BeautifulSoup(html, "html.parser")
    except Exception:
        return links
    for tag in soup.find_all(["a", "area"]):
        href = tag.get("href")
        if href and not href.startswith(("mailto:", "tel:", "javascript:", "#", "data:")):
            links.add(urljoin(base, href))
    for tag in soup.find_all(["script", "iframe", "link"]):
        src = tag.get("src") or tag.get("href")
        if src and not src.startswith("data:"):
            links.add(urljoin(base, src))
    for m in LINK_RE.findall(html):
        links.add(urljoin(base, m))
    return links


class Crawler:
    def __init__(self, cfg, http: HttpClient):
        self.cfg = cfg
        self.http = http

    def same_origin_or_scope(self, url: str) -> bool:
        if not self.cfg.in_scope(url):
            return False
        return True

    def canonical(self, url: str) -> str:
        """Strip fragments; keep query (params are attack surface)."""
        p = urlparse(url)
        return urlunparse((p.scheme, p.netloc, p.path, p.params, p.query, ""))

    def crawl(self, seeds: list) -> dict:
        pages: dict = {}
        queue = deque((s, 0) for s in seeds)
        seen = set()
        forms: list = []
        js_endpoints: set = set()
        param_urls: set = set()

        while queue and len(pages) < self.cfg.max_pages:
            batch = []
            while queue and len(batch) < self.cfg.concurrency * 2:
                url, depth = queue.popleft()
                canon = self.canonical(url)
                if canon in seen or looks_like_asset(canon):
                    continue
                if not self.same_origin_or_scope(canon):
                    continue
                seen.add(canon)
                batch.append((url, depth, canon))

            def fetch(item):
                url, depth, canon = item
                try:
                    resp = self.http.get(url)
                    return item, resp
                except Exception:
                    return item, None

            with cf.ThreadPoolExecutor(max_workers=self.cfg.concurrency) as pool:
                for (url, depth, canon), resp in pool.map(fetch, batch):
                    if resp is None or resp.status_code >= 500:
                        continue
                    ctype = resp.headers.get("content-type", "")
                    body = resp.text if "text" in ctype or "json" in ctype or "html" in ctype else ""
                    page = Page(url=canon, status=resp.status_code,
                                headers=dict(resp.headers), body=body[:500_000])
                    pages[canon] = page
                    if depth >= self.cfg.max_depth:
                        continue

                    if "html" in ctype:
                        page.forms = [f for f in extract_forms(body, canon)]
                        forms.extend(page.forms)
                        for link in extract_links(body, canon):
                            if self.same_origin_or_scope(link):
                                queue.append((link, depth + 1))

                    for script_src in re.findall(r'<script[^>]+src=["\']([^"\']+)', body):
                        js_url = urljoin(canon, script_src)
                        if self.same_origin_or_scope(js_url) and js_url.endswith(".js"):
                            try:
                                js_resp = self.http.get(js_url)
                                for m in API_PATH_RE.findall(js_resp.text):
                                    js_endpoints.add(urljoin(js_url, "/" + m))
                            except Exception:
                                pass

                    if urlparse(canon).query:
                        param_urls.add(canon)

        return {
            "pages": pages,
            "forms": forms,
            "js_endpoints": sorted(js_endpoints),
            "param_urls": sorted(param_urls),
        }
