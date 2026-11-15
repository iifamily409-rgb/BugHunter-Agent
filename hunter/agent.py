"""The autonomous agent: per-target scan pipeline + 24/7 daemon loop."""
from __future__ import annotations

import json
import os
import time
from urllib.parse import urljoin

from rich.console import Console

from .core import HttpClient, Finding, is_private_ip
from .config import Config
from .recon import recon_target, Asset
from .crawler import Crawler
from .detectors import ScanContext, run_all_checks
from .report import write_reports, dedupe

console = Console()


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.http = HttpClient(cfg)
        self.state = self._load_state()
        self._stop = False

    # ------------------------------------------------------------------ state
    def _load_state(self) -> dict:
        path = self.cfg.state_file
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            except (json.JSONDecodeError, OSError):
                pass
        return {"targets": {}}

    def _save_state(self):
        os.makedirs(os.path.dirname(self.cfg.state_file) or ".", exist_ok=True)
        with open(self.cfg.state_file, "w", encoding="utf-8") as fh:
            json.dump(self.state, fh, indent=2, default=str)

    def log(self, msg: str):
        console.print(msg)

    # ------------------------------------------------------------------ guard
    def _guard_target(self, url: str):
        if not self.cfg.in_scope(url):
            raise PermissionError(f"target {url} outside scope_allow")
        host = url.split("//", 1)[-1].split("/")[0].split(":")[0]
        if not self.cfg.allow_private_hosts and (
                is_private_ip(host) or host in ("localhost",) or host.endswith(".local") or
                host.endswith(".internal")):
            raise PermissionError(
                f"{host} resolves to private/internal space. "
                "Set allow_private_hosts: true ONLY for your own lab targets.")

    # ------------------------------------------------------------------ pipeline
    def scan_target(self, target_url: str) -> list:
        t0 = time.time()
        self._guard_target(target_url)
        self.log(f"\n[bold cyan]═══ Scanning {target_url} ═══[/]")

        self.log("[bold]→ Recon[/]")
        try:
            asset = recon_target(target_url, self.http, self.cfg)
        except Exception as exc:
            self.log(f"[red]Target unreachable: {exc}[/]")
            return []
        self.log(f"  IPs: {asset.ips or 'unresolved'} | ports: "
                 f"{[p for p, _ in asset.open_ports]} | tech: {asset.technologies}")

        self.log("[bold]→ Crawl[/]")
        crawler = Crawler(self.cfg, self.http)
        crawl = crawler.crawl([target_url])
        pages, forms = crawl["pages"], crawl["forms"]
        param_urls = sorted(set(crawl["param_urls"]) |
                            {u for u, p in pages.items() if p.params})

        # GET forms imply parameterized endpoints even without observed queries
        from .core import get_params, set_params
        for form in forms:
            if form.method == "GET" and form.injectable_params():
                probe_url = form.absolute_action()
                params = get_params(probe_url)
                for name in form.injectable_params():
                    params.setdefault(name, "")
                candidate = set_params(probe_url, params)
                if candidate not in param_urls:
                    param_urls.append(candidate)

        # recon-confirmed sensitive paths become scannable pages too
        for path, status, _ in asset.interesting_paths:
            if status == 200:
                probe = urljoin(target_url, path)
                if probe not in pages:
                    try:
                        resp = self.http.get(probe)
                        from .core import Page
                        pages[probe] = Page(url=probe, status=resp.status_code,
                                            headers=dict(resp.headers),
                                            body=resp.text[:500_000])
                    except Exception:
                        pass

        for ep in crawl["js_endpoints"][:30]:
            if self.cfg.in_scope(ep):
                param_urls.append(ep)
        self.log(f"  pages: {len(pages)} | forms: {len(forms)} | "
                 f"parameterized URLs: {len(param_urls)}")

        self.log("[bold]→ Vulnerability checks[/]")
        ctx = ScanContext(self.cfg, self.http, target_url, pages, forms,
                          param_urls, asset, self.log)
        findings = run_all_checks(ctx)
        findings = dedupe(findings)

        self.log("[bold]→ Report[/]")
        md_path, html_path = write_reports(target_url, asset, findings,
                                           self.cfg.output_dir, t0)
        self.log(f"  [green]Markdown:[/] {md_path}")
        self.log(f"  [green]HTML:[/]     {html_path}")

        prev = self.state["targets"].get(target_url, {})
        def state_key(f):
            return f"{f.title}@{f.url.split('?')[0]}@{f.param}"
        prev_keys = {state_key(Finding.from_dict(fd)) for fd in prev.get("findings", [])}
        new = [f for f in findings if state_key(f) not in prev_keys]
        self.state["targets"][target_url] = {
            "last_scan": time.time(),
            "findings": [f.to_dict() for f in findings],
            "risk_score": sum(f.severity.rank for f in findings),
        }
        self._save_state()

        summary = ", ".join(f"{f.severity.value}: {f.title}" for f in
                            sorted(findings, key=lambda f: -f.severity.rank)[:8])
        self.log(f"[bold]Done in {time.time() - t0:.0f}s — {len(findings)} findings "
                 f"({len(new)} new).[/]")
        if summary:
            self.log(f"  Top: {summary}")
        return findings

    # ------------------------------------------------------------------ daemon
    def run_forever(self):
        self.log("[bold green]🛡 Bug Hunter daemon started — 24/7 mode.[/]")
        self.log(f"Targets: {self.cfg.targets} | interval: {self.cfg.interval_seconds}s")
        while not self._stop:
            for target in list(self.cfg.targets):
                if self._stop:
                    break
                try:
                    self.scan_target(target)
                except PermissionError as exc:
                    self.log(f"[red]SCOPE BLOCKED {target}: {exc}[/]")
                except Exception as exc:
                    self.log(f"[red]Error scanning {target}: {exc}[/]")
            if self._stop:
                break
            self.log(f"[dim]Sleeping {self.cfg.interval_seconds}s until next cycle...[/]")
            for _ in range(self.cfg.interval_seconds):
                if self._stop:
                    break
                time.sleep(1)

    def stop(self):
        self._stop = True
