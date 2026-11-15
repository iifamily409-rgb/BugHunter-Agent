"""Detector registry: collects all check generators for the scan context."""
from __future__ import annotations

from . import passive, active


class ScanContext:
    """Everything a check may need. `checks` receive this object."""

    def __init__(self, cfg, http, target_url, pages, forms, param_urls, asset, log):
        self.cfg = cfg
        self.http = http
        self.target_url = target_url
        self.pages = pages
        self.forms = forms
        self.param_urls = param_urls
        self.asset = asset
        self.log = log

    def get_params(self, url):
        from ..core import get_params
        return get_params(url)


def run_all_checks(ctx) -> list:
    findings = []
    for module in (passive, active):
        for check in module.PASSIVE_CHECKS if module is passive else module.ACTIVE_CHECKS:
            name = check.__name__
            try:
                for finding in check(ctx):
                    findings.append(finding)
                    ctx.log(f"  [finding] {finding.severity.value:8s} {finding.title}")
            except Exception as exc:
                ctx.log(f"  [warn] check {name} failed: {exc}")
    return findings
