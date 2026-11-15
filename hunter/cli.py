"""CLI entrypoint."""
from __future__ import annotations

import argparse
import signal
import sys

from .config import load_config, verify_authorization, AUTH_ATTESTATION, AuthorizationError, ScopeError
from .agent import Agent
from . import __version__


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bug-hunter",
        description="Autonomous AI bug hunter for authorized web targets. "
                    "Recon → crawl → passive & active checks → investigative report.",
        epilog=f'Authorization flag value: --authorized "{AUTH_ATTESTATION}"',
    )
    p.add_argument("--version", action="version", version=f"bug-hunter {__version__}")
    p.add_argument("-c", "--config", default="hunter.yaml", help="YAML config file")
    p.add_argument("-t", "--target", action="append", dest="targets",
                   help="target URL (repeatable)")
    p.add_argument("--authorized", metavar="PHRASE",
                   help=f'attestation: "{AUTH_ATTESTATION}"')
    p.add_argument("--allow", action="append", dest="scope_allow",
                   help="scope wildcard, e.g. '*.example.com' (repeatable)")
    p.add_argument("--private", action="store_true",
                   help="allow private/internal hosts (lab use only)")
    p.add_argument("--max-pages", type=int)
    p.add_argument("--max-depth", type=int)
    p.add_argument("--delay", type=float, help="rate limit delay in seconds")
    p.add_argument("--aggressive", action="store_true",
                   help="enable time-based blind probes (slower)")
    p.add_argument("--passive", action="store_true", help="disable active probes")
    p.add_argument("--output", help="report output directory")
    p.add_argument("--state-file", help="findings state database (JSON)")
    p.add_argument("--daemon", action="store_true",
                   help="run 24/7: rescan all targets every --interval seconds")
    p.add_argument("--interval", type=int, help="daemon rescan interval in seconds")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    overrides = {
        "targets": args.targets,
        "scope_allow": args.scope_allow,
        "allow_private_hosts": args.private,
        "max_pages": args.max_pages,
        "max_depth": args.max_depth,
        "rate_limit_delay": args.delay,
        "aggressive": args.aggressive,
        "active_scans": not args.passive,
        "output_dir": args.output,
        "state_file": args.state_file,
        "daemon": args.daemon,
        "interval_seconds": args.interval,
    }
    try:
        cfg = load_config(args.config, overrides)
        verify_authorization(args.authorized, cfg.targets, cfg.scope_allow)
        cfg.validate()
    except (AuthorizationError, ScopeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2

    agent = Agent(cfg)
    if cfg.daemon:
        signal.signal(signal.SIGINT, lambda *_: agent.stop())
        signal.signal(signal.SIGTERM, lambda *_: agent.stop())
        agent.run_forever()
    else:
        for target in cfg.targets:
            try:
                agent.scan_target(target)
            except PermissionError as exc:
                print(f"SCOPE BLOCKED {target}: {exc}", file=sys.stderr)
                return 3
            except Exception as exc:
                print(f"error scanning {target}: {exc}", file=sys.stderr)
                return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
