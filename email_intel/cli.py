from __future__ import annotations
import sys
import logging

import click
from rich.console import Console

from email_intel import __version__
from email_intel.config import load_config
from email_intel.parser import parse_headers, is_private_ip
from email_intel.geo import GeoCache, resolve_ip, resolve_ips_batch, IpApiProvider, MaxMindProvider
from email_intel.reporter import (
    render_analysis, render_scan_summary,
    build_scan_summary, export_json, export_csv,
)

console = Console()
logger = logging.getLogger("email_intel")


def _get_provider(cfg):
    if cfg.geo_provider == "maxmind" and cfg.maxmind_db_path:
        return MaxMindProvider(cfg.maxmind_db_path)
    return IpApiProvider()


def _analyze_single(raw_headers: str, cfg, fmt: str, output_path: str | None):
    analysis = parse_headers(raw_headers)

    if analysis.originating_ip and not is_private_ip(analysis.originating_ip):
        cache = GeoCache(db_path=cfg.cache_db_path)
        provider = _get_provider(cfg)
        analysis.geo = resolve_ip(analysis.originating_ip, cache=cache, provider=provider)

    if fmt == "json":
        text = export_json([analysis])
    elif fmt == "csv":
        text = export_csv([analysis])
    else:
        text = render_analysis(analysis)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Output written to {output_path}")
    else:
        click.echo(text)


@click.group()
@click.version_option(version=__version__)
def main():
    """Email Intel — Personal inbox intelligence."""
    pass


@main.command()
@click.option("--file", "file_path", type=click.Path(exists=True), help="Path to .emlx or raw header file")
@click.option("--gmail-id", help="Gmail message ID to analyze")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
@click.option("-o", "--output", "output_path", help="Output file path")
def analyze(file_path, gmail_id, fmt, output_path):
    """Analyze a single email's headers."""
    cfg = load_config()

    if gmail_id:
        try:
            from email_intel.gmail_client import fetch_gmail_headers
            headers_list = fetch_gmail_headers(cfg, message_id=gmail_id)
            if not headers_list:
                console.print("[red]No message found with that ID.[/red]")
                sys.exit(1)
            _analyze_single(headers_list[0], cfg, fmt, output_path)
        except ImportError:
            console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
            sys.exit(1)
        return

    if file_path:
        if file_path.endswith(".emlx"):
            from email_intel.apple_mail import parse_emlx
            raw = parse_emlx(file_path)
            if raw is None:
                console.print(f"[red]Failed to parse {file_path}[/red]")
                sys.exit(1)
        else:
            with open(file_path) as f:
                raw = f.read()
        _analyze_single(raw, cfg, fmt, output_path)
        return

    # stdin / interactive paste
    stdin = click.get_text_stream("stdin")
    if not stdin.isatty():
        raw = stdin.read()
    else:
        console.print("Paste email headers (press Ctrl+D when done):")
        raw = stdin.read()

    if not raw.strip():
        console.print("[red]No headers provided.[/red]")
        sys.exit(1)

    _analyze_single(raw, cfg, fmt, output_path)


@main.command()
@click.option("--source", type=click.Choice(["gmail", "apple-mail"]), required=True)
@click.option("--days", type=int, default=None, help="Scan last N days")
@click.option("--from", "from_filter", help="Filter by sender")
@click.option("--query", help="Search query")
@click.option("--limit", type=int, default=None, help="Max messages (0=unlimited)")
@click.option("--format", "fmt", type=click.Choice(["table", "json", "csv"]), default="table")
@click.option("-o", "--output", "output_path", help="Output file path")
def scan(source, days, from_filter, query, limit, fmt, output_path):
    """Bulk scan inbox for patterns."""
    cfg = load_config()
    days = days or cfg.default_days
    limit = limit if limit is not None else cfg.default_limit

    from rich.progress import Progress

    if source == "gmail":
        try:
            from email_intel.gmail_client import fetch_gmail_headers
            console.print(f"Fetching Gmail messages (last {days} days, limit {limit})...")
            raw_headers_list = fetch_gmail_headers(
                cfg, days=days, from_filter=from_filter, query=query, limit=limit,
            )
        except ImportError:
            console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
            sys.exit(1)
    else:
        from email_intel.apple_mail import find_emlx_files, parse_emlx
        console.print(f"Scanning Apple Mail (last {days} days)...")
        files = find_emlx_files(days=days, from_filter=from_filter, query=query)
        if limit > 0:
            files = files[:limit]
        raw_headers_list = []
        for f in files:
            parsed = parse_emlx(f)
            if parsed:
                raw_headers_list.append(parsed)

    if not raw_headers_list:
        console.print("No messages found.")
        sys.exit(0)

    analyses = []
    with Progress() as progress:
        task = progress.add_task("Parsing headers...", total=len(raw_headers_list))
        for raw in raw_headers_list:
            analyses.append(parse_headers(raw))
            progress.advance(task)

    ips_to_resolve = [
        a.originating_ip for a in analyses
        if a.originating_ip and not is_private_ip(a.originating_ip)
    ]

    if ips_to_resolve:
        cache = GeoCache(db_path=cfg.cache_db_path)
        provider = _get_provider(cfg)
        console.print(f"Resolving {len(set(ips_to_resolve))} unique IPs...")
        geo_map = resolve_ips_batch(ips_to_resolve, cache=cache, provider=provider)
        for a in analyses:
            if a.originating_ip and a.originating_ip in geo_map:
                a.geo = geo_map[a.originating_ip]

    summary = build_scan_summary(analyses)

    if fmt == "json":
        text = export_json(analyses)
    elif fmt == "csv":
        text = export_csv(analyses)
    else:
        text = render_scan_summary(summary)

    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Output written to {output_path}")
    else:
        click.echo(text)


@main.command()
def auth():
    """Authenticate with Gmail (OAuth2)."""
    cfg = load_config()
    try:
        from email_intel.gmail_client import gmail_auth
        if gmail_auth(cfg):
            console.print("[green]✓ Authenticated successfully.[/green]")
        else:
            console.print("[red]✗ Authentication failed.[/red]")
            sys.exit(1)
    except ImportError:
        console.print("[red]Gmail dependencies not installed. Run: pip install email-intel[gmail][/red]")
        sys.exit(1)
