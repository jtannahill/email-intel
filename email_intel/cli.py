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
from email_intel.org_profiler import extract_stack, extract_domain
from email_intel.org_store import OrgStore
from email_intel.org_classifier import classify_change as classify_org_change
from email_intel.plocamium_bridge import PlocamiumBridge

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
@click.option("--profile/--no-profile", default=True, help="Enable org profiling")
def scan(source, days, from_filter, query, limit, fmt, output_path, profile):
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

    # Org profiling
    if profile and cfg.orgs_enabled:
        store = OrgStore(db_path=cfg.orgs_db_path)
        bridge = PlocamiumBridge(
            enabled=cfg.plocamium_enabled, output=cfg.plocamium_output,
            local_path=cfg.plocamium_local_path, s3_bucket=cfg.plocamium_s3_bucket,
            s3_prefix=cfg.plocamium_s3_prefix, s3_profile=cfg.plocamium_s3_profile)

        for i, a in enumerate(analyses):
            domain = extract_domain(a.from_addr)
            if not domain:
                continue
            raw = raw_headers_list[i] if i < len(raw_headers_list) else None
            if not raw:
                continue
            try:
                stack = extract_stack(raw, a)
                org_changes = store.upsert(domain, stack)
                for ch in org_changes:
                    cls = classify_org_change(ch)
                    store.classify_change(ch.id, cls.signal, cls.confidence, cls.reasoning, cls.category)
                    entity = store.resolve_entity(domain)
                    name = entity.entity_name if entity else domain
                    icon = "⚠" if cls.signal != "neutral" else "✓"
                    color = {"positive": "green", "negative": "red", "neutral": "dim"}.get(cls.signal, "")
                    console.print(f"[{color}]{icon} {name} ({domain}): {cls.reasoning} [{cls.signal}/{cls.category}][/{color}]")

                    if cfg.plocamium_enabled:
                        from email_intel.models import OrgInfraSignal
                        bridge.buffer(OrgInfraSignal(
                            signal_id=ch.id, domain=domain,
                            entity_id=entity.entity_id if entity else None,
                            entity_name=entity.entity_name if entity else domain,
                            sector=entity.sector if entity else None,
                            change=ch, classification=cls, timestamp=ch.timestamp))
            except Exception as e:
                logger.warning("Org profiling failed for %s: %s", domain, e)

        bridge.flush()

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


@main.group(invoke_without_command=True)
@click.pass_context
def orgs(ctx):
    """Org infrastructure profiles."""
    if ctx.invoked_subcommand is None:
        cfg = load_config()
        store = OrgStore(db_path=cfg.orgs_db_path)
        profiles = store.list_profiles()
        if not profiles:
            console.print("No org profiles yet. Run a scan to start profiling.")
            return
        from rich.table import Table
        table = Table(title=f"Org Profiles ({len(profiles)})")
        table.add_column("Domain")
        table.add_column("Name")
        table.add_column("Platform")
        table.add_column("Security")
        table.add_column("DMARC")
        table.add_column("Emails", justify="right")
        table.add_column("Last Seen")
        for p in profiles:
            s = p.current_stack
            table.add_row(p.domain, p.display_name or p.domain, s.email_platform or "?",
                s.security_gateway or "-", s.dmarc_policy or "?",
                str(p.email_count), p.last_seen.strftime("%Y-%m-%d"))
        console.print(table)


@orgs.command("show")
@click.argument("domain")
def orgs_show(domain):
    """Show detailed profile for a specific org."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    profile = store.get_profile(domain)
    entity = store.resolve_entity(domain)

    if not profile and not entity:
        console.print(f"No profile or entity mapping found for {domain}")
        return

    if entity:
        console.print(f"[bold]{entity.entity_name}[/bold] ({domain})")
        if entity.sector:
            console.print(f"Sector: {entity.sector}")
        console.print(f"Source: {entity.source}")
        console.print()

    if profile:
        s = profile.current_stack
        from rich.table import Table
        table = Table(title="Infrastructure Stack")
        table.add_column("Field")
        table.add_column("Value")
        table.add_row("MTA", f"{s.mta_vendor or '?'} {s.mta_version or ''}")
        table.add_row("Platform", s.email_platform or "?")
        table.add_row("Security Gateway", f"{s.security_gateway or '-'} {s.security_gateway_version or ''}")
        table.add_row("TLS", f"{s.tls_version or '?'} / {s.tls_cipher or '?'}")
        table.add_row("DMARC", s.dmarc_policy or "?")
        table.add_row("DLP", s.dlp_system or "-")
        table.add_row("Tenant ID", s.tenant_id or "-")
        table.add_row("DKIM Domains", ", ".join(s.dkim_domains) if s.dkim_domains else "-")
        console.print(table)
        console.print(f"\nEmails observed: {profile.email_count}")
        console.print(f"First seen: {profile.first_seen.strftime('%Y-%m-%d')}")
        console.print(f"Last seen: {profile.last_seen.strftime('%Y-%m-%d')}")

        changes = store.get_changes(domain=domain)
        if changes:
            console.print(f"\n[bold]Recent Changes ({len(changes)}):[/bold]")
            for c in changes[:10]:
                console.print(f"  {c.timestamp.strftime('%Y-%m-%d')} {c.field}: {c.old_value} → {c.new_value}")
    else:
        console.print("Entity mapped but no email profile yet. Run a scan to populate.")


@orgs.command("map")
@click.argument("domain")
@click.argument("name")
@click.option("--sector", help="Industry sector")
@click.option("--entity-id", help="Plocamium entity ID")
def orgs_map(domain, name, sector, entity_id):
    """Map a domain to an organization name."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    store.set_entity_mapping(domain, name, entity_id=entity_id, sector=sector, source="manual")
    console.print(f"Mapped {domain} → {name}")


@orgs.command("export")
@click.option("--format", "fmt", type=click.Choice(["json", "csv"]), default="json")
@click.option("-o", "--output", "output_path", help="Output file path")
def orgs_export(fmt, output_path):
    """Export all org profiles."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    profiles = store.list_profiles()
    import json as json_mod
    rows = []
    for p in profiles:
        s = p.current_stack
        rows.append({"domain": p.domain, "name": p.display_name,
            "entity_id": p.entity_id, "sector": p.sector,
            "platform": s.email_platform, "mta": s.mta_vendor,
            "security_gateway": s.security_gateway,
            "dmarc": s.dmarc_policy, "tls": s.tls_version,
            "dlp": s.dlp_system, "emails": p.email_count,
            "first_seen": p.first_seen.isoformat(), "last_seen": p.last_seen.isoformat()})
    if fmt == "json":
        text = json_mod.dumps(rows, indent=2)
    else:
        import csv, io
        output = io.StringIO()
        if rows:
            writer = csv.DictWriter(output, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        text = output.getvalue()
    if output_path:
        with open(output_path, "w") as f:
            f.write(text)
        console.print(f"Exported {len(profiles)} profiles to {output_path}")
    else:
        click.echo(text)


@main.command()
@click.option("--days", type=int, default=None, help="Filter to last N days")
@click.option("--signal", type=click.Choice(["positive", "negative", "neutral"]), help="Filter by signal")
@click.option("--domain", help="Filter by domain")
def changes(days, signal, domain):
    """Show recent org infrastructure changes."""
    cfg = load_config()
    store = OrgStore(db_path=cfg.orgs_db_path)
    change_list = store.get_changes(domain=domain, days=days, signal=signal)
    if not change_list:
        console.print("No changes found.")
        return
    from rich.table import Table
    table = Table(title=f"Infrastructure Changes ({len(change_list)})")
    table.add_column("Date")
    table.add_column("Domain")
    table.add_column("Field")
    table.add_column("Old")
    table.add_column("New")
    for c in change_list[:50]:
        table.add_row(c.timestamp.strftime("%Y-%m-%d"), c.domain, c.field,
            c.old_value or "-", c.new_value or "-")
    console.print(table)
