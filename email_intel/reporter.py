from __future__ import annotations
import csv
import io
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from email_intel.models import EmailAnalysis, ScanSummary


def render_analysis(analysis: EmailAnalysis) -> str:
    console = Console(file=io.StringIO(), force_terminal=True, width=80)

    console.print(Panel.fit(
        f"[bold]From:[/bold] {analysis.from_addr or 'Unknown'}\n"
        f"[bold]To:[/bold] {analysis.to_addr or 'Unknown'}\n"
        f"[bold]Subject:[/bold] {analysis.subject or '(none)'}\n"
        f"[bold]Date:[/bold] {analysis.date or 'Unknown'} "
        f"UTC{analysis.timezone_offset or '?'}"
        f"{f' ({analysis.timezone_name})' if analysis.timezone_name else ''}",
        title="Email Analysis",
    ))

    if analysis.originating_ip:
        geo = analysis.geo
        origin_text = f"[bold]IP:[/bold] {analysis.originating_ip}"
        if geo:
            origin_text += f" → {geo.city or '?'}, {geo.region or '?'}, {geo.country or '?'}"
            if geo.isp:
                origin_text += f" ({geo.isp})"
        origin_text += f"\n[bold]Client:[/bold] {analysis.mail_client or 'Unknown'}"
        console.print(Panel.fit(origin_text, title="Origin"))

    def _auth_icon(val: str | None) -> str:
        if val == "pass":
            return "✓"
        elif val in ("fail", "softfail"):
            return "✗"
        return "?"

    auth = analysis.auth
    console.print(Panel.fit(
        f"SPF {_auth_icon(auth.spf)} {auth.spf or 'none'}  "
        f"DKIM {_auth_icon(auth.dkim)} {auth.dkim or 'none'}  "
        f"DMARC {_auth_icon(auth.dmarc)} {auth.dmarc or 'none'}",
        title="Auth",
    ))

    if analysis.hops:
        table = Table(title=f"Server Hops ({len(analysis.hops)})")
        table.add_column("#", style="dim", width=3)
        table.add_column("Server")
        table.add_column("IP")
        table.add_column("Protocol")
        table.add_column("Latency")

        for i, hop in enumerate(analysis.hops, 1):
            latency = f"{hop.latency_ms:.0f}ms" if hop.latency_ms is not None else "-"
            table.add_row(
                str(i), hop.server, hop.ip or "-",
                hop.protocol or "-", latency,
            )
        console.print(table)

    if analysis.flags:
        flags_text = "\n".join(f"⚠ {f}" for f in analysis.flags)
        console.print(Panel.fit(flags_text, title="Flags", border_style="yellow"))

    output = console.file.getvalue()
    return output


def render_scan_summary(summary: ScanSummary) -> str:
    console = Console(file=io.StringIO(), force_terminal=True, width=100)

    console.print(f"\n[bold]Scanned {summary.total_messages} messages[/bold]")

    if summary.top_locations:
        table = Table(title="Top Sender Locations")
        table.add_column("Location")
        table.add_column("Count", justify="right")
        for loc, count in summary.top_locations[:10]:
            table.add_row(loc, str(count))
        console.print(table)

    if summary.timezone_distribution:
        table = Table(title="Timezone Distribution")
        table.add_column("Timezone")
        table.add_column("Count", justify="right")
        for tz, count in sorted(summary.timezone_distribution.items(), key=lambda x: -x[1]):
            table.add_row(tz, str(count))
        console.print(table)

    if summary.client_breakdown:
        table = Table(title="Mail Clients")
        table.add_column("Client")
        table.add_column("Count", justify="right")
        for client, count in sorted(summary.client_breakdown.items(), key=lambda x: -x[1]):
            table.add_row(client, str(count))
        console.print(table)

    if summary.flagged_messages:
        console.print(f"\n[yellow bold]⚠ {len(summary.flagged_messages)} flagged messages:[/yellow bold]")
        for msg in summary.flagged_messages[:20]:
            flags = ", ".join(msg.flags)
            console.print(f"  • {msg.from_addr or '?'} — {msg.subject or '(no subject)'} [{flags}]")

    return console.file.getvalue()


def build_scan_summary(emails: list[EmailAnalysis]) -> ScanSummary:
    if not emails:
        now = datetime.now(tz=timezone.utc)
        return ScanSummary(total_messages=0, date_range=(now, now))

    # Normalize all dates to aware (UTC) to avoid naive/aware comparison errors
    aware_dates = []
    for e in emails:
        if e.date:
            if e.date.tzinfo is None:
                aware_dates.append(e.date.replace(tzinfo=timezone.utc))
            else:
                aware_dates.append(e.date)
    date_range = (min(aware_dates), max(aware_dates)) if aware_dates else (
        datetime.now(tz=timezone.utc), datetime.now(tz=timezone.utc)
    )

    loc_counter: Counter[str] = Counter()
    for e in emails:
        if e.geo and e.geo.city and e.geo.country:
            loc_counter[f"{e.geo.city}, {e.geo.country}"] += 1

    tz_counter: Counter[str] = Counter()
    for e in emails:
        tz_label = e.timezone_name or e.timezone_offset
        if tz_label:
            tz_counter[tz_label] += 1

    client_counter: Counter[str] = Counter()
    for e in emails:
        if e.mail_client:
            client_counter[e.mail_client] += 1

    flagged = [e for e in emails if e.flags]

    return ScanSummary(
        total_messages=len(emails),
        date_range=date_range,
        top_locations=loc_counter.most_common(20),
        timezone_distribution=dict(tz_counter),
        client_breakdown=dict(client_counter),
        flagged_messages=flagged,
        emails=emails,
    )


def _analysis_to_flat(a: EmailAnalysis) -> dict:
    return {
        "message_id": a.message_id,
        "from_addr": a.from_addr,
        "to_addr": a.to_addr,
        "subject": a.subject,
        "date": a.date.isoformat() if a.date else None,
        "timezone_offset": a.timezone_offset,
        "timezone_name": a.timezone_name,
        "mail_client": a.mail_client,
        "originating_ip": a.originating_ip,
        "geo_city": a.geo.city if a.geo else None,
        "geo_region": a.geo.region if a.geo else None,
        "geo_country": a.geo.country if a.geo else None,
        "geo_lat": a.geo.lat if a.geo else None,
        "geo_lon": a.geo.lon if a.geo else None,
        "geo_isp": a.geo.isp if a.geo else None,
        "geo_org": a.geo.org if a.geo else None,
        "spf": a.auth.spf,
        "dkim": a.auth.dkim,
        "dmarc": a.auth.dmarc,
        "reply_to_mismatch": a.reply_to_mismatch,
        "is_bulk": a.is_bulk,
        "hop_count": len(a.hops),
        "flags": "; ".join(a.flags) if a.flags else "",
    }


def export_json(emails: list[EmailAnalysis]) -> str:
    return json.dumps([_analysis_to_flat(e) for e in emails], indent=2)


def export_csv(emails: list[EmailAnalysis]) -> str:
    if not emails:
        return ""
    rows = [_analysis_to_flat(e) for e in emails]
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()
