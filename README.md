# Email Intel

![Status](https://img.shields.io/badge/status-active-success)
![Python](https://img.shields.io/badge/Python-3776AB?logo=python&logoColor=white)
![AWS](https://img.shields.io/badge/AWS-232F3E?logo=amazonwebservices&logoColor=white)
![Last Commit](https://img.shields.io/github/last-commit/jtannahill/email-intel)

Email header analysis tool + organizational infrastructure profiler with a web dashboard. Paste raw email headers and get IP geolocation, sending stack fingerprinting, org profiling, and change detection across 147 organizations.

## What It Does

- **Header Analysis**: Parse raw email headers to extract originating IP, relay chain, SPF/DKIM/DMARC status, and sending software
- **IP Geolocation**: Resolve originating IPs via ip-api.com (default) or MaxMind GeoLite2
- **Org Profiling**: Fingerprint sending infrastructure: ESP (Salesforce/HubSpot/Mailchimp/Marketo/etc.), CDN, mail server vendor, authentication posture
- **Change Detection**: Rules-based classifier flags positive, negative, or neutral infrastructure changes when an org's stack changes between scans
- **Plocamium Bridge**: Optional integration to push org signals into the Plocamium content engine pipeline
- **Web Dashboard**: Local HTML dashboard at `localhost:8888` showing 147 profiled orgs, change feed, and scan history

## Architecture

```
CLI (Click + Rich)
    ↓
parser.py      : Raw header → structured EmailAnalysis
geo.py         : IP → GeoResult (ip-api or MaxMind)
org_profiler.py: Domain → OrgStack (ESP, CDN, MX, DMARC)
org_store.py   : SQLite persistence of org profiles + scan history
org_classifier.py: Change classification (positive/negative/neutral)
reporter.py    : Rich terminal output + JSON/CSV export
dashboard.py   : Stdlib HTTP server for the web dashboard
plocamium_bridge.py: Optional signal push to Plocamium
```

## Install

```bash
pipx install email-header-intel            # or: uv tool install email-header-intel
pipx install 'email-header-intel[gmail]'   # with Gmail API support
pipx install 'email-header-intel[maxmind]' # with MaxMind GeoLite2 support
```

The PyPI package is `email-header-intel` (PyPI reserves `email-intel` as
too similar to another project); the command is still `email-intel`.

```bash
```

## Usage

```bash
# Single header analysis
email-intel analyze --headers "$(pbpaste)"

# Scan an org by domain
email-intel scan example.com

# Batch scan from file
email-intel batch orgs.txt

# Start web dashboard
email-intel dashboard --port 8888

# Export results
email-intel analyze --headers "..." --format json --output result.json
```

## Stack

- **Language:** Python 3.12
- **CLI:** Click + Rich (terminal output)
- **Geo:** ip-api.com (free tier) or MaxMind GeoLite2 DB
- **Storage:** SQLite (org profiles, scan history, change log)
- **Dashboard:** Flask + vanilla JS (local only)
- **Tests:** pytest, 105 tests

## Setup

```bash
pip install -e .
cp config.example.yaml config.yaml   # configure geo provider, Plocamium token
email-intel --help
```
