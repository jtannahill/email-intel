from __future__ import annotations
import base64
import logging
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from email_intel.config import Config

logger = logging.getLogger(__name__)

MAX_RETRIES = 3


def _get_gmail_service(config: Config):
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    token_path = Path(config.gmail_token_path)
    creds_path = Path(config.gmail_credentials_path)
    scopes = ["https://www.googleapis.com/auth/gmail.readonly"]

    creds = None
    if token_path.exists():
        creds = Credentials.from_authorized_user_file(str(token_path), scopes)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not creds_path.exists():
                raise FileNotFoundError(
                    f"Gmail credentials not found at {creds_path}. "
                    "Download from Google Cloud Console and place at "
                    "~/.email-intel/credentials.json"
                )
            flow = InstalledAppFlow.from_client_secrets_file(
                str(creds_path), scopes
            )
            creds = flow.run_local_server(port=8080)

        token_path.parent.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json())

    return build("gmail", "v1", credentials=creds)


def _execute_with_retry(request):
    """Execute a Google API request with exponential backoff on 429."""
    from googleapiclient.errors import HttpError
    for attempt in range(MAX_RETRIES):
        try:
            return request.execute()
        except HttpError as e:
            if e.resp.status == 429 and attempt < MAX_RETRIES - 1:
                wait = 2 ** (attempt + 1)
                logger.warning("Gmail API rate limited, retrying in %ds...", wait)
                time.sleep(wait)
            else:
                raise


def _headers_from_metadata(payload: dict) -> str:
    """Reconstruct raw headers string from Gmail metadata payload."""
    headers = payload.get("headers", [])
    return "\n".join(f"{h['name']}: {h['value']}" for h in headers)


def gmail_auth(config: Config) -> bool:
    try:
        service = _get_gmail_service(config)
        profile = service.users().getProfile(userId="me").execute()
        logger.info("Authenticated as %s", profile.get("emailAddress"))
        return True
    except Exception as e:
        logger.error("Gmail authentication failed: %s", e)
        return False


def fetch_gmail_headers(
    config: Config,
    message_id: str | None = None,
    days: int | None = None,
    from_filter: str | None = None,
    query: str | None = None,
    limit: int = 500,
) -> list[str]:
    service = _get_gmail_service(config)

    if message_id:
        msg = _execute_with_retry(
            service.users().messages().get(
                userId="me", id=message_id, format="raw"
            )
        )
        raw = base64.urlsafe_b64decode(msg["raw"]).decode("utf-8", errors="replace")
        header_end = raw.find("\r\n\r\n")
        if header_end < 0:
            header_end = raw.find("\n\n")
        return [raw[:header_end] if header_end > 0 else raw]

    parts: list[str] = []
    if days:
        after_date = (datetime.now(tz=timezone.utc) - timedelta(days=days)).strftime("%Y/%m/%d")
        parts.append(f"after:{after_date}")
    if from_filter:
        parts.append(f"from:{from_filter}")
    if query:
        parts.append(query)

    search_query = " ".join(parts) if parts else "in:inbox"

    all_ids: list[str] = []
    page_token = None
    fetch_limit = limit if limit > 0 else 10000

    while len(all_ids) < fetch_limit:
        batch_size = min(100, fetch_limit - len(all_ids))
        result = _execute_with_retry(
            service.users().messages().list(
                userId="me", q=search_query,
                maxResults=batch_size, pageToken=page_token,
            )
        )

        messages = result.get("messages", [])
        all_ids.extend(m["id"] for m in messages)

        page_token = result.get("nextPageToken")
        if not page_token:
            break

    headers_list: list[str] = []
    for msg_id in all_ids:
        try:
            msg = _execute_with_retry(
                service.users().messages().get(
                    userId="me", id=msg_id, format="metadata",
                    metadataHeaders=["From", "To", "Subject", "Date", "Message-ID",
                                     "Received", "Authentication-Results", "X-Mailer",
                                     "User-Agent", "Reply-To", "X-Originating-IP",
                                     "List-Unsubscribe", "X-Campaign-ID", "Precedence",
                                     "Delivered-To", "Content-Type"],
                )
            )
            headers_str = _headers_from_metadata(msg.get("payload", {}))
            if headers_str:
                headers_list.append(headers_str)
        except Exception as e:
            logger.warning("Failed to fetch message %s: %s", msg_id, e)

    return headers_list
