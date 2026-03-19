from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from email_intel.models import OrgInfraSignal

logger = logging.getLogger(__name__)

_DEFAULT_LOCAL_PATH = Path.home() / ".email-intel" / "signals.jsonl"


class PlocamiumBridge:
    def __init__(self, enabled: bool = False, output: str = "local",
                 local_path: str | None = None, s3_bucket: str | None = None,
                 s3_prefix: str = "email-intel/", s3_profile: str | None = None):
        self._enabled = enabled
        self._output = output
        self._local_path = local_path or str(_DEFAULT_LOCAL_PATH)
        self._s3_bucket = s3_bucket
        self._s3_prefix = s3_prefix
        self._s3_profile = s3_profile
        self._buffer: list[OrgInfraSignal] = []

    @property
    def pending_count(self) -> int:
        return len(self._buffer)

    def buffer(self, signal: OrgInfraSignal):
        if not self._enabled:
            return
        self._buffer.append(signal)

    def flush(self):
        if not self._enabled or not self._buffer:
            return
        if self._output == "local":
            self._flush_local()
        elif self._output == "s3":
            self._flush_s3()
        self._buffer.clear()

    def _signal_to_dict(self, signal: OrgInfraSignal) -> dict:
        return {
            "signal_id": signal.signal_id,
            "domain": signal.domain,
            "entity_id": signal.entity_id,
            "entity_name": signal.entity_name,
            "sector": signal.sector,
            "field": signal.change.field,
            "old_value": signal.change.old_value,
            "new_value": signal.change.new_value,
            "signal": signal.classification.signal,
            "confidence": signal.classification.confidence,
            "reasoning": signal.classification.reasoning,
            "category": signal.classification.category,
            "timestamp": signal.timestamp.isoformat(),
        }

    def _flush_local(self):
        try:
            path = Path(self._local_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a") as f:
                for signal in self._buffer:
                    f.write(json.dumps(self._signal_to_dict(signal)) + "\n")
            logger.info("Wrote %d signals to %s", len(self._buffer), self._local_path)
        except Exception as e:
            logger.error("Failed to write signals locally: %s", e)

    def _flush_s3(self):
        try:
            import boto3
            session_kwargs = {}
            if self._s3_profile:
                session_kwargs["profile_name"] = self._s3_profile
            session = boto3.Session(**session_kwargs)
            s3 = session.client("s3")
            body = "\n".join(json.dumps(self._signal_to_dict(s)) for s in self._buffer) + "\n"
            key = f"{self._s3_prefix}signals-{datetime.now(tz=timezone.utc).strftime('%Y%m%d-%H%M%S')}.jsonl"
            s3.put_object(Bucket=self._s3_bucket, Key=key, Body=body.encode())
            logger.info("Wrote %d signals to s3://%s/%s", len(self._buffer), self._s3_bucket, key)
        except Exception as e:
            logger.error("Failed to write signals to S3: %s", e)
