from __future__ import annotations
import base64
import json
import logging
import re

logger = logging.getLogger(__name__)


def decode_titus(raw_b64: str) -> dict:
    if not raw_b64:
        return {}
    try:
        decoded = base64.b64decode(raw_b64).decode("utf-8")
        data = json.loads(decoded)
        result: dict = {}
        metadata = data.get("Metadata", {})
        result["namespace"] = metadata.get("ns", "")
        result["id"] = metadata.get("id", "")
        for prop in metadata.get("props", []):
            name = prop.get("n", "")
            vals = prop.get("vals", [])
            if vals:
                result[name] = vals[0].get("value", "")
            else:
                result[name] = ""
        result["tmc_version"] = data.get("TMCVersion", "")
        return result
    except Exception as e:
        logger.warning("Failed to decode Titus metadata: %s", e)
        return {}


def decode_msip(raw: str) -> dict:
    if not raw or not raw.strip():
        return {}
    try:
        result: dict = {}
        label_id = None
        for part in raw.split(";"):
            part = part.strip()
            if not part or "=" not in part:
                continue
            key, value = part.split("=", 1)
            key = key.strip()
            value = value.strip()
            if label_id is None:
                match = re.search(r"MSIP_Label_([a-f0-9\-]+)_", key)
                if match:
                    label_id = match.group(1)
            if key.endswith("_Name"):
                result["label_name"] = value
            elif key.endswith("_Enabled"):
                result["enabled"] = value.lower() == "true"
            elif key.endswith("_Method"):
                result["method"] = value
            elif key.endswith("_SetDate"):
                result["set_date"] = value
        if label_id:
            result["label_id"] = label_id
        return result
    except Exception as e:
        logger.warning("Failed to decode MSIP labels: %s", e)
        return {}


def decode_proofpoint(raw: str) -> dict:
    if not raw:
        return {}
    try:
        match = re.search(r"engine=(.+?)(?:\s+definitions=|\s*$)", raw)
        if not match:
            return {}
        engines_str = match.group(1)
        result: dict = {}
        for part in engines_str.split(","):
            if ":" in part:
                name, version = part.split(":", 1)
                result[name.strip()] = version.strip()
        return result
    except Exception as e:
        logger.warning("Failed to decode Proofpoint version: %s", e)
        return {}


def decode_antispam(antispam_header: str, forefront_header: str) -> dict:
    if not antispam_header and not forefront_header:
        return {}
    result: dict = {}
    try:
        bcl_match = re.search(r"BCL:(\d+)", antispam_header)
        if bcl_match:
            result["BCL"] = int(bcl_match.group(1))
        scl_match = re.search(r"SCL:(\d+)", forefront_header)
        if scl_match:
            result["SCL"] = int(scl_match.group(1))
    except Exception as e:
        logger.warning("Failed to decode antispam: %s", e)
    return result
