from __future__ import annotations
import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Protocol

import requests

from email_intel.models import GeoResult

logger = logging.getLogger(__name__)

_DEFAULT_CACHE_DIR = Path.home() / ".email-intel"


class GeoProvider(Protocol):
    def lookup(self, ip: str) -> GeoResult | None: ...
    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]: ...


class IpApiProvider:
    BASE_URL = "http://ip-api.com"
    MAX_RETRIES = 3

    def _request_with_retry(self, method: str, url: str, **kwargs) -> requests.Response | None:
        for attempt in range(self.MAX_RETRIES):
            try:
                resp = getattr(requests, method)(url, **kwargs)
                if resp.status_code == 429:
                    wait = 2 ** (attempt + 1)
                    logger.warning("ip-api rate limited, retrying in %ds...", wait)
                    time.sleep(wait)
                    continue
                return resp
            except requests.RequestException as e:
                logger.warning("ip-api request failed (attempt %d): %s", attempt + 1, e)
                if attempt < self.MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
        return None

    def lookup(self, ip: str) -> GeoResult | None:
        resp = self._request_with_retry(
            "get",
            f"{self.BASE_URL}/json/{ip}",
            params={"fields": "status,query,city,regionName,country,countryCode,lat,lon,isp,org"},
            timeout=10,
        )
        if not resp:
            return None
        try:
            data = resp.json()
            if data.get("status") != "success":
                return None
            return self._to_geo(data)
        except ValueError as e:
            logger.warning("ip-api lookup failed for %s: %s", ip, e)
            return None

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        results: dict[str, GeoResult] = {}
        for i in range(0, len(ips), 100):
            chunk = ips[i:i + 100]
            resp = self._request_with_retry(
                "post",
                f"{self.BASE_URL}/batch",
                json=[{"query": ip, "fields": "status,query,city,regionName,country,countryCode,lat,lon,isp,org"} for ip in chunk],
                timeout=30,
            )
            if resp:
                try:
                    for item in resp.json():
                        if item.get("status") == "success":
                            geo = self._to_geo(item)
                            results[geo.ip] = geo
                except ValueError as e:
                    logger.warning("ip-api batch parse failed: %s", e)

            if i + 100 < len(ips):
                time.sleep(4)

        return results

    @staticmethod
    def _to_geo(data: dict) -> GeoResult:
        return GeoResult(
            ip=data["query"],
            city=data.get("city"),
            region=data.get("regionName"),
            country=data.get("countryCode") or data.get("country"),
            lat=data.get("lat"),
            lon=data.get("lon"),
            isp=data.get("isp"),
            org=data.get("org"),
            source="ip-api",
        )


class MaxMindProvider:
    def __init__(self, db_path: str):
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(db_path)
        except ImportError:
            raise ImportError("geoip2 not installed. Install with: pip install email-intel[maxmind]")

    def lookup(self, ip: str) -> GeoResult | None:
        try:
            resp = self._reader.city(ip)
            return GeoResult(
                ip=ip,
                city=resp.city.name,
                region=resp.subdivisions.most_specific.name if resp.subdivisions else None,
                country=resp.country.iso_code,
                lat=resp.location.latitude,
                lon=resp.location.longitude,
                isp=None,
                org=getattr(resp, "autonomous_system_organization", None) if hasattr(resp, "autonomous_system_organization") else None,
                source="maxmind",
            )
        except Exception as e:
            logger.warning("MaxMind lookup failed for %s: %s", ip, e)
            return None

    def lookup_batch(self, ips: list[str]) -> dict[str, GeoResult]:
        results: dict[str, GeoResult] = {}
        for ip in ips:
            geo = self.lookup(ip)
            if geo:
                results[ip] = geo
        return results


class GeoCache:
    def __init__(self, db_path: str | None = None, ttl_days: int = 30):
        self._db_path = db_path or str(_DEFAULT_CACHE_DIR / "geo_cache.db")
        self._ttl_seconds = ttl_days * 86400
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS geo_cache (
                ip TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                cached_at INTEGER NOT NULL
            )
        """)
        conn.commit()
        conn.close()

    def get(self, ip: str) -> GeoResult | None:
        try:
            conn = sqlite3.connect(self._db_path)
            row = conn.execute(
                "SELECT data, cached_at FROM geo_cache WHERE ip = ?", (ip,)
            ).fetchone()
            conn.close()
            if not row:
                return None
            data, cached_at = row
            if time.time() - cached_at > self._ttl_seconds:
                return None
            d = json.loads(data)
            return GeoResult(**d)
        except (sqlite3.Error, json.JSONDecodeError) as e:
            logger.warning("Cache read error: %s", e)
            return None

    def put(self, geo: GeoResult):
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT OR REPLACE INTO geo_cache (ip, data, cached_at) VALUES (?, ?, ?)",
                (geo.ip, json.dumps(geo.__dict__), int(time.time())),
            )
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            logger.warning("Cache write error: %s", e)


def _get_provider(provider_name: str = "ip-api", maxmind_path: str | None = None) -> GeoProvider:
    if provider_name == "maxmind" and maxmind_path:
        return MaxMindProvider(maxmind_path)
    return IpApiProvider()


def resolve_ip(
    ip: str,
    cache: GeoCache | None = None,
    provider: GeoProvider | None = None,
) -> GeoResult | None:
    if cache:
        cached = cache.get(ip)
        if cached:
            return cached
    prov = provider or IpApiProvider()
    result = prov.lookup(ip)
    if result and cache:
        cache.put(result)
    return result


def resolve_ips_batch(
    ips: list[str],
    cache: GeoCache | None = None,
    provider: GeoProvider | None = None,
) -> dict[str, GeoResult]:
    unique_ips = list(set(ips))
    results: dict[str, GeoResult] = {}
    uncached: list[str] = []

    if cache:
        for ip in unique_ips:
            cached = cache.get(ip)
            if cached:
                results[ip] = cached
            else:
                uncached.append(ip)
    else:
        uncached = unique_ips

    if uncached:
        prov = provider or IpApiProvider()
        fetched = prov.lookup_batch(uncached)
        for ip, geo in fetched.items():
            results[ip] = geo
            if cache:
                cache.put(geo)

    return results
