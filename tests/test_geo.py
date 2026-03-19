import sqlite3
import time
from unittest.mock import patch, MagicMock
from email_intel.geo import (
    IpApiProvider,
    MaxMindProvider,
    GeoCache,
    resolve_ip,
    resolve_ips_batch,
)
from email_intel.models import GeoResult


def test_ip_api_single(tmp_path):
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "status": "success", "query": "74.125.82.42",
        "city": "Mountain View", "regionName": "California",
        "country": "United States", "countryCode": "US",
        "lat": 37.386, "lon": -122.084,
        "isp": "Google LLC", "org": "Google LLC",
    }
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.get", return_value=mock_response):
        provider = IpApiProvider()
        result = provider.lookup("74.125.82.42")
        assert result.city == "Mountain View"
        assert result.source == "ip-api"


def test_ip_api_batch(tmp_path):
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {"status": "success", "query": "74.125.82.42",
         "city": "Mountain View", "regionName": "California",
         "country": "United States", "countryCode": "US",
         "lat": 37.386, "lon": -122.084, "isp": "Google", "org": "Google"},
        {"status": "success", "query": "203.0.113.45",
         "city": "London", "regionName": "England",
         "country": "United Kingdom", "countryCode": "GB",
         "lat": 51.509, "lon": -0.118, "isp": "Example ISP", "org": "Example"},
    ]
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.post", return_value=mock_response):
        provider = IpApiProvider()
        results = provider.lookup_batch(["74.125.82.42", "203.0.113.45"])
        assert len(results) == 2
        assert results["74.125.82.42"].city == "Mountain View"
        assert results["203.0.113.45"].city == "London"


def test_geo_cache_hit(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    geo = GeoResult(
        ip="1.2.3.4", city="Test", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)
    result = cache.get("1.2.3.4")
    assert result is not None
    assert result.city == "Test"


def test_geo_cache_miss(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    result = cache.get("9.9.9.9")
    assert result is None


def test_geo_cache_expired(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"), ttl_days=1)
    geo = GeoResult(
        ip="1.2.3.4", city="Old", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)
    conn = sqlite3.connect(str(tmp_path / "test_cache.db"))
    conn.execute("UPDATE geo_cache SET cached_at = cached_at - 86401")
    conn.commit()
    conn.close()
    result = cache.get("1.2.3.4")
    assert result is None


def test_resolve_ip_uses_cache(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    geo = GeoResult(
        ip="1.2.3.4", city="Cached", region="R", country="US",
        lat=0.0, lon=0.0, isp="ISP", org="Org", source="ip-api",
    )
    cache.put(geo)
    result = resolve_ip("1.2.3.4", cache=cache)
    assert result.city == "Cached"


def test_resolve_ips_batch_deduplicates(tmp_path):
    cache = GeoCache(db_path=str(tmp_path / "test_cache.db"))
    mock_response = MagicMock()
    mock_response.json.return_value = [{
        "status": "success", "query": "1.2.3.4",
        "city": "Test", "regionName": "R",
        "country": "US", "countryCode": "US",
        "lat": 0.0, "lon": 0.0, "isp": "ISP", "org": "Org",
    }]
    mock_response.status_code = 200

    with patch("email_intel.geo.requests.post", return_value=mock_response):
        results = resolve_ips_batch(
            ["1.2.3.4", "1.2.3.4", "1.2.3.4"],
            cache=cache,
        )
    assert len(results) == 1
    assert results["1.2.3.4"].city == "Test"
