
import pytest

from app.url_analyzer import analyze_url


def test_analyzes_normal_https_url():
    result = analyze_url("https://example.com/login")

    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert result["path"] == "/login"
    assert result["https"] is True
    assert result["host_is_ip"] is False
    assert result["indicators"] == []


def test_detects_ip_address_hostname():
    result = analyze_url("http://192.0.2.1/login")

    assert result["host_is_ip"] is True
    assert "IP address used as hostname" in result["indicators"]


def test_detects_at_character():
    result = analyze_url("https://example.com@evil.test/login")

    assert "URL contains an @ character" in result["indicators"]


def test_rejects_unsupported_scheme():
    with pytest.raises(ValueError):
        analyze_url("ftp://example.com/file")


def test_rejects_missing_hostname():
    with pytest.raises(ValueError):
        analyze_url("https:///login")


def test_rejects_empty_url():
    with pytest.raises(ValueError):
        analyze_url("   ")


def test_rejects_invalid_port():
    with pytest.raises(ValueError):
        analyze_url("https://example.com:abc/")
