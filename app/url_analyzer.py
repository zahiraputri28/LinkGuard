
from urllib.parse import urlsplit
import ipaddress
import re


def analyze_url(url: str) -> dict:
    """Analyze URL structure, not a definitive phishing verdict."""

    url = url.strip()

    if not url or any(ord(c) < 32 or ord(c) == 127 for c in url):
        raise ValueError("URL is empty or contains control characters")

    try:
        parsed = urlsplit(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError("Only HTTP and HTTPS URLs are supported")

        if not parsed.hostname:
            raise ValueError("URL must contain a hostname")

        # Validate port syntax.
        _ = parsed.port
        hostname = parsed.hostname.rstrip(".").lower()

    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid URL") from exc

    try:
        ipaddress.ip_address(hostname)
        host_is_ip = True
    except ValueError:
        host_is_ip = False

    labels = hostname.split(".")
    indicators = []

    if host_is_ip:
        indicators.append("IP address used as hostname")

    if "@" in url:
        indicators.append("URL contains an @ character")

    if len(url) > 100:
        indicators.append("Unusually long URL")

    if len(labels) >= 5:
        indicators.append("Many hostname labels")

    if re.search(r"%[0-9a-fA-F]{2}", url):
        indicators.append("Percent-encoded characters present")

    return {
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "path": parsed.path or "/",
        "https": parsed.scheme.lower() == "https",
        "host_is_ip": host_is_ip,
        "url_length": len(url),
        "indicators": indicators,
        "warning": (
            "Structural indicators only; this does not prove "
            "whether the URL is malicious."
        ),
    }


if __name__ == "__main__":
    sample_url = "https://example.com/login"
    print(analyze_url(sample_url))
