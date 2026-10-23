
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


def calculate_risk(analysis: dict) -> dict:
    """Calculate an illustrative risk score from URL indicators."""

    score = 0
    reasons = []

    if analysis["host_is_ip"]:
        score += 40
        reasons.append("Hostname is an IP address (+40)")

    if not analysis["https"]:
        score += 20
        reasons.append("URL does not use HTTPS (+20)")

    if analysis["url_length"] > 100:
        score += 10
        reasons.append("URL is unusually long (+10)")

    if "URL contains an @ character" in analysis["indicators"]:
        score += 20
        reasons.append("URL contains an @ character (+20)")


    score = min(score, 100)

    if score >= 60:
        level = "high"
    elif score >= 30:
        level = "medium"
    else:
        level = "low"

    return {
        "score": score,
        "level": level,
        "reasons": reasons,
        "warning": (
            "This score is based on simple structural rules. "
            "It does not prove whether a URL is malicious."
        ),
    }


if __name__ == "__main__":
    print("=== LinkGuard URL Analyzer ===")
    print("Enter a URL to analyze. Type 'exit' to quit.")

    while True:
        sample_url = input("\nURL: ").strip()

        if sample_url.lower() == "exit":
            print("LinkGuard closed.")
            break

        try:
            analysis = analyze_url(sample_url)
            risk = calculate_risk(analysis)

            print("\n=== Analysis Result ===")
            print(f"Hostname: {analysis['hostname']}")
            print(f"HTTPS: {analysis['https']}")
            print(f"Risk score: {risk['score']}/100")
            print(f"Risk level: {risk['level'].upper()}")

            print("Indicators:")
            if analysis["indicators"]:
                for indicator in analysis["indicators"]:
                    print(f"- {indicator}")
            else:
                print("- No structural indicators detected.")

            print("Reasons:")
            if risk["reasons"]:
                for reason in risk["reasons"]:
                    print(f"- {reason}")
            else:
                print("- No risk rules matched.")

            print(f"Warning: {risk['warning']}")

        except ValueError as exc:
            print(f"Invalid URL: {exc}")


