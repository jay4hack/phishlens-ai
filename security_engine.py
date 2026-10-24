"""
PhishLens AI — Security & Threat Analysis Engine
Core functions for URL parsing, deterministic heuristics, validation, and report generation.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

# Standard configuration
MAX_TEXT_LENGTH = 15000  # Characters
MAX_IMAGE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB
ALLOWED_IMAGE_TYPES = {"image/png", "image/jpeg", "image/jpg", "image/webp"}

# Suspicious / throwaway generic top-level domains commonly abused in phishing
SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".buzz", ".work", ".click", ".country", ".gq", ".cf",
    ".tk", ".ml", ".ga", ".fit", ".rest", ".stream", ".icu", ".cam", ".monster", ".link"
}

# High-frequency brand targets for credential harvesting
POPULAR_TARGET_BRANDS = [
    "paypal", "apple", "microsoft", "google", "netflix", "amazon",
    "chase", "wellsfargo", "bankofamerica", "coinbase", "binance",
    "facebook", "instagram", "whatsapp", "dropbox", "dhl", "fedex",
    "usps", "irs", "gov", "outlook", "office365", "steam"
]

# Sensitive action & authentication keywords
CREDENTIAL_KEYWORDS = [
    "login", "signin", "verify", "update-account", "wallet", "banking",
    "secure", "checkpoint", "password", "authenticate", "confirm", "billing", "recovery"
]


def extract_urls(text: Optional[str]) -> List[str]:
    """
    Extracts URLs from arbitrary text input.
    Supports standard web schemes (http, https) and handles punctuation boundary cleanup.
    """
    if not text or not isinstance(text, str):
        return []

    # Regex capturing standard URLs
    url_pattern = re.compile(
        r'https?://(?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9.:_%+-]+(?:/[^\s<>"\'{}|\\^`]*)*',
        re.IGNORECASE
    )
    raw_matches = url_pattern.findall(text)
    
    # Clean trailing punctuation from natural sentence endings (e.g. "http://example.com.")
    cleaned_urls = []
    for u in raw_matches:
        cleaned = re.sub(r'[\.,;:\)\!?]+$', '', u)
        if cleaned and cleaned not in cleaned_urls:
            cleaned_urls.append(cleaned)
            
    return cleaned_urls


def validate_input(text: Optional[str], image_bytes: Optional[bytes] = None, mime_type: Optional[str] = None) -> Dict[str, Any]:
    """
    Validates user text and image inputs against safe size and type boundaries.
    """
    errors = []
    
    # Check text length
    if text and len(text) > MAX_TEXT_LENGTH:
        errors.append(f"Text input exceeds maximum limit of {MAX_TEXT_LENGTH:,} characters (received {len(text):,}).")

    # Check image size & type
    if image_bytes is not None:
        size = len(image_bytes)
        if size > MAX_IMAGE_SIZE_BYTES:
            errors.append(f"Image exceeds the 5MB file-size limit ({size / (1024*1024):.1f}MB).")
        if mime_type and mime_type.lower() not in ALLOWED_IMAGE_TYPES:
            errors.append(f"Unsupported image type '{mime_type}'. Please upload PNG, JPEG, or WEBP.")

    has_content = bool(text and text.strip()) or (image_bytes is not None and len(image_bytes) > 0)
    if not has_content and not errors:
        errors.append("No content provided. Please provide text, a URL, or a screenshot.")

    return {
        "is_valid": len(errors) == 0,
        "errors": errors
    }


def analyze_url_heuristics(url: str) -> Dict[str, Any]:
    """
    Performs deterministic, transparent lexical checks on a URL.
    
    IMPORTANT: This function evaluates URL syntax and lexical lures only.
    It DOES NOT claim a domain is malicious based solely on appearance,
    and it DOES NOT perform active network calls or live web requests.
    """
    findings = []
    is_suspicious = False
    
    if not url or not isinstance(url, str):
        return {
            "url": str(url),
            "is_suspicious": False,
            "findings": ["Empty or invalid URL reference."],
            "components": {}
        }

    try:
        parsed = urlparse(url.strip())
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # 1. Check scheme
        if scheme == "http":
            findings.append("Insecure Protocol: URL uses unencrypted 'http://' rather than 'https://'.")
            is_suspicious = True
        elif scheme not in ("http", "https"):
            findings.append(f"Irregular Scheme: URL specifies unusual protocol '{scheme}://'.")
            is_suspicious = True

        # 2. IP Address host detection (IPv4 / IPv6)
        if hostname:
            try:
                ipaddress.ip_address(hostname)
                findings.append(f"Direct IP Host: Hostname is a raw numeric IP ({hostname}) rather than a registered domain name.")
                is_suspicious = True
            except ValueError:
                pass

        # 3. Misleading subdomain structure & excessive dots
        if hostname:
            dot_count = hostname.count(".")
            if dot_count >= 4:
                findings.append(f"Excessive Subdomains: Hostname contains {dot_count} dots, often used in subdomain stacking to deceive users.")
                is_suspicious = True

        # 4. Authority delimiter spoofing (@ symbol)
        if "@" in netloc:
            findings.append("Deceptive Delimiter: Authority segment contains '@' symbol (often used to obscure the true target destination).")
            is_suspicious = True

        # 5. Suspicious or throwaway generic TLD
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append(f"Suspicious TLD: Domain ends with high-risk TLD '{tld}' commonly observed in transient fraud infrastructure.")
                is_suspicious = True
                break

        # 6. Misleading brand naming / brand in subdomain or path
        for brand in POPULAR_TARGET_BRANDS:
            if brand in hostname:
                parts = hostname.split(".")
                # Extract root domain (e.g., example.com from sub.example.com)
                root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
                if root_domain != f"{brand}.com" and root_domain != f"{brand}.org" and root_domain != f"{brand}.gov":
                    findings.append(f"Brand Keyword in Subdomain: Recognized brand '{brand}' appears in hostname ({hostname}), but is not the root domain.")
                    is_suspicious = True
            elif brand in path or brand in query:
                findings.append(f"Brand Keyword in Path/Query: Recognized brand '{brand}' appears in the URL path or query parameters.")

        # 7. Sensitive credential / action keywords in path or query
        for kw in CREDENTIAL_KEYWORDS:
            if kw in path or kw in query:
                findings.append(f"Authentication Keyword: Sensitive security keyword '{kw}' found in URL path or parameters.")
                break

        # 8. Suspicious port number
        if parsed.port and parsed.port not in (80, 443, 8080):
            findings.append(f"Non-Standard Port: URL connects to unusual destination port {parsed.port}.")
            is_suspicious = True

    except Exception as e:
        findings.append(f"Malformed URL Structure: Could not cleanly parse URL ({str(e)}).")
        is_suspicious = True

    return {
        "url": url,
        "is_suspicious": is_suspicious,
        "findings": findings,
        "components": {
            "scheme": parsed.scheme if 'parsed' in locals() else "",
            "hostname": parsed.hostname if 'parsed' in locals() else "",
            "path": parsed.path if 'parsed' in locals() else "",
            "query": parsed.query if 'parsed' in locals() else ""
        }
    }


def format_text_report(
    timestamp: str,
    model: str,
    risk_level: str,
    summary: str,
    warning_signs: List[str],
    recommended_actions: List[str],
    technical_indicators: List[str],
    url_findings: List[Dict[str, Any]],
    input_preview: str
) -> str:
    """
    Builds a clean, structured plaintext security triage report.
    """
    signs_block = "\n".join(f"- {s}" for s in warning_signs) if warning_signs else "- None detected"
    actions_block = "\n".join(f"- {a}" for a in recommended_actions) if recommended_actions else "- Practice standard cybersecurity hygiene"
    tech_block = "\n".join(f"- {t}" for t in technical_indicators) if technical_indicators else "- None specified"
    
    if url_findings:
        url_lines = []
        for u in url_findings:
            url_lines.append(f"URL: {u.get('url', 'N/A')}")
            findings = u.get("findings", [])
            if findings:
                for f in findings:
                    url_lines.append(f"  * {f}")
            else:
                url_lines.append("  * No obvious suspicious structural indicators flagged")
        urls_block = "\n".join(url_lines)
    else:
        urls_block = "No standalone URLs evaluated."

    return f"""=====================================================
PHISHLENS AI — CYBERSECURITY TRIAGE REPORT
Generated At: {timestamp}
Evaluator Model: {model}
=====================================================

1. RISK ASSESSMENT:
Assessed Threat Level: {risk_level}
Executive Summary:
{summary}

2. EVIDENCE & WARNING SIGNS:
{signs_block}

3. RECOMMENDED DEFENSIVE ACTIONS:
{actions_block}

4. TECHNICAL INDICATORS:
{tech_block}

5. URL ANATOMY & HEURISTIC CHECKS:
{urls_block}

6. INPUT PREVIEW:
{input_preview}

7. LIMITATIONS & TRANSPARENCY NOTICE:
- Advisory Only: This report is a decision-support assessment generated via probabilistic AI pattern evaluation and deterministic heuristics. It does NOT guarantee that an evaluated message is 100% benign or malicious.
- No Live Reputation Lookups: URL checks inspect lexical syntax and formatting patterns without visiting the URL, conducting DNS lookups, or executing active sandboxing.
- Defense in Depth: Never rely on a single automated indicator. Confirm unexpected communications directly through verified, out-of-band channels.
=====================================================
"""
