"""Conservative, non-destructive checks for explicitly authorized web targets."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urldefrag, urljoin, urlsplit, urlunsplit

import requests

USER_AGENT = "WAPT-LabScanner/1.0 (+authorized defensive assessment)"
MAX_REDIRECTS = 4
REQUEST_TIMEOUT = (4, 7)
MAX_PAGE_BYTES = 256_000
MAX_CRAWL_PAGES = 8
MAX_CRAWL_DEPTH = 1


class ScanError(Exception):
    """Raised when a target cannot be safely or reliably scanned."""


@dataclass
class ResponseSnapshot:
    url: str
    status_code: int
    headers: dict[str, str]
    cookies: list[str]
    body: bytes
    elapsed_ms: int


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.mixed_content: list[str] = []
        self.forms: list[dict[str, object]] = []
        self.links: list[str] = []
        self.meta: list[dict[str, str]] = []
        self.scripts: list[str] = []
        self.api_references: list[str] = []
        self.title = ""
        self._in_title = False
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "meta":
            self.meta.append({key: value for key, value in values.items() if key in {"name", "property", "content"}})
        if tag.lower() == "script":
            src = values.get("src", "").strip()
            if src:
                self.scripts.append(src)
        for attr in ("src", "href", "action", "poster"):
            value = values.get(attr, "").strip()
            if value.lower().startswith("http://"):
                self.mixed_content.append(value)
            if attr in {"href", "src"} and value:
                self.links.append(value)
        if tag.lower() == "title":
            self._in_title = True
        if tag.lower() == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(), "has_password": False}
            self.forms.append(self._form)
        elif tag.lower() == "input" and self._form is not None:
            if values.get("type", "").lower() == "password":
                self._form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False
        if tag.lower() == "form":
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data


def _resolve_addresses(hostname: str) -> set[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScanError(f"DNS lookup failed for {hostname}: {exc}") from exc
    addresses = {ipaddress.ip_address(record[4][0].split("%", 1)[0]) for record in records}
    if not addresses:
        raise ScanError(f"No IP addresses were returned for {hostname}.")
    return addresses


def validate_target(url: str) -> str:
    """Normalize a URL and block private, link-local, and metadata destinations.

    Loopback is allowed for local lab targets (localhost/127.0.0.1/::1).
    Non-loopback targets are limited to standard HTTP/HTTPS ports.
    """
    if not isinstance(url, str) or len(url) > 2048:
        raise ScanError("Enter a valid URL under 2,048 characters.")
    raw = url.strip()
    if not raw:
        raise ScanError("Target URL is required.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError as exc:
        raise ScanError("The target URL or port is malformed.") from exc

    scheme = parts.scheme.lower()
    hostname = (parts.hostname or "").rstrip(".").lower()
    if scheme not in {"http", "https"}:
        raise ScanError("Only HTTP and HTTPS targets are supported.")
    if not hostname or parts.username or parts.password:
        raise ScanError("Enter a URL with a hostname. Embedded credentials are not allowed.")
    if any(ch.isspace() for ch in hostname):
        raise ScanError("The hostname contains invalid whitespace.")

    default_port = 443 if scheme == "https" else 80
    effective_port = port or default_port
    try:
        ip = ipaddress.ip_address(hostname)
        addresses = {ip}
    except ValueError:
        addresses = _resolve_addresses(hostname)

    is_loopback_name = hostname == "localhost" or hostname.endswith(".localhost")
    all_loopback = all(address.is_loopback for address in addresses)
    if is_loopback_name and not all_loopback:
        raise ScanError("The localhost name resolved to a non-loopback address; target blocked.")

    for address in addresses:
        if address.is_loopback:
            continue
        if not address.is_global:
            raise ScanError(f"Target resolves to a non-public IP address ({address}); private/internal targets are blocked.")

    if not all_loopback and effective_port not in {80, 443}:
        raise ScanError("For public targets, only ports 80 and 443 are allowed. Localhost lab ports are supported.")
    if all_loopback and not (1 <= effective_port <= 65535):
        raise ScanError("Invalid localhost port.")

    netloc = hostname
    if ":" in hostname and not hostname.startswith("["):
        netloc = f"[{hostname}]"
    if port and port != default_port:
        netloc = f"{netloc}:{port}"
    path = parts.path or "/"
    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _snapshot_request(session: requests.Session, url: str, max_bytes: int = MAX_PAGE_BYTES) -> ResponseSnapshot:
    current = validate_target(url)
    started = time.monotonic()
    for hop in range(MAX_REDIRECTS + 1):
        # Revalidate every redirect destination before making another request.
        current = validate_target(current)
        try:
            response = session.get(
                current,
                allow_redirects=False,
                stream=True,
                timeout=REQUEST_TIMEOUT,
                verify=True,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
            )
        except requests.exceptions.SSLError as exc:
            raise ScanError(f"TLS certificate verification failed: {exc}") from exc
        except requests.RequestException as exc:
            raise ScanError(f"Could not fetch the target: {exc}") from exc

        if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("Location"):
            location = urljoin(current, response.headers["Location"])
            response.close()
            if hop >= MAX_REDIRECTS:
                raise ScanError("The target exceeded the maximum of four redirects.")
            current = validate_target(location)
            continue

        body = bytearray()
        try:
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                remaining = max_bytes - len(body)
                body.extend(chunk[:remaining])
                if len(body) >= max_bytes:
                    break
        finally:
            try:
                raw_headers = response.raw.headers
                cookie_values = raw_headers.getlist("Set-Cookie") if hasattr(raw_headers, "getlist") else []
            except Exception:
                cookie_values = []
            snapshot = ResponseSnapshot(
                url=current,
                status_code=response.status_code,
                headers={str(k): str(v) for k, v in response.headers.items()},
                cookies=[str(v) for v in cookie_values],
                body=bytes(body),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
            response.close()
        return snapshot
    raise ScanError("Could not follow the target redirect chain safely.")


def _finding(title: str, category: str, severity: str, description: str, evidence: str,
             recommendation: str, cwe: str = "", *, affected_url: str = "",
             confidence: str = "confirmed", observation_type: str = "confirmed_vulnerability",
             impact: str = "", verification: str = "", detection_method: str = "") -> dict[str, str]:
    finding = {
        "title": title,
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence[:500],
        "recommendation": recommendation,
        "cwe": cwe,
        "affected_url": affected_url,
        "confidence": confidence,
        "observation_type": observation_type,
        "impact": impact or description,
        "verification": verification or "Compare the response and configuration again after the remediation.",
        "detection_method": detection_method or "HTTP response inspection",
        "detected_at": datetime.now(timezone.utc).isoformat(),
    }
    fingerprint_source = f"{category}|{title}|{affected_url}|{evidence[:240]}"
    import hashlib
    finding["fingerprint"] = hashlib.sha256(fingerprint_source.encode("utf-8")).hexdigest()[:16]
    return finding


def check_tls(hostname: str, port: int) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=hostname) as tls_socket:
                cert = tls_socket.getpeercert()
                cipher = tls_socket.cipher()
        expiry_value = cert.get("notAfter")
        if expiry_value:
            expires = datetime.strptime(expiry_value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding(
                    "TLS certificate has expired", "Transport Security", "high",
                    "The server presented a certificate whose validity period has ended.",
                    f"Certificate expired on {expires.isoformat()}.",
                    "Renew the certificate and confirm the full certificate chain is installed.", "CWE-295"))
            elif days_left <= 14:
                findings.append(_finding(
                    "TLS certificate expires soon", "Transport Security", "medium",
                    "The certificate is close to its expiry date.",
                    f"Approximately {days_left} day(s) remain.",
                    "Renew the certificate before expiry and automate renewal monitoring.", "CWE-324"))
        if cipher and cipher[1] in {"TLSv1", "TLSv1.1", "SSLv3", "SSLv2"}:
            findings.append(_finding(
                "Legacy TLS protocol negotiated", "Transport Security", "high",
                "The endpoint negotiated an obsolete transport protocol.",
                f"Negotiated protocol: {cipher[1]}.",
                "Disable obsolete SSL/TLS protocols and permit TLS 1.2 or TLS 1.3.", "CWE-326"))
    except ssl.SSLCertVerificationError as exc:
        findings.append(_finding(
            "TLS certificate validation failed", "Transport Security", "high",
            "The certificate could not be validated by the local trust store.",
            str(exc), "Install a valid certificate with the correct hostname and complete trusted chain.", "CWE-295"))
    except (OSError, ssl.SSLError, ValueError) as exc:
        findings.append(_finding(
            "TLS handshake could not be verified", "Transport Security", "info",
            "The scanner could not complete an independent TLS handshake.",
            str(exc), "Confirm that HTTPS is enabled and the server accepts modern TLS connections."))
    return findings


def _inspect_headers(snapshot: ResponseSnapshot, findings: list[dict[str, str]]) -> None:
    headers = {key.lower(): value for key, value in snapshot.headers.items()}
    is_https = urlsplit(snapshot.url).scheme == "https"

    if is_https and "strict-transport-security" not in headers:
        findings.append(_finding(
            "HTTP Strict Transport Security (HSTS) is missing", "Security Headers", "medium",
            "The HTTPS response does not instruct browsers to prefer HTTPS for future requests.",
            "Strict-Transport-Security response header not found.",
            "Configure HSTS after confirming the entire site and required subdomains work over HTTPS. Start with a suitable max-age.", "CWE-319"))
    if "content-security-policy" not in headers:
        findings.append(_finding(
            "Content Security Policy (CSP) is missing", "Security Headers", "medium",
            "No Content-Security-Policy header was observed on the main response.",
            "Content-Security-Policy response header not found.",
            "Define a restrictive CSP for scripts, styles, images, frames, and other required resource sources; test in report-only mode first.", "CWE-693"))
    csp = headers.get("content-security-policy", "").lower()
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        findings.append(_finding(
            "Clickjacking protection is missing", "Security Headers", "medium",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "No recognized anti-framing response header was found.",
            "Set Content-Security-Policy frame-ancestors, or X-Frame-Options for legacy browser support.", "CWE-1021"))
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(_finding(
            "MIME sniffing protection is missing", "Security Headers", "low",
            "X-Content-Type-Options: nosniff was not observed.",
            f"Observed value: {headers.get('x-content-type-options', 'not set')}.",
            "Set X-Content-Type-Options: nosniff on application responses.", "CWE-16"))
    if "referrer-policy" not in headers:
        findings.append(_finding(
            "Referrer-Policy is missing", "Security Headers", "low",
            "The response does not define a referrer information policy.",
            "Referrer-Policy response header not found.",
            "Set a policy such as strict-origin-when-cross-origin, based on application requirements.", "CWE-200"))
    if "permissions-policy" not in headers:
        findings.append(_finding(
            "Permissions-Policy is missing", "Security Headers", "info",
            "No Permissions-Policy header was observed.",
            "Permissions-Policy response header not found.",
            "Explicitly disable browser capabilities the application does not need, such as camera, microphone, or geolocation."))

    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        findings.append(_finding(
            "Web server version disclosure", "Information Disclosure", "low",
            "The Server header appears to reveal a product version.",
            f"Server: {server}",
            "Suppress unnecessary product/version details in response headers where practical.", "CWE-200"))
    powered = headers.get("x-powered-by", "")
    if powered:
        findings.append(_finding(
            "Technology stack disclosure", "Information Disclosure", "low",
            "The X-Powered-By header reveals application technology details.",
            f"X-Powered-By: {powered}",
            "Remove X-Powered-By and similar stack-identifying response headers.", "CWE-200"))

    cors_origin = headers.get("access-control-allow-origin", "")
    cors_credentials = headers.get("access-control-allow-credentials", "").lower()
    if cors_origin == "*":
        severity = "low" if cors_credentials != "true" else "medium"
        findings.append(_finding(
            "Permissive CORS origin policy", "Access Control", severity,
            "The response allows cross-origin requests from any origin. This may be intentional for public resources, but should be reviewed.",
            f"Access-Control-Allow-Origin: *; Allow-Credentials: {cors_credentials or 'not set'}.",
            "Use an explicit allowlist of trusted origins for private or user-specific data. Do not combine wildcard origins with credentialed access.",
            "CWE-942", affected_url=snapshot.url, confidence="potential",
            observation_type="potential_vulnerability",
            impact="A cross-origin caller may read this response if the resource contains sensitive or user-specific data.",
            verification="Send a controlled Origin header and verify whether only approved origins are returned.",
            detection_method="CORS response-header inspection"))


def _inspect_cookies(snapshot: ResponseSnapshot, findings: list[dict[str, str]]) -> None:
    is_https = urlsplit(snapshot.url).scheme == "https"
    for cookie in snapshot.cookies:
        lower = cookie.lower()
        name = cookie.split("=", 1)[0].strip() or "unnamed cookie"
        missing: list[str] = []
        if is_https and "; secure" not in lower:
            missing.append("Secure")
        if "; httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite=" not in lower:
            missing.append("SameSite")
        if missing:
            severity = "medium" if "Secure" in missing else "low"
            findings.append(_finding(
                f"Cookie flags need review: {name[:60]}", "Session Management", severity,
                "A Set-Cookie response was observed without all commonly recommended browser security attributes.",
                f"Set-Cookie for {name} on {snapshot.url}; missing: {', '.join(missing)}.",
                "Set Secure on HTTPS cookies, HttpOnly for cookies not needed by JavaScript, and an appropriate SameSite value. Review each cookie's purpose.",
                "CWE-614", affected_url=snapshot.url, confidence="confirmed",
                observation_type="security_misconfiguration",
                impact="Missing cookie attributes can expose session or preference data to interception or script access.",
                verification="Inspect the Set-Cookie response again and confirm each required attribute is present.",
                detection_method="Set-Cookie header parsing"))


def _inspect_page(snapshot: ResponseSnapshot, findings: list[dict[str, str]]) -> None:
    content_type = next((v for k, v in snapshot.headers.items() if k.lower() == "content-type"), "")
    if "html" not in content_type.lower() and not snapshot.body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return
    parser = PageParser()
    try:
        parser.feed(snapshot.body.decode("utf-8", errors="replace"))
    except Exception:
        return
    if parser.mixed_content:
        examples = ", ".join(parser.mixed_content[:3])
        findings.append(_finding(
            "Potential mixed content on HTTPS page", "Transport Security", "medium",
            "The page contains one or more resources or links using plain HTTP. HTTP scripts, styles, and media can weaken an HTTPS page; ordinary links need separate review.",
            f"Observed URL(s): {examples}",
            "Change active resources to HTTPS or remove them. Review ordinary navigation links separately rather than treating every HTTP link as executable mixed content.", "CWE-311"))

    page_is_https = urlsplit(snapshot.url).scheme == "https"
    for form in parser.forms:
        if not form.get("has_password"):
            continue
        action = str(form.get("action") or snapshot.url)
        action_url = urljoin(snapshot.url, action)
        action_parts = urlsplit(action_url)
        if page_is_https and action_parts.scheme == "http":
            findings.append(_finding(
                "Password form submits over HTTP", "Authentication", "high",
                "A password input was detected in a form whose action uses unencrypted HTTP.",
                f"Form action: {action_url}",
                "Submit credentials only to an HTTPS endpoint and enforce HTTPS across the authentication flow.", "CWE-319"))
        elif action_parts.netloc and action_parts.netloc.lower() != urlsplit(snapshot.url).netloc.lower():
            findings.append(_finding(
                "Password form submits to a different host", "Authentication", "medium",
                "A password form appears to submit credentials to a host different from the page host. Confirm this is an approved identity provider.",
                f"Form action: {action_url}",
                "Verify the destination is an approved authentication provider and that the handoff is protected by HTTPS.", "CWE-522"))


def _probe_exposures(session: requests.Session, base_url: str, findings: list[dict[str, str]]) -> None:
    checks = [
        ("/.env", "environment configuration", lambda b: any(token in b.upper() for token in (b"DB_PASSWORD", b"SECRET_KEY", b"AWS_ACCESS_KEY", b"APP_KEY"))),
        ("/.git/HEAD", "Git repository metadata", lambda b: b"ref: refs/heads/" in b.lower()),
        ("/.ds_store", "macOS directory metadata", lambda b: b"Bud1" in b[:16]),
        ("/backup.zip", "backup archive", lambda b: b.startswith(b"PK\x03\x04")),
        ("/config.php.bak", "backup configuration file", lambda b: any(token in b.upper() for token in (b"DB_HOST", b"DB_PASSWORD", b"MYSQL_"))),
        ("/phpinfo.php", "PHP configuration page", lambda b: b"phpinfo()" in b.lower() or b"php version" in b.lower()),
        ("/server-status", "web server status page", lambda b: b"server status" in b.lower() or b"server uptime" in b.lower()),
    ]
    for path, label, signature in checks:
        try:
            snap = _snapshot_request(session, urljoin(base_url, path), max_bytes=4096)
        except ScanError:
            continue
        if snap.status_code == 200 and signature(snap.body):
            findings.append(_finding(
                f"Publicly accessible {label}", "Exposed Resources", "high",
                f"A known sensitive resource signature was detected at {path}.",
                f"GET {path} returned HTTP 200 and matched a {label} content signature.",
                "Remove the resource from the web root, deny web access at the server, rotate any exposed secrets, and review access logs.", "CWE-552"))
        time.sleep(0.12)

    for path in ("/uploads/", "/backup/", "/files/"):
        try:
            snap = _snapshot_request(session, urljoin(base_url, path), max_bytes=8192)
        except ScanError:
            continue
        body_lower = snap.body.lower()
        if snap.status_code == 200 and (b"<title>index of /" in body_lower or b"<h1>index of /" in body_lower):
            findings.append(_finding(
                f"Directory listing enabled: {path}", "Exposed Resources", "medium",
                "The server appears to provide an automatically generated directory index.",
                f"GET {path} returned HTTP 200 and an 'Index of' page signature.",
                "Disable directory indexing and ensure sensitive files are stored outside the public web root.", "CWE-548"))
        time.sleep(0.12)


def _inspect_robots(session: requests.Session, base_url: str, findings: list[dict[str, str]]) -> None:
    try:
        snap = _snapshot_request(session, urljoin(base_url, "/robots.txt"), max_bytes=8192)
    except ScanError:
        return
    if snap.status_code == 200 and snap.body.strip():
        lines = [line.strip() for line in snap.body.decode("utf-8", errors="replace").splitlines()
                 if line.lower().startswith("disallow:") and line.split(":", 1)[-1].strip()]
        if lines:
            findings.append(_finding(
                "Robots.txt lists restricted-looking paths", "Information Disclosure", "info",
                "robots.txt is public by design, but its Disallow entries may reveal paths worth reviewing. This is not proof that those paths are accessible.",
                "; ".join(lines[:8]),
                "Do not rely on robots.txt for access control. Enforce authentication and authorization on every restricted route."))


def calculate_score(findings: list[dict[str, str]], coverage: dict[str, object] | None = None) -> int | None:
    """Calculate a bounded baseline score from unique, actionable findings.

    Coverage below 50 percent is insufficient for a reliable posture score.
    The score is not a guarantee and does not reward successful completion alone.
    """
    if coverage:
        percentage = int(coverage.get("percentage", 0))
        if percentage < 50:
            return None
    deductions = {"critical": 30, "high": 18, "medium": 9, "low": 4, "info": 0}
    seen: set[str] = set()
    total = 0
    for item in findings:
        fingerprint = str(item.get("fingerprint") or "")
        if fingerprint and fingerprint in seen:
            continue
        if fingerprint:
            seen.add(fingerprint)
        if item.get("observation_type") in {"informational_observation", "security_observation"}:
            continue
        total += deductions.get(str(item.get("severity", "info")).lower(), 0)
    return max(0, 100 - total)


def _fingerprint_technologies(headers: dict[str, str], body: bytes, parser: PageParser) -> list[dict[str, str]]:
    observations: list[dict[str, str]] = []
    lower_body = body.lower()

    for source_name, evidence in (
        ("Server header", headers.get("server", "")),
        ("X-Powered-By header", headers.get("x-powered-by", "")),
    ):
        if evidence:
            observations.append({
                "name": evidence,
                "source": source_name,
                "evidence": evidence[:240],
                "confidence": "medium",
                "status": "inferred",
            })

    signatures = (
        ("WordPress", (b"/wp-content/", b"/wp-includes/", b"wp-json"), "HTML asset or API paths"),
        ("Drupal", (b"/sites/default/files/", b"drupal-settings-json"), "HTML asset or response pattern"),
        ("React", (b"react-dom", b"__react", b"/static/js/"), "HTML asset or JavaScript package signature"),
        ("Next.js", (b"/_next/static/", b"__next_data__"), "HTML asset or framework response pattern"),
        ("Vue.js", (b"data-v-", b"/__vite/", b"vue.runtime"), "HTML asset or framework response pattern"),
        ("Bootstrap", (b"bootstrap.min.css", b"bootstrap.bundle"), "HTML asset signature"),
        ("jQuery", (b"jquery.min.js", b"jquery-", b"/jquery.js"), "JavaScript library signature"),
    )
    for name, signatures_list, source in signatures:
        evidence = next((needle.decode("utf-8", errors="ignore") for needle in signatures_list if needle in lower_body), "")
        if evidence:
            script_evidence = next((url for url in parser.scripts if evidence.lower().strip("/") in url.lower()), "")
            observations.append({
                "name": name,
                "source": source,
                "evidence": script_evidence or evidence,
                "confidence": "high" if evidence else "low",
                "status": "confirmed",
            })

    for meta in parser.meta:
        generator = meta.get("content", "") if meta.get("name", "").lower() == "generator" else ""
        if generator:
            observations.append({
                "name": generator,
                "source": "HTML generator metadata",
                "evidence": f"meta name=\"generator\" content=\"{generator}\"",
                "confidence": "high",
                "status": "confirmed",
            })
    return observations


def _browser_render(start_url: str) -> dict[str, object]:
    result = {
        "status": "not_tested",
        "reason": "Set WAPT_PLAYWRIGHT=1 to enable optional browser rendering.",
        "pages": [],
        "links": [],
        "forms": [],
    }
    if os.getenv("WAPT_PLAYWRIGHT", "").lower() not in {"1", "true", "yes"}:
        return result
    try:
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError:
        result["reason"] = "Playwright is not installed; browser rendering was not tested."
        return result

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                java_script_enabled=True,
                ignore_https_errors=False,
                viewport={"width": 1280, "height": 720},
            )
            base = urlsplit(start_url)

            def block_external(route) -> None:
                destination = urlsplit(route.request.url)
                if destination.scheme not in {"http", "https"} or destination.netloc.lower() != base.netloc.lower():
                    route.abort()
                else:
                    route.continue_()

            context.route("**/*", block_external)
            page = context.new_page()
            page.set_default_navigation_timeout(7000)
            page.set_default_timeout(7000)
            response = page.goto(start_url, wait_until="domcontentloaded", timeout=7000)
            page.wait_for_timeout(500)
            html = page.content()
            links = page.eval_on_selector_all("a[href]", "(elements) => elements.map(e => e.href)")
            forms = page.eval_on_selector_all(
                "form",
                "(elements) => elements.map(f => ({action: f.action || '', method: f.method || 'get', inputs: Array.from(f.elements).map(e => e.name || e.type).filter(Boolean)}))",
            )
            same_origin_links = []
            for link in links:
                normalized = _normalize_same_origin_url(start_url, str(link))
                if normalized:
                    same_origin_links.append(normalized)
            result = {
                "status": "tested",
                "reason": "",
                "http_status": response.status if response else None,
                "pages": [start_url],
                "links": sorted(set(same_origin_links))[:MAX_CRAWL_PAGES],
                "forms": forms[:20],
                "rendered_dom_bytes": len(html.encode("utf-8")),
            }
            browser.close()
    except PlaywrightTimeoutError:
        result["status"] = "inconclusive"
        result["reason"] = "Browser navigation exceeded the strict timeout."
    except Exception as exc:
        result["status"] = "inconclusive"
        result["reason"] = f"Browser rendering could not be completed safely: {type(exc).__name__}"
    return result


def redact_url_for_recon(value: str) -> str:
    return re.sub(r"([?&](?:token|key|password|secret|session)=[^&#]*)", r"\1[redacted]", value, flags=re.I)


def _normalize_same_origin_url(base_url: str, link: str) -> str | None:
    absolute = urldefrag(urljoin(base_url, link))[0]
    parts = urlsplit(absolute)
    base = urlsplit(base_url)
    if parts.scheme not in {"http", "https"} or parts.netloc.lower() != base.netloc.lower():
        return None
    if parts.scheme != base.scheme:
        return None
    path = parts.path or "/"
    if parts.query:
        normalized = urlunsplit((parts.scheme, parts.netloc, path, parts.query, ""))
    else:
        normalized = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
    return normalized


def _bounded_crawl(session: requests.Session, start_url: str) -> dict[str, object]:
    base = urlsplit(start_url)
    queue: list[tuple[str, int]] = [(start_url, 0)]
    visited: set[str] = set()
    pages: list[dict[str, object]] = []
    discovered_links: set[str] = set()
    forms: list[dict[str, object]] = []
    while queue and len(pages) < MAX_CRAWL_PAGES:
        url, depth = queue.pop(0)
        normalized = _normalize_same_origin_url(start_url, url)
        if not normalized or normalized in visited:
            continue
        visited.add(normalized)
        try:
            snapshot = _snapshot_request(session, normalized, max_bytes=MAX_PAGE_BYTES)
        except ScanError:
            pages.append({"url": normalized, "status": None, "error": "Not fetched: target safety or request validation rejected it"})
            continue
        content_type = next((v for k, v in snapshot.headers.items() if k.lower() == "content-type"), "")
        pages.append({"url": snapshot.url, "status": snapshot.status_code, "content_type": content_type})
        if "html" not in content_type.lower() and not snapshot.body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
            continue
        parser = PageParser()
        parser.feed(snapshot.body.decode("utf-8", errors="replace"))
        for form in parser.forms:
            forms.append({"page": snapshot.url, **form})
        if depth < MAX_CRAWL_DEPTH:
            for link in parser.links:
                link_url = _normalize_same_origin_url(snapshot.url, link)
                if link_url and link_url not in visited:
                    discovered_links.add(link_url)
                    queue.append((link_url, depth + 1))
        time.sleep(0.12)
    return {
        "pages": pages,
        "pages_assessed": len(pages),
        "links_discovered": sorted(discovered_links),
        "forms": forms,
        "same_origin": f"{base.scheme}://{base.netloc}",
        "limits": {"max_pages": MAX_CRAWL_PAGES, "max_depth": MAX_CRAWL_DEPTH, "timeout_seconds": 7},
    }


def _tls_observations(hostname: str, port: int) -> dict[str, object]:
    if not hostname:
        return {"status": "not_tested", "reason": "No HTTPS hostname was available."}
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as tls:
                certificate = tls.getpeercert()
                protocol = tls.cipher()
        result = {
            "status": "verified",
            "subject": certificate.get("subject"),
            "issuer": certificate.get("issuer"),
            "not_before": certificate.get("notBefore"),
            "not_after": certificate.get("notAfter"),
            "cipher": protocol,
        }
        return result
    except (OSError, ssl.SSLError, ssl.SSLCertVerificationError) as exc:
        return {"status": "inconclusive", "reason": str(exc)}


def scan_site(target: str) -> dict[str, object]:
    normalized = validate_target(target)
    findings: list[dict[str, str]] = []
    observations: list[dict[str, str]] = []
    coverage_checks: dict[str, str] = {}
    started = time.monotonic()
    initial_parts = urlsplit(normalized)
    if initial_parts.scheme == "https":
        # Run TLS verification first so an invalid certificate can still be reported
        # without disabling certificate verification for the HTTP request.
        findings.extend(check_tls(initial_parts.hostname or "", initial_parts.port or 443))
        coverage_checks["TLS configuration"] = "tested"

    session = requests.Session()
    session.trust_env = False  # Do not inherit proxy settings from the host environment.
    main: ResponseSnapshot | None = None
    request_error: str | None = None
    try:
        main = _snapshot_request(session, normalized)
    except ScanError as exc:
        request_error = str(exc)
    finally:
        session.close()

    if main is not None:
        _inspect_headers(main, findings)
        _inspect_cookies(main, findings)
        _inspect_page(main, findings)
        for category in ("HSTS", "CSP", "Clickjacking", "MIME sniffing", "Referrer-Policy",
                         "Permissions-Policy", "CORS", "Cookies", "Forms"):
            coverage_checks[category] = "tested"
        final_url = main.url
        http_status: int | None = main.status_code
        response_time_ms: int | None = main.elapsed_ms
        final_parts_for_tls = urlsplit(final_url)
        initial_tls_key = (initial_parts.hostname, initial_parts.port or 443) if initial_parts.scheme == "https" else None
        final_tls_key = (final_parts_for_tls.hostname, final_parts_for_tls.port or 443) if final_parts_for_tls.scheme == "https" else None
        if final_tls_key and final_tls_key != initial_tls_key:
            findings.extend(check_tls(final_parts_for_tls.hostname or "", final_parts_for_tls.port or 443))
    else:
        # Preserve TLS findings if the safe, certificate-verified HTTP request failed.
        if not findings:
            raise ScanError(request_error or "The target could not be assessed.")
        final_url = normalized
        http_status = None
        response_time_ms = None
        findings.append(_finding(
            "Main page could not be fetched safely", "Assessment Coverage", "info",
            "The scanner did not bypass transport verification to retrieve the page.",
            request_error or "No additional response details are available.",
            "Resolve the transport or connectivity issue and run the assessment again."))

    final_parts = urlsplit(final_url)
    if final_parts.scheme == "http":
        findings.append(_finding(
            "Website is served over HTTP", "Transport Security", "high",
            "The final page URL uses unencrypted HTTP, so traffic can be read or modified in transit.",
            f"Final URL: {final_url}",
            "Enable HTTPS with a trusted certificate and redirect HTTP requests to HTTPS. Mark sensitive cookies Secure.", "CWE-319"))

    # Additional probes are deliberately limited to a fixed, small set of public paths.
    # Skip these probes when the verified main-page request failed.
    if main is not None:
        probe_session = requests.Session()
        probe_session.trust_env = False
        try:
            _probe_exposures(probe_session, main.url, findings)
            _inspect_robots(probe_session, main.url, findings)
            coverage_checks["Exposed resources"] = "tested"
            coverage_checks["robots.txt"] = "tested"
            crawl = _bounded_crawl(probe_session, main.url)
            browser = _browser_render(main.url)
            if browser["status"] == "tested":
                coverage_checks["Browser-rendered coverage"] = "tested"
            else:
                coverage_checks["Browser-rendered coverage"] = browser["status"]
        finally:
            probe_session.close()
    else:
        crawl = {"pages": [], "pages_assessed": 0, "links_discovered": [], "forms": [],
                 "same_origin": urlunsplit((initial_parts.scheme, initial_parts.netloc, "", "", "")),
                 "limits": {"max_pages": MAX_CRAWL_PAGES, "max_depth": MAX_CRAWL_DEPTH, "timeout_seconds": 7}}
        browser = {"status": "not_tested", "reason": "Main HTTP page was not available.", "pages": [],
                   "links": [], "forms": []}

    coverage_checks.setdefault("Main page", "tested" if main is not None else "not_tested")
    coverage_checks.setdefault("Crawler", "tested" if main is not None and crawl["pages_assessed"] > 0 else "not_tested")
    coverage_checks.setdefault("Exposed resources", "tested" if main is not None else "not_tested")
    coverage_checks.setdefault("robots.txt", "tested" if main is not None else "not_tested")
    tested = sum(1 for value in coverage_checks.values() if value == "tested")
    total = len(coverage_checks)
    coverage = {
        "tested": tested,
        "total": total,
        "percentage": round((tested * 100 / total), 1) if total else 0,
        "checks": coverage_checks,
        "pages_assessed": crawl["pages_assessed"],
        "limits": crawl["limits"],
    }

    unique: dict[str, dict[str, str]] = {}
    for item in findings:
        item.setdefault("affected_url", final_url)
        item.setdefault("confidence", "confirmed" if item["severity"] in {"critical", "high", "medium", "low"} else "informational")
        item.setdefault("observation_type", "security_misconfiguration" if item["severity"] != "info" else "informational_observation")
        item.setdefault("impact", item["description"])
        item.setdefault("verification", "Compare the response and configuration again after remediation.")
        item.setdefault("detection_method", "Targeted HTTP and TLS response inspection")
        key = str(item.get("fingerprint") or f"{item['category']}|{item['title']}|{item['evidence'][:120]}")
        unique[key] = item
    findings = list(unique.values())
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order.get(item["severity"], 5), item["category"], item["title"]))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity)
              for severity in ("critical", "high", "medium", "low", "info")}
    reconnaissance_headers = {}
    if main is not None:
        reconnaissance_headers = {str(k).lower(): str(v) for k, v in main.headers.items()}
    recon = {
        "target": normalized,
        "final_url": final_url,
        "http_status": http_status,
        "response_time_ms": response_time_ms,
        "content_type": next((v for k, v in reconnaissance_headers.items() if k == "content-type"), "unknown"),
        "headers": reconnaissance_headers,
        "cookies": [cookie.split(";", 1)[0] for cookie in (main.cookies if main is not None else [])],
        "crawler": crawl,
        "browser": browser,
        "technologies": [],
        "html_metadata": {"title": "", "meta": [], "scripts": []},
        "api_references": [],
        "tls": _tls_observations(final_parts.hostname or "", final_parts.port or (443 if final_parts.scheme == "https" else 80)),
    }
    server = reconnaissance_headers.get("server", "")
    powered = reconnaissance_headers.get("x-powered-by", "")
    if main is not None:
        parser = PageParser()
        parser.feed(main.body.decode("utf-8", errors="replace"))
        recon["html_metadata"] = {
            "title": parser.title.strip(),
            "meta": parser.meta[:30],
            "scripts": parser.scripts[:30],
        }
        api_matches = re.findall(r"(?:https?:)?//[^\"'\s<>]+|(?:/api/)[^\"'\s<>]+", main.body.decode("utf-8", errors="replace"), re.I)
        recon["api_references"] = sorted(set(redact_url_for_recon(urljoin(final_url, match)) for match in api_matches))[:20]
        recon["technologies"] = _fingerprint_technologies(reconnaissance_headers, main.body, parser)
    if server:
        recon["technologies"].append({"name": "Server header", "value": server, "confidence": "medium"})
    if powered:
        recon["technologies"].append({"name": "X-Powered-By", "value": powered, "confidence": "medium"})
    return {
        "target": normalized,
        "final_url": final_url,
        "http_status": http_status,
        "response_time_ms": response_time_ms,
        "duration_seconds": round(time.monotonic() - started, 2),
        "score": calculate_score(findings, coverage),
        "coverage": coverage,
        "reconnaissance": recon,
        "observations": observations,
        "counts": counts,
        "findings": findings,
        "scanner_version": "2.0.0",
        "methodology_version": "WAPT-Baseline-2",
        "scope_note": "Safe baseline checks only. No credential attacks, destructive tests, or exploit payloads were executed.",
    }
