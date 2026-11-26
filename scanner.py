"""Conservative, non-destructive checks for explicitly authorized web targets."""
from __future__ import annotations

import ipaddress
import re
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import requests

USER_AGENT = "WAPT-LabScanner/1.0 (+authorized defensive assessment)"
MAX_REDIRECTS = 4
REQUEST_TIMEOUT = (4, 7)
MAX_PAGE_BYTES = 256_000


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
        self._form: dict[str, object] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        for attr in ("src", "href", "action", "poster"):
            value = values.get(attr, "").strip()
            if value.lower().startswith("http://"):
                self.mixed_content.append(value)
        if tag.lower() == "form":
            self._form = {"action": values.get("action", ""), "method": values.get("method", "get").lower(), "has_password": False}
            self.forms.append(self._form)
        elif tag.lower() == "input" and self._form is not None:
            if values.get("type", "").lower() == "password":
                self._form["has_password"] = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._form = None


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


def _finding(title: str, category: str, severity: str, description: str, evidence: str, recommendation: str, cwe: str = "") -> dict[str, str]:
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "description": description,
        "evidence": evidence[:500],
        "recommendation": recommendation,
        "cwe": cwe,
    }


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
            "Use an explicit allowlist of trusted origins for private or user-specific data. Do not combine wildcard origins with credentialed access.", "CWE-942"))


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
                f"Cookie name: {name}; missing: {', '.join(missing)}.",
                "Set Secure on HTTPS cookies, HttpOnly for cookies not needed by JavaScript, and an appropriate SameSite value. Review each cookie's purpose.", "CWE-614"))


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


def calculate_score(findings: list[dict[str, str]]) -> int:
    deductions = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
    return max(0, 100 - sum(deductions.get(item.get("severity", "info"), 0) for item in findings))


def scan_site(target: str) -> dict[str, object]:
    normalized = validate_target(target)
    findings: list[dict[str, str]] = []
    started = time.monotonic()
    initial_parts = urlsplit(normalized)
    if initial_parts.scheme == "https":
        # Run TLS verification first so an invalid certificate can still be reported
        # without disabling certificate verification for the HTTP request.
        findings.extend(check_tls(initial_parts.hostname or "", initial_parts.port or 443))

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
        finally:
            probe_session.close()

    unique: dict[tuple[str, str], dict[str, str]] = {}
    for item in findings:
        unique[(item["title"], item["evidence"])] = item
    findings = list(unique.values())
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda item: (order.get(item["severity"], 5), item["category"], item["title"]))
    counts = {severity: sum(1 for item in findings if item["severity"] == severity)
              for severity in ("critical", "high", "medium", "low", "info")}
    return {
        "target": normalized,
        "final_url": final_url,
        "http_status": http_status,
        "response_time_ms": response_time_ms,
        "duration_seconds": round(time.monotonic() - started, 2),
        "score": calculate_score(findings),
        "counts": counts,
        "findings": findings,
        "scanner_version": "1.0.0",
        "scope_note": "Safe baseline checks only. No credential attacks, destructive tests, or exploit payloads were executed.",
    }
