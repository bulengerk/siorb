#!/usr/bin/env python3
"""Produce a deterministic catalog evidence/review health report."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import pathlib
import socket
import threading
import tomllib
import urllib.error
import urllib.parse
import urllib.request


def safe_https_url(value: str) -> tuple[bool, str]:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError as error:
        return False, str(error)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        return False, "evidence URL must be credential-free HTTPS"
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return True, ""
    if not address.is_global:
        return False, "evidence URL cannot use a non-global IP literal"
    return True, ""


def request_url(url: str, method: str, timeout: float) -> tuple[int | None, str | None]:
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "User-Agent": "siorb-catalog-health/1",
    }
    request = urllib.request.Request(url, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, None
    except urllib.error.HTTPError as error:
        return error.code, f"HTTP {error.code}"
    except (OSError, socket.timeout, urllib.error.URLError) as error:
        return None, str(error)


def check_link(url: str, timeout: float) -> tuple[str, str | None, str | None]:
    valid, reason = safe_https_url(url)
    if not valid:
        return url, "evidence_unreachable", reason

    status, error = request_url(url, "HEAD", timeout)
    if status is not None and status < 400:
        return url, None, None

    # A number of repository/search endpoints reject HEAD even though their
    # browser-facing GET route is healthy. Retry with GET, but never consume the
    # response body. urllib closes the response as soon as the context exits.
    status, error = request_url(url, "GET", timeout)
    if status is not None and status < 400:
        return url, None, None
    if status in {404, 410}:
        return url, "evidence_unreachable", error
    return url, "evidence_probe_inconclusive", error or "evidence probe failed"


def parse_date(value: object) -> dt.date | None:
    if not isinstance(value, str):
        return None
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        return None


def interleave_by_hostname(urls: set[str]) -> list[str]:
    buckets: dict[str, list[str]] = {}
    for url in sorted(urls):
        hostname = urllib.parse.urlsplit(url).hostname or ""
        buckets.setdefault(hostname, []).append(url)
    result: list[str] = []
    while buckets:
        for hostname in sorted(buckets):
            values = buckets[hostname]
            result.append(values.pop(0))
        buckets = {hostname: values for hostname, values in buckets.items() if values}
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--catalog-dir", type=pathlib.Path, default=pathlib.Path("catalog/packages"))
    parser.add_argument("--max-age-days", type=int, default=180)
    parser.add_argument("--as-of", type=dt.date.fromisoformat, default=dt.datetime.now(dt.timezone.utc).date())
    parser.add_argument("--check-links", action="store_true")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    if args.max_age_days < 1 or args.timeout <= 0:
        parser.error("max age and timeout must be positive")

    findings: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []
    urls: set[str] = set()
    manifests = sorted(args.catalog_dir.rglob("*.toml"))
    for path in manifests:
        relative = path.as_posix()
        try:
            document = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
            findings.append({"kind": "invalid_manifest", "subject": relative, "detail": str(error)})
            continue
        package_id = str(document.get("id", relative))
        reviews = [(package_id, document.get("reviewed_at"))]
        for value in document.get("evidence", []):
            if isinstance(value, str):
                urls.add(value)
        for source in document.get("sources", []):
            if not isinstance(source, dict):
                continue
            subject = f"{package_id}:{source.get('id', '<unknown-source>')}"
            reviews.append((subject, source.get("reviewed_at")))
            if isinstance(source.get("evidence"), str):
                urls.add(source["evidence"])
        for subject, value in reviews:
            reviewed = parse_date(value)
            if reviewed is None:
                findings.append({"kind": "invalid_review_date", "subject": subject, "detail": str(value)})
            elif reviewed > args.as_of:
                findings.append({"kind": "future_review_date", "subject": subject, "detail": reviewed.isoformat()})
            elif (args.as_of - reviewed).days > args.max_age_days:
                findings.append({"kind": "stale_review", "subject": subject, "detail": reviewed.isoformat()})
    for url in sorted(urls):
        valid, reason = safe_https_url(url)
        if not valid:
            findings.append({"kind": "unsafe_evidence_url", "subject": url, "detail": reason})
    if args.check_links:
        host_locks = {
            urllib.parse.urlsplit(url).hostname: threading.Lock()
            for url in urls
            if urllib.parse.urlsplit(url).hostname
        }

        def probe(url: str) -> tuple[str, str | None, str | None]:
            hostname = urllib.parse.urlsplit(url).hostname
            if hostname is None:
                return check_link(url, args.timeout)
            # Avoid rate-limiting evidence providers by probing at most one URL
            # per host at a time while still checking independent hosts in
            # parallel.
            with host_locks[hostname]:
                return check_link(url, args.timeout)

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            for url, kind, detail in executor.map(probe, interleave_by_hostname(urls)):
                if kind == "evidence_unreachable":
                    findings.append({"kind": kind, "subject": url, "detail": detail or "unreachable"})
                elif kind == "evidence_probe_inconclusive":
                    warnings.append({"kind": kind, "subject": url, "detail": detail or "inconclusive"})

    findings.sort(key=lambda item: (item["kind"], item["subject"], item["detail"]))
    warnings.sort(key=lambda item: (item["kind"], item["subject"], item["detail"]))
    report = {
        "schema_version": "1.0",
        "as_of": args.as_of.isoformat(),
        "max_age_days": args.max_age_days,
        "manifests": len(manifests),
        "evidence_urls": len(urls),
        "healthy": not findings,
        "findings": findings,
        "warnings": warnings,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
