#!/usr/bin/env python3
"""
psirt_fetch.py — poll the Cisco PSIRT openVuln API and write advisories.json
for the PSIRT Watch dashboard.

Auth:  OAuth2 client-credentials against https://id.cisco.com/oauth2/default/v1/token
API:   https://apix.cisco.com/security/advisories/v2   (apps created after Mar 2023)
Docs:  https://developer.cisco.com/docs/psirt/

Credentials come from the environment — never hard-code them:
    export CISCO_CLIENT_ID=xxxxxxxx
    export CISCO_CLIENT_SECRET=xxxxxxxx

Usage:
    python3 psirt_fetch.py --once                 # single pull (for cron / systemd timer)
    python3 psirt_fetch.py                         # loop, poll every 30s
    python3 psirt_fetch.py --mode firstpublished --start 2026-07-28 --end 2026-07-28
    python3 psirt_fetch.py --latest 200 --out /var/www/psirt/advisories.json

Stdlib only — no pip install required.
"""

import argparse
import json
import os
import sys
import time
import tempfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone, date, timedelta

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_BASE = "https://apix.cisco.com/security/advisories/v2"

_token = {"value": None, "expires_at": 0}


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def get_token(client_id, client_secret):
    """Return a cached bearer token, refreshing shortly before expiry."""
    if _token["value"] and time.time() < _token["expires_at"] - 60:
        return _token["value"]

    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "grant_type": "client_credentials",
    }).encode()
    req = urllib.request.Request(
        TOKEN_URL, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.load(r)
    _token["value"] = data["access_token"]
    _token["expires_at"] = time.time() + int(data.get("expires_in", 3599))
    log("obtained new access token")
    return _token["value"]


def api_get(path, token):
    req = urllib.request.Request(
        API_BASE + path,
        headers={"Authorization": "Bearer " + token, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=45) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        if "NO_DATA_FOUND" in body:          # empty date window is not an error
            return {"advisories": []}
        raise


def build_path(args):
    if args.mode == "firstpublished":
        start, end = args.start, args.end
        if not (start and end):                       # default: rolling last N days
            end = date.today().isoformat()
            start = (date.today() - timedelta(days=args.days)).isoformat()
        q = urllib.parse.urlencode({"startDate": start, "endDate": end})
        return f"/all/firstpublished?{q}"
    if args.mode == "severity":
        return f"/severity/{args.severity}/firstpublished"
    n = min(max(args.latest, 1), 100)                 # API caps pageSize at 100
    return f"/latest/{n}"


def normalise(raw):
    """Map the openVuln v2 payload to the compact shape the dashboard reads.

    The v2 API returns {"advisories": [ {...}, ... ]}. Fields vary a little by
    endpoint, so every access is defensive.
    """
    advisories = raw.get("advisories", raw if isinstance(raw, list) else [])
    out = []
    for a in advisories:
        cves = a.get("cves") or []
        if isinstance(cves, str):
            cves = [cves]
        products = a.get("productNames") or a.get("product_names") or []
        if isinstance(products, str):
            products = [products]
        out.append({
            "id": a.get("advisoryId") or a.get("advisory_id") or "",
            "title": a.get("advisoryTitle") or a.get("advisory_title") or "",
            "sir": a.get("sir") or "Informational",
            "cvss": a.get("cvssBaseScore") or a.get("cvss_base_score") or "—",
            "cves": [c for c in cves if c and c != "NA"],
            "products": products,
            "firstPublished": a.get("firstPublished") or a.get("first_published") or "",
            "lastUpdated": a.get("lastUpdated") or a.get("last_updated") or "",
            "version": a.get("version") or "",
            "url": a.get("publicationUrl") or a.get("publication_url") or "#",
        })
    # newest first
    out.sort(key=lambda x: x.get("firstPublished") or "", reverse=True)
    return out


def write_atomic(path, payload):
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=d, suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        os.replace(tmp, path)  # atomic on POSIX — dashboard never sees a half-written file
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def pull_once(args, client_id, client_secret):
    token = get_token(client_id, client_secret)
    raw = api_get(build_path(args), token)
    advisories = normalise(raw)
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "source": API_BASE + build_path(args),
        "count": len(advisories),
        "advisories": advisories,
    }
    write_atomic(args.out, payload)
    log(f"wrote {len(advisories)} advisories -> {args.out}")
    return len(advisories)


def main():
    p = argparse.ArgumentParser(description="Poll Cisco PSIRT openVuln API -> advisories.json")
    p.add_argument("--out", default="advisories.json", help="output file (default: ./advisories.json)")
    p.add_argument("--once", action="store_true", help="single pull then exit (for cron)")
    p.add_argument("--interval", type=int, default=30, help="loop poll interval seconds (default 30)")
    p.add_argument("--mode", choices=["latest", "firstpublished", "severity"], default="firstpublished")
    p.add_argument("--days", type=int, default=14, help="firstpublished rolling window in days (default 14)")
    p.add_argument("--latest", type=int, default=100, help="how many latest advisories, max 100 (mode=latest)")
    p.add_argument("--severity", default="critical", help="critical|high|medium|info (mode=severity)")
    p.add_argument("--start", help="YYYY-MM-DD (mode=firstpublished, overrides --days)")
    p.add_argument("--end", help="YYYY-MM-DD (mode=firstpublished, overrides --days)")
    args = p.parse_args()

    client_id = os.environ.get("CISCO_CLIENT_ID")
    client_secret = os.environ.get("CISCO_CLIENT_SECRET")
    if not client_id or not client_secret:
        sys.exit("Set CISCO_CLIENT_ID and CISCO_CLIENT_SECRET in the environment first.")

    if args.once:
        pull_once(args, client_id, client_secret)
        return

    log(f"polling every {args.interval}s — Ctrl-C to stop")
    while True:
        try:
            pull_once(args, client_id, client_secret)
        except urllib.error.HTTPError as e:
            log(f"HTTP {e.code}: {e.reason} (will retry)")
            if e.code == 401:
                _token["value"] = None  # force token refresh next loop
        except Exception as e:  # noqa: BLE001 — keep the watcher alive
            log(f"error: {e} (will retry)")
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
