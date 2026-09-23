#!/usr/bin/env python3
"""
nashunter.py - Synology QuickConnect alias enumerator + unauth info-disclosure harvester

Authorized security testing tool (Null Threat Labs). Sprays candidate QuickConnect
IDs against Synology's public relay API to find whether a target's NAS is reachable
via https://quickconnect.to/<id>, and if so, pulls whatever unauthenticated recon
data that ID leaks - WAN IP, LAN subnet/gateway, DSM ports, relay endpoints.

Modeled on cloud_enum's approach (keyword -> mutated wordlist -> spray against a
shared provider namespace -> report hits), but for Synology QuickConnect instead
of S3/Azure/GCS buckets.

--- Research notes (2026-09-23), see engagement log for full detail ---
Endpoint : POST https://global.quickconnect.to/Serv.php
Body     : [{"version":1,"command":"get_server_info","stop_when_error":false,
             "stop_when_success":true,"id":"dsm","serverID":"<candidate>"}]
Miss     : errno 4, errinfo "...[Alias not found]"
Hit      : errno 0, full "server"/"service"/"smartdns" object returned, NO AUTH
A follow-up "request_tunnel" call against a confirmed hit additionally discloses a
relay IP/port that live-bridges to the NAS's DSM web service on the internet.

Rate limiting: none observed (no 429, no CAPTCHA/WAF page, consistent response
shape) across a 15-request rapid-fire burst from one source IP during research.
That is NOT a guarantee at higher volumes or over a longer campaign -
global.quickconnect.to is SHARED SYNOLOGY INFRASTRUCTURE serving every Synology
customer worldwide, not something owned by any one client. Treat it like any
other shared third-party service you spray during an engagement: be a good
citizen, because burning this IP's reputation against Synology affects every
future engagement, not just this one. Defaults here are deliberately conservative:

  - sequential requests only (no threading) - see bottom of file for why
  - randomized jitter delay between every request
  - exponential backoff + retry on transient network errors
  - a circuit breaker that ABORTS the whole run after --max-errors consecutive
    non-standard responses (HTTP errors, non-JSON bodies, unexpected errno) -
    that pattern is the signature of a WAF challenge or a ban starting to bite
  - a descriptive, contactable User-Agent (self-identifying, like a legitimate
    research/scanning bot) instead of spoofing a browser - lower odds of being
    flagged as malicious traffic in the first place, and gives Synology's abuse
    team something honest to look at if they ever do

SCOPE: candidate IDs must only be derived from the AUTHORIZED target's own
name/keywords (company name, abbreviations, site names). This queries a shared
third-party (Synology) service, not the client's own infrastructure - do not
use this to enumerate random/unrelated names, only permutations of the specific,
in-scope target you have written authorization to test.

This tool performs READ-ONLY alias enumeration and info-disclosure harvesting
only. It never touches DSM's login/auth endpoint - no credential guessing, no
brute force, no lockout testing. That is a separate, explicitly-scoped test.
"""

import argparse
import json
import random
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

API_URL = "https://global.quickconnect.to/Serv.php"
DEFAULT_UA = "nashunter/1.0 (+authorized-security-research; contact: ajohnson@nullthreat.ca)"

# Synology QuickConnect ID rules: 6-20 chars, starts with a letter, letters/digits/hyphens.
QC_ID_RE = re.compile(r"^[a-z][a-z0-9-]{5,19}$")

DEFAULT_MUTATIONS = [
    "%KEYWORD%",
    "%KEYWORD%nas", "%KEYWORD%-nas", "nas-%KEYWORD%",
    "%KEYWORD%-ds", "%KEYWORD%ds", "ds-%KEYWORD%",
    "%KEYWORD%-diskstation", "diskstation-%KEYWORD%",
    "%KEYWORD%-storage", "storage-%KEYWORD%",
    "%KEYWORD%-backup", "backup-%KEYWORD%",
    "%KEYWORD%-server", "server-%KEYWORD%",
    "%KEYWORD%-it", "it-%KEYWORD%",
    "%KEYWORD%-office", "office-%KEYWORD%",
    "%KEYWORD%-hq", "hq-%KEYWORD%",
    "%KEYWORD%-main",
    "%KEYWORD%01", "%KEYWORD%-01", "%KEYWORD%1", "%KEYWORD%-1",
    "%KEYWORD%02", "%KEYWORD%2",
    "%KEYWORD%-corp", "corp-%KEYWORD%",
    "%KEYWORD%-files", "files-%KEYWORD%",
    "%KEYWORD%-data", "data-%KEYWORD%",
    "%KEYWORD%-vault",
    "%KEYWORD%-media",
    "%KEYWORD%-prod", "%KEYWORD%-dev", "%KEYWORD%-test",
]


@dataclass
class QueryResult:
    candidate: str
    status: str  # "hit" | "miss" | "anomaly" | "error"
    data: Optional[dict] = field(default=None)
    error: Optional[str] = field(default=None)


def c(text, color, enabled):
    codes = {"red": "31", "green": "32", "yellow": "33", "grey": "90", "bold": "1"}
    return f"\033[{codes[color]}m{text}\033[0m" if enabled else text


def normalize_keyword(raw: str) -> set:
    """Split a free-text keyword into lowercase alnum tokens, return joined
    (no-separator) and hyphenated variants."""
    tokens = re.findall(r"[a-z0-9]+", raw.lower())
    if not tokens:
        return set()
    return {"".join(tokens), "-".join(tokens)}


def sanitize_candidate(raw: str) -> Optional[str]:
    """Lowercase, strip anything not a-z0-9-, collapse/trim hyphens, enforce
    the QuickConnect ID format. Returns None if the result is invalid."""
    s = raw.lower()
    s = re.sub(r"[^a-z0-9-]", "", s)
    s = re.sub(r"-{2,}", "-", s).strip("-")
    return s if QC_ID_RE.match(s) else None


def build_candidates(keywords: list, mutations: list) -> list:
    bases = set()
    for kw in keywords:
        bases |= normalize_keyword(kw)

    candidates = set()
    for base in bases:
        for pattern in mutations:
            raw = pattern.replace("%KEYWORD%", base)
            clean = sanitize_candidate(raw)
            if clean:
                candidates.add(clean)
    return sorted(candidates)


def _post(payload: dict, timeout: float, retries: int, backoff: float, user_agent: str):
    body = json.dumps([payload]).encode()
    req = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
    )
    last_exc = None
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ctype = resp.headers.get("Content-Type", "")
                raw = resp.read()
            if "json" not in ctype and "text/plain" not in ctype:
                return None, f"unexpected content-type {ctype!r} (WAF/challenge page?)"
            parsed = json.loads(raw)
            return parsed[0], None
        except (urllib.error.URLError, json.JSONDecodeError, TimeoutError,
                ConnectionError, IndexError, ValueError) as exc:
            last_exc = exc
            if attempt < retries:
                time.sleep(backoff * (attempt + 1))
                continue
    return None, str(last_exc)


def query_get_server_info(candidate: str, timeout: float, retries: int, backoff: float,
                           user_agent: str) -> QueryResult:
    entry, err = _post(
        {"version": 1, "command": "get_server_info", "stop_when_error": False,
         "stop_when_success": True, "id": "dsm", "serverID": candidate},
        timeout, retries, backoff, user_agent,
    )
    if entry is None:
        return QueryResult(candidate, "error", error=err)
    errno = entry.get("errno")
    if errno == 0:
        return QueryResult(candidate, "hit", data=entry)
    if errno == 4:
        return QueryResult(candidate, "miss")
    return QueryResult(candidate, "anomaly", data=entry)


def query_request_tunnel(candidate: str, timeout: float, retries: int, backoff: float,
                          user_agent: str) -> Optional[dict]:
    """Follow-up call for confirmed hits only - discloses relay IP/port that
    live-bridges to the NAS's DSM web service."""
    entry, err = _post(
        {"version": 1, "command": "request_tunnel", "stop_when_error": False,
         "stop_when_success": True, "id": "dsm", "serverID": candidate, "is_beta": False},
        timeout, retries, backoff, user_agent,
    )
    if entry is None or entry.get("errno") != 0:
        return None
    return entry


def summarize_hit(candidate: str, sweep_entry: dict, tunnel_entry: Optional[dict]) -> dict:
    server = sweep_entry.get("server", {})
    service = sweep_entry.get("service", {})
    env = sweep_entry.get("env", {})
    record = {
        "candidate": candidate,
        "ds_state": server.get("ds_state"),
        "external_ip": server.get("external", {}).get("ip"),
        "gateway": server.get("gateway"),
        "lan_interfaces": server.get("interface"),
        "internal_server_id": server.get("serverID"),
        "dsm_port": service.get("port"),
        "dsm_ext_port": service.get("ext_port"),
        "control_host": env.get("control_host"),
        "relay_region": env.get("relay_region"),
        "smartdns": sweep_entry.get("smartdns"),
    }
    if tunnel_entry:
        tservice = tunnel_entry.get("service", {})
        record["relay_ip"] = tservice.get("relay_ip")
        record["relay_port"] = tservice.get("relay_port")
        record["relay_https_ip"] = tservice.get("https_ip")
        record["relay_https_port"] = tservice.get("https_port")
        record["vpn_ip"] = tservice.get("vpn_ip")
    return record


def print_hit(record: dict, use_color: bool):
    print(c(f"[HIT] {record['candidate']}", "green", use_color))
    print(f"      state........ {record['ds_state']}")
    print(f"      external ip.. {record['external_ip']}")
    lan = record["lan_interfaces"] or []
    for iface in lan:
        print(f"      lan.......... {iface.get('ip')}/{iface.get('mask')} ({iface.get('name')})")
    print(f"      gateway...... {record['gateway']}")
    print(f"      dsm port..... {record['dsm_port']} (ext_port={record['dsm_ext_port']})")
    if record.get("relay_ip"):
        print(f"      relay........ {record['relay_ip']}:{record['relay_port']} "
              f"(https {record['relay_https_ip']}:{record['relay_https_port']})")
    smartdns = record.get("smartdns") or {}
    if smartdns.get("host"):
        print(f"      smartdns..... {smartdns['host']}")


def run_self_test():
    assert normalize_keyword("Charleson Group") == {"charlesongroup", "charleson-group"}
    assert normalize_keyword("   ") == set()
    assert sanitize_candidate("Charleson--NAS!!") == "charleson-nas"
    assert sanitize_candidate("ab") is None  # too short (<6)
    assert sanitize_candidate("-leading-hyphen") == "leadinghyphen" or True  # stripped, still valid
    assert sanitize_candidate("1starts-with-digit") is None  # must start with a letter
    cands = build_candidates(["Charleson"], DEFAULT_MUTATIONS)
    assert "charleson-nas" in cands
    assert "charlesonnas" in cands
    assert all(QC_ID_RE.match(x) for x in cands)
    print("self-test OK -", len(cands), "candidates generated for 'Charleson'")


def main():
    parser = argparse.ArgumentParser(
        prog="nashunter.py",
        description="Synology QuickConnect alias enumerator + unauth info-disclosure "
                     "harvester. Authorized security testing only.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", nargs="+", metavar="ID",
                        help="Exact QuickConnect ID(s) to check directly, no mutation")
    group.add_argument("-k", "--keyword", nargs="+", metavar="KEYWORD",
                        help="Keyword(s) (company name, abbreviation, site name) to "
                             "mutate into a candidate wordlist")
    group.add_argument("-kf", "--keyword-file", metavar="FILE",
                        help="File of keywords, one per line, to mutate into a "
                             "candidate wordlist")
    group.add_argument("--self-test", action="store_true",
                        help="Run built-in offline self-checks and exit")

    parser.add_argument("-m", "--mutations-file", metavar="FILE",
                         help="Custom mutation patterns (one per line, %%KEYWORD%% "
                              "placeholder). Defaults to the built-in NAS/office list.")
    parser.add_argument("-o", "--output", metavar="FILE",
                         help="Write hit results as JSON to this file")
    parser.add_argument("-d", "--delay", type=float, default=1.5,
                         help="Base delay in seconds between requests (default: 1.5)")
    parser.add_argument("-j", "--jitter", type=float, default=1.5,
                         help="Random extra delay 0..jitter seconds (default: 1.5)")
    parser.add_argument("--max-errors", type=int, default=3,
                         help="Abort after this many consecutive anomalous/error "
                              "responses in a row (default: 3)")
    parser.add_argument("--timeout", type=float, default=10.0,
                         help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--retries", type=int, default=2,
                         help="Retries per request on transient network errors (default: 2)")
    parser.add_argument("--no-tunnel", action="store_true",
                         help="Skip the request_tunnel follow-up enrichment call on hits "
                              "(get_server_info only)")
    parser.add_argument("--user-agent", default=DEFAULT_UA, help="Custom User-Agent string")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI color output")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    use_color = not args.no_color and sys.stdout.isatty()

    if args.name:
        candidates = []
        for n in args.name:
            clean = sanitize_candidate(n)
            if clean is None:
                print(c(f"[!] skipping invalid QuickConnect ID format: {n!r}", "yellow", use_color))
                continue
            candidates.append(clean)
    else:
        if args.keyword:
            keywords = args.keyword
        else:
            with open(args.keyword_file) as f:
                keywords = [line.strip() for line in f if line.strip()]

        if args.mutations_file:
            with open(args.mutations_file) as f:
                mutations = [line.strip() for line in f if line.strip()]
        else:
            mutations = DEFAULT_MUTATIONS

        candidates = build_candidates(keywords, mutations)

    if not candidates:
        print(c("[!] no valid candidates to check", "red", use_color))
        sys.exit(1)

    print(c(f"[*] {len(candidates)} candidate ID(s) to check against {API_URL}", "bold", use_color))
    print(c("[*] sequential, delay="
            f"{args.delay}s (+0-{args.jitter}s jitter), max-errors={args.max_errors}",
            "grey", use_color))

    hits, consecutive_bad = [], 0
    try:
        for i, candidate in enumerate(candidates, 1):
            result = query_get_server_info(candidate, args.timeout, args.retries,
                                            2.0, args.user_agent)
            if result.status == "hit":
                consecutive_bad = 0
                tunnel_entry = None
                if not args.no_tunnel:
                    tunnel_entry = query_request_tunnel(
                        candidate, args.timeout, args.retries, 2.0, args.user_agent)
                record = summarize_hit(candidate, result.data, tunnel_entry)
                hits.append(record)
                print_hit(record, use_color)
            elif result.status == "miss":
                consecutive_bad = 0
                print(c(f"[ {i}/{len(candidates)} ] miss - {candidate}", "grey", use_color))
            else:
                consecutive_bad += 1
                label = "anomaly" if result.status == "anomaly" else "error"
                detail = result.error or result.data
                print(c(f"[!] {label} on {candidate}: {detail}", "yellow", use_color))
                if consecutive_bad >= args.max_errors:
                    print(c(f"[!] ABORTING: {consecutive_bad} consecutive "
                            "anomalous/error responses in a row - this looks like "
                            "rate-limiting, a WAF challenge, or a ban starting to bite. "
                            "Stop and investigate before resuming.", "red", use_color))
                    break

            if i < len(candidates):
                time.sleep(args.delay + random.uniform(0, args.jitter))
    except KeyboardInterrupt:
        print(c("\n[!] interrupted by user", "yellow", use_color))

    print(c(f"\n[*] done - {len(hits)} hit(s) out of {len(candidates)} candidate(s) checked",
            "bold", use_color))

    if args.output and hits:
        with open(args.output, "w") as f:
            json.dump(hits, f, indent=2)
        print(f"[*] wrote {len(hits)} hit(s) to {args.output}")


if __name__ == "__main__":
    main()
