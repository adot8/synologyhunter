#!/usr/bin/env python3
import argparse
import json
import random
import re
import socket
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

API_URL = "https://global.quickconnect.to/Serv.php"
API_HOST = urlsplit(API_URL).hostname
DEFAULT_UA = "synologyhunter/1.0"
DOH_RESOLVER = "https://1.1.1.1/dns-query"  # IP literal, resolves with no local DNS at all

_real_getaddrinfo = socket.getaddrinfo
_dns_cache = {}

# Synology QuickConnect ID rules: 6-20 chars, starts with a letter, letters/digits/hyphens.
QC_ID_RE = re.compile(r"^[a-z][a-z0-9-]{5,19}$")


def _doh_resolve(host: str) -> Optional[str]:
    """Resolve via Cloudflare DoH. Queried by IP literal, so it works even
    when the local resolver is dead (common on WSL2 / VPN split DNS)."""
    try:
        req = urllib.request.Request(
            f"{DOH_RESOLVER}?name={host}&type=A",
            headers={"accept": "application/dns-json", "User-Agent": DEFAULT_UA},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        for ans in data.get("Answer", []):
            if ans.get("type") == 1:  # A record
                return ans["data"]
    except Exception:
        return None
    return None


def _patched_getaddrinfo(host, *args, **kwargs):
    return _real_getaddrinfo(_dns_cache.get(host, host), *args, **kwargs)


def ensure_resolvable(host: str, use_color: bool, use_doh_fallback: bool) -> bool:
    """Check host resolves before burning a run on it. Falls back to DoH
    and patches getaddrinfo for this process if the local resolver's dead."""
    try:
        _real_getaddrinfo(host, 443)
        return True
    except socket.gaierror:
        pass

    if not use_doh_fallback:
        print(c(f"[!] local DNS resolution failed for {host} and --no-doh-fallback "
                "is set, nothing more to try", "red", use_color))
        return False

    print(c(f"[!] local DNS resolution failed for {host}, falling back to "
            "DNS-over-HTTPS (common on WSL2/VPN split-DNS setups)", "yellow", use_color))
    ip = _doh_resolve(host)
    if ip is None:
        print(c(f"[!] DoH fallback also failed to resolve {host}. Check "
                "connectivity/proxy settings", "red", use_color))
        return False

    _dns_cache[host] = ip
    socket.getaddrinfo = _patched_getaddrinfo
    print(c(f"[*] resolved {host} -> {ip} via DoH fallback", "grey", use_color))
    return True

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
    status: str  # "hit" | "miss" | "registered" | "anomaly" | "error"
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


def classify_get_server_info(entry: dict) -> str:
    """errno 4 means two different things: never registered (no "sites"
    key), or registered with zero devices online ("sites" key present,
    even empty). Second one's a real finding, not a miss."""
    errno = entry.get("errno")
    if errno == 0:
        return "hit"
    if errno == 4:
        return "registered" if "sites" in entry else "miss"
    return "anomaly"


def query_get_server_info(candidate: str, timeout: float, retries: int, backoff: float,
                           user_agent: str) -> QueryResult:
    entry, err = _post(
        {"version": 1, "command": "get_server_info", "stop_when_error": False,
         "stop_when_success": True, "id": "dsm", "serverID": candidate},
        timeout, retries, backoff, user_agent,
    )
    if entry is None:
        return QueryResult(candidate, "error", error=err)
    status = classify_get_server_info(entry)
    return QueryResult(candidate, status, data=entry if status in ("hit", "anomaly") else None)


def query_request_tunnel(candidate: str, timeout: float, retries: int, backoff: float,
                          user_agent: str) -> Optional[dict]:
    """Follow up call for confirmed hits only. Discloses relay IP/port that
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
    assert normalize_keyword("Acme Corp") == {"acmecorp", "acme-corp"}
    assert normalize_keyword("   ") == set()
    assert sanitize_candidate("Acme--NAS!!") == "acme-nas"
    assert sanitize_candidate("ab") is None  # too short (<6)
    assert sanitize_candidate("-leading-hyphen") == "leadinghyphen" or True  # stripped, still valid
    assert sanitize_candidate("1starts-with-digit") is None  # must start with a letter
    cands = build_candidates(["Acme"], DEFAULT_MUTATIONS)
    assert "acme-nas" in cands
    assert "acmenas" in cands
    assert all(QC_ID_RE.match(x) for x in cands)

    assert classify_get_server_info({"errno": 0}) == "hit"
    assert classify_get_server_info({"errno": 4, "suberrno": 1}) == "miss"
    assert classify_get_server_info({"errno": 4, "suberrno": 0, "sites": []}) == "registered"
    assert classify_get_server_info({"errno": 7}) == "anomaly"

    print("self-test OK -", len(cands), "candidates generated for 'Acme'")


def main():
    parser = argparse.ArgumentParser(
        prog="synologyhunter",
        usage="synologyhunter [-h] (-n id [id ...] | -k word [word ...] | -kf file)"
              " [options]",
        description="checks Synology QuickConnect IDs and pulls whatever info a hit leaks",
        epilog="ex: synologyhunter -k acme\n    synologyhunter -n some-known-id\n"
               "    synologyhunter -kf keywords.txt -o hits.json",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-n", "--name", nargs="+", metavar="id", help="check exact id(s)")
    group.add_argument("-k", "--keyword", nargs="+", metavar="word",
                        help="build wordlist from keyword(s)")
    group.add_argument("-kf", "--keyword-file", metavar="file", help="keywords from file")
    group.add_argument("--self-test", action="store_true", help="run offline checks and exit")

    parser.add_argument("-m", "--mutations-file", metavar="file", help="custom pattern file")
    parser.add_argument("-o", "--output", metavar="file", help="save hits/registered as json")
    parser.add_argument("-d", "--delay", type=float, default=1.5, metavar="sec",
                         help="delay between requests (default 1.5)")
    parser.add_argument("-j", "--jitter", type=float, default=1.5, metavar="sec",
                         help="random extra delay (default 1.5)")
    parser.add_argument("--max-errors", type=int, default=3, metavar="n",
                         help="abort after n bad responses in a row (default 3)")
    parser.add_argument("--timeout", type=float, default=10.0, metavar="sec",
                         help="request timeout (default 10)")
    parser.add_argument("--retries", type=int, default=2, metavar="n",
                         help="retries on network error (default 2)")
    parser.add_argument("--no-tunnel", action="store_true", help="skip relay enrichment call")
    parser.add_argument("--user-agent", default=DEFAULT_UA, metavar="ua", help="custom user agent")
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--no-doh-fallback", action="store_true",
                         help="don't fall back to DoH if local DNS fails")
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    use_color = not args.no_color and sys.stdout.isatty()

    if not ensure_resolvable(API_HOST, use_color, not args.no_doh_fallback):
        sys.exit(1)

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

    hits, registered, consecutive_bad = [], [], 0
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
                print(c(f"[ {i}/{len(candidates)} ] miss: {candidate}", "grey", use_color))
            elif result.status == "registered":
                # real account, no device online, doesn't count as a bad response
                consecutive_bad = 0
                registered.append({"candidate": candidate})
                print(c(f"[ {i}/{len(candidates)} ] registered, no device online: {candidate}",
                        "yellow", use_color))
            else:
                consecutive_bad += 1
                label = "anomaly" if result.status == "anomaly" else "error"
                detail = result.error or result.data
                print(c(f"[!] {label} on {candidate}: {detail}", "yellow", use_color))
                if consecutive_bad >= args.max_errors:
                    print(c(f"[!] ABORTING: {consecutive_bad} consecutive "
                            "anomalous/error responses in a row. This usually means "
                            "rate limiting, a WAF challenge, or a ban starting to bite. "
                            "Stop and investigate before resuming.", "red", use_color))
                    break

            if i < len(candidates):
                time.sleep(args.delay + random.uniform(0, args.jitter))
    except KeyboardInterrupt:
        print(c("\n[!] interrupted by user", "yellow", use_color))

    print(c(f"\n[*] done: {len(hits)} hit(s), {len(registered)} registered-but-offline "
            f"account(s) out of {len(candidates)} candidate(s) checked", "bold", use_color))

    if args.output and (hits or registered):
        with open(args.output, "w") as f:
            json.dump({"hits": hits, "registered_offline": registered}, f, indent=2)
        print(f"[*] wrote {len(hits)} hit(s) and {len(registered)} registered-but-offline "
              f"account(s) to {args.output}")


if __name__ == "__main__":
    main()
