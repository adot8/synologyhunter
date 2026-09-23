# nashunter

Synology QuickConnect alias enumerator + unauthenticated info-disclosure harvester.

Sprays candidate QuickConnect IDs against Synology's public relay API
(`global.quickconnect.to`) to find whether a target's NAS is reachable via
`https://quickconnect.to/<id>`, and if it is, pulls whatever unauthenticated
recon data that ID leaks: WAN IP, LAN subnet/gateway, DSM ports, and a relay
endpoint that live-bridges to the NAS's DSM web service over the internet.

Modeled on `cloud_enum`'s approach — keyword -> mutated wordlist -> spray
against a shared provider namespace -> report hits — but for Synology
QuickConnect instead of S3/Azure/GCS buckets.

Does **not** touch DSM's login/auth endpoint. Read-only alias enumeration and
info-disclosure harvesting only — no credential guessing, no brute force, no
lockout testing. That's a separate, explicitly-scoped test (see engagement
notes for the manual `auth.cgi` methodology if needed).

## Usage

```bash
# Check a specific known/suspected ID directly, no mutation
./nashunter.py -n charleson-nas

# Generate a wordlist from keywords and spray it
./nashunter.py -k charleson "charleson group" cgi

# Keywords from a file, custom mutation patterns, save hits to JSON
./nashunter.py -kf keywords.txt -m custom_mutations.txt -o hits.json

# Offline sanity check of the mutation/validation logic (no network calls)
./nashunter.py --self-test
```

`-m`/`--mutations-file` takes one pattern per line with a `%KEYWORD%`
placeholder — extend the built-in NAS/office naming list (`-nas`, `-ds`,
`-backup`, `-it`, `-hq`, `-01`, etc.) for a specific client's naming
conventions if the defaults don't fit.

## Safety / OPSEC — why it's slow by default

`global.quickconnect.to` is **Synology's shared infrastructure**, serving
every Synology customer worldwide — not something owned by any one client.
Burning this IP's reputation against it affects every future engagement, not
just the one you're running. Research notes (2026-09-23): no rate limiting
observed across a 15-request burst from one source IP (no 429, no CAPTCHA/WAF
page), but that's not a guarantee at higher volumes or over a longer
campaign. Defaults are deliberately conservative:

- Sequential requests only, no threading.
- Randomized jitter delay between every request (`-d`/`-j`).
- Exponential backoff + retry on transient network errors.
- A circuit breaker (`--max-errors`, default 3) that **aborts the whole run**
  on repeated non-standard responses — HTTP errors, non-JSON bodies,
  unexpected `errno` values. That pattern is the signature of a WAF challenge
  or a ban starting to bite.
- A descriptive, contactable User-Agent (`nashunter/1.0 (+authorized-
  security-research; contact: ajohnson@nullthreat.ca)`) instead of spoofing a
  browser — lower odds of being flagged as malicious traffic, and gives
  Synology's abuse team something honest to look at if they ever go looking.

**Scope:** candidate IDs must only be derived from the authorized target's
own name/keywords. This queries a shared third-party service, not the
client's own infrastructure — don't use this to enumerate random/unrelated
names, only permutations of the specific, in-scope target you have written
authorization to test.

## API notes

```
POST https://global.quickconnect.to/Serv.php
Body: [{"version":1,"command":"get_server_info","stop_when_error":false,
        "stop_when_success":true,"id":"dsm","serverID":"<candidate>"}]

Miss: errno 4, errinfo "...[Alias not found]"
Hit:  errno 0, full server/service/smartdns object, no auth required
```

A follow-up `request_tunnel` call (made automatically for confirmed hits,
skip with `--no-tunnel`) additionally discloses a relay IP/port that
live-bridges to the NAS's DSM web service.
