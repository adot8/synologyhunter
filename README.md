# nashunter

nashunter checks Synology QuickConnect IDs and pulls whatever info a hit leaks without any authentication. WAN IP, LAN subnet, gateway, DSM port, and a relay endpoint that connects straight to the NAS's DSM login page over the internet with no port forward needed.

Same idea as cloud_enum. Give it a keyword, it builds a wordlist, sprays it against Synology's QuickConnect API and reports what exists.

Read only. It never touches DSM's login page, so no credential guessing, no brute forcing, no lockout testing.

## Installation

```
git clone https://github.com/adot8/nashunter.git && cd nashunter
```

Nothing to install. Just needs Python 3.

## Usage

```bash
./nashunter.py -n some-known-id

./nashunter.py -k acme "acme corp" acmeio

./nashunter.py -kf keywords.txt -o hits.json
```

`-n` checks an exact ID with no mutation. `-k` and `-kf` build a wordlist from keywords using a built in list of NAS and office naming patterns like nas, ds, backup, it, hq, 01. Pass your own list with `-m patterns.txt` using `%KEYWORD%` as the placeholder.

`--self-test` runs the wordlist logic offline with no network calls, good for checking it still works after editing the mutation list.

Every hit gets a second automatic call that pulls the relay IP and port bridging to the NAS. Skip it with `--no-tunnel` if you only want the basic info.

## Rate limiting

global.quickconnect.to is shared Synology infrastructure, not something any one target owns. Getting flagged there follows you to the next target too, so this is slow on purpose. No throttling showed up in testing, but that's not a guarantee at scale.

It runs one request at a time with a random delay between each one. Network errors get retried with backoff. If it sees a few bad responses in a row it stops the whole run instead of hammering something that might be rate limiting or blocking it.

Only run this against keywords tied to something you're actually authorized to test. It hits Synology's servers, not the target's, so random enumeration is out of scope even if the target itself isn't.

## API

```
POST https://global.quickconnect.to/Serv.php
[{"version":1,"command":"get_server_info","stop_when_error":false,
  "stop_when_success":true,"id":"dsm","serverID":"<candidate>"}]
```

errno 4 means the alias doesn't exist. errno 0 with a full server object means it does, and none of it needs auth.
