# synologyhunter

synologyhunter checks Synology QuickConnect IDs and pulls whatever info a hit leaks without any authentication. WAN IP, LAN subnet, gateway, DSM port, and a relay endpoint that connects straight to the NAS's DSM login page over the internet with no port forward needed.

Same idea as [cloud_enum](https://github.com/initstring/cloud_enum). Give it a keyword, it builds a wordlist, sprays it against Synology's QuickConnect API and reports what exists.

## Usage

```bash
usage: synologyhunter [-h] (-n id [id ...] | -k word [word ...] | -kf file) [options]

checks Synology QuickConnect IDs and pulls whatever info a hit leaks

options:
  -h, --help            show this help message and exit
  -n, --name id [id ...]
                        check exact id(s)
  -k, --keyword word [word ...]
                        build wordlist from keyword(s)
  -kf, --keyword-file file
                        keywords from file
  --self-test           run offline checks and exit
  -m, --mutations-file file
                        custom pattern file
  -o, --output file     save hits as json
  -d, --delay sec       delay between requests (default 1.5)
  -j, --jitter sec      random extra delay (default 1.5)
  --max-errors n        abort after n bad responses in a row (default 3)
  --timeout sec         request timeout (default 10)
  --retries n           retries on network error (default 2)
  --no-tunnel           skip relay enrichment call
  --user-agent ua       custom user agent
  --no-color            disable colored output
  --no-doh-fallback     don't fall back to DoH if local DNS fails

ex: synologyhunter -k acme
    synologyhunter -n some-known-id
    synologyhunter -kf keywords.txt -o hits.json
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

## Disclaimer

The information and materials provided in this repository are for **educational, research, and authorized testing purposes only**. 

The author is **not responsible for any misuse, damage, or illegal actions** caused by the software, code, or information contained herein. By downloading, cloning, or using any part of this repository, you agree that you are solely responsible for your own actions and compliance with all applicable local, national, and international laws.

**Usage of these tools for attacking targets without prior mutual consent is illegal.** It is the end user's responsibility to obey all applicable laws. The author assumes no liability and is not responsible for any misuse or damage caused by this program.

