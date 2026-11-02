# Domain Scorecard

A self-hosted domain security rating dashboard, in the style of SecurityScorecard. It needs only Python 3 and has no packages to install.

```
python3 app.py                         # then open http://127.0.0.1:8765
python3 app.py --domains my-list.txt   # also queue a list at startup
python3 app.py --port 9000             # use another port
python3 -m unittest                    # run the tests
```

Enter one domain, paste a list, or upload a `.txt` or `.csv` file (first column). Results and scan history are stored in `scorecard.db`. To start over, stop the app and delete that file.

## What it checks

| Factor | Weight | Checks | Source |
|---|---|---|---|
| Network & TLS | 20 | Certificate validity and expiry, TLS versions, weak ciphers, risky open ports | TLS handshakes, Shodan InternetDB |
| Patching | 20 | Possible CVEs by CVSS and CISA known-exploited status, end-of-life software | Shodan InternetDB and CVEDB |
| Application security | 15 | HTTPS redirect, HSTS, CSP, framing, cookie flags, version banners, security.txt | Normal web requests |
| Email security | 15 | SPF, DMARC, DKIM at common selectors, MTA-STS | DNS |
| DNS health | 10 | Nameservers, DNSSEC, CAA | DNS |
| IP & domain reputation | 10 | Compromise tags, spam blocklists, malware-domain feed | Shodan, SpamCop, PSBL, Cloudflare |
| Attack surface | 10 | Subdomains from certificate logs, dangling CNAMEs, exposed admin or dev hostnames, internal IPs in public DNS | crt.sh, Cert Spotter, DNS |

**Deep checks** are off by default and require you to confirm you have authorization. They request sensitive paths (`/.git/HEAD`, `/.env` and others) and connect directly to risky ports on the main host. Only use them on domains you own or have written permission to test. Response contents are never stored.

## Issues and fixes

Each issue lists every affected URL or asset, why it matters, fix steps, example config where useful, a command to check the fix, and references. Issues open expanded on the domain page. **All issues** shows them across every domain. **Export issues CSV** gives one row per affected URL.

## After a rescan

Each domain page has a **Changes since the scan** section: issues fixed, partly fixed and new, plus the score change. **Export changes CSV** gives one row per item.

An issue only counts as fixed when the rescan re-tested that item and it passed. If the site was down, returned a bot wall, or the check didn't run, the item appears under **Could not confirm**. CVE and port results come from Shodan, whose data can lag, so confirm those on the server. Deep-check findings need a deep rescan, and the Rescan button runs a normal scan, so run a deep scan from the scan form to confirm them.

## How scoring works

- Each factor starts at 100 and loses points per failed check: critical 40, high 20, medium 10, low 3.
- The same issue on several hosts counts once, however many URLs it affects.
- The total is the weighted average of factors that have data.
- Any critical finding caps the total at 69, and any high finding at 89.
- Grades: A 90+, B 80+, C 70+, D 60+, F below 60.
- A check that couldn't run is shown as "Could not verify". It neither passes nor loses points, and coverage shows how much of the score had data. Under 40% coverage, no grade is given.

This scoring model is this project's own. The scores won't match SecurityScorecard's.

## Limitations

- **Possible CVEs need confirming.** Shodan infers them from version banners, so patched systems can be flagged. Its data can also be weeks old.
- **No Shodan data isn't a clean result.** It's shown as "Could not verify".
- **Limits per scan.** At most 500 subdomains and 100 IPs are checked, and web and TLS checks run on the main host plus 50 live subdomains (sensitive-looking names first). When a limit is hit, the scan lists what wasn't tested.
- **One page per host.** Web checks read each host's home page, so this isn't a site crawl and issues on other pages won't appear.
- **IPv4 only** for IP intelligence. CDN addresses aren't scored for ports or CVEs because they describe the provider.
- **Not covered:** leaked credentials, dark-web chatter, malware sinkhole data and DKIM at custom selectors. These rely on proprietary or paid feeds, or can't be seen from outside.

## Privacy and safety

- Scanned domain names and IPs are sent to Cloudflare and Google DNS, crt.sh, Cert Spotter, Shodan and the blocklist operators. Don't scan names you need to keep confidential.
- The app listens only on `127.0.0.1` and has no login, so don't expose it to a network.
- It refuses requests from other websites, and it won't connect to private or loopback addresses even if a scanned domain or redirect points there.
