"""Detailed fix guidance for each check, attached to findings when results are read.

Keeping this apart from stored scan results means improved guidance also applies
to old scans. {domain} and {host} in text are filled in per domain.
"""

RFC = "https://www.rfc-editor.org/rfc/rfc"
OWASP = "https://cheatsheetseries.owasp.org/cheatsheets/"
MDN = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
MOZILLA_TLS = "https://ssl-config.mozilla.org/"

GUIDE = {
    # ---------------------------------------------------------- DNS
    "ns": {
        "why": "If your only nameserver fails, the domain's website and email stop resolving.",
        "steps": ["In your DNS provider, find the nameservers assigned to the zone.",
                  "Make sure at least two are listed at your registrar, ideally on separate networks.",
                  "Wait for the parent zone's TTL to expire, then verify."],
        "verify": "dig +short NS {domain}",
        "references": [RFC + "1034"],
    },
    "dnssec": {
        "why": "Without DNSSEC, resolvers can't tell whether a DNS answer is genuine, so forged answers can send users or mail to an attacker.",
        "steps": ["Turn on DNSSEC signing in your DNS provider. Most managed providers do this with one setting.",
                  "Copy the DS record the provider generates.",
                  "Add the DS record at your registrar.",
                  "Wait for it to publish, then verify. Remove the old DS record first if you ever change DNS provider, or the domain will stop resolving."],
        "verify": "dig +short DS {domain}\ndig +dnssec {domain} SOA   # look for the 'ad' flag",
        "references": [RFC + "4033"],
    },
    "caa": {
        "why": "CAA tells certificate authorities who may issue certificates for your domain, which narrows the risk of a mis-issued certificate.",
        "steps": ["List every CA you use, including those behind your CDN and hosted platforms. Check issuers in your current certificates.",
                  "Add one CAA 'issue' record per CA at the top of the domain.",
                  "Optionally add an 'iodef' address to receive reports of refused requests.",
                  "Renew a test certificate to confirm issuance still works."],
        "example": '{domain}. CAA 0 issue "letsencrypt.org"\n{domain}. CAA 0 issuewild ";"\n{domain}. CAA 0 iodef "mailto:security@{domain}"',
        "verify": "dig +short CAA {domain}",
        "references": [RFC + "8659"],
    },
    # ---------------------------------------------------------- email
    "spf": {
        "why": "SPF lists the servers allowed to send mail for your domain. Without an enforcing record, spoofed phishing mail is more likely to reach inboxes.",
        "steps": ["List everything that sends mail as this domain: mail provider, marketing tools, ticketing systems, servers.",
                  "Publish exactly one TXT record starting v=spf1 that includes all of them.",
                  "End it with ~all while testing, then -all once DMARC reports look clean.",
                  'If the domain sends no mail, publish "v=spf1 -all".'],
        "example": '{domain}. TXT "v=spf1 include:_spf.google.com include:sendgrid.net ~all"\n\n; A domain that sends no mail:\n{domain}. TXT "v=spf1 -all"',
        "verify": "dig +short TXT {domain} | grep spf1",
        "references": [RFC + "7208"],
    },
    "spf-lookups": {
        "why": "SPF allows 10 DNS lookups. Beyond that, receivers can treat SPF as failed and reject legitimate mail.",
        "steps": ["Remove includes for services you no longer use.",
                  "Replace 'a', 'mx' and 'ptr' terms with explicit ip4: or ip6: ranges where those addresses are stable.",
                  "Move separate senders onto subdomains, each with its own SPF record.",
                  "Consider a maintained SPF flattening service only if the steps above aren't enough."],
        "verify": "dig +short TXT {domain} | grep spf1",
        "references": [RFC + "7208#section-4.6.4"],
    },
    "dmarc": {
        "why": "DMARC tells receivers what to do with mail that fails authentication. Without an enforcing policy, attackers can send convincing mail from your exact domain.",
        "steps": ["Make sure SPF and DKIM are set up for every legitimate sender.",
                  "Publish a p=none record with a rua report address and review reports for 2 to 4 weeks.",
                  "Fix any legitimate sender that fails, then move to p=quarantine.",
                  "When reports stay clean, move to p=reject."],
        "example": '_dmarc.{domain}. TXT "v=DMARC1; p=none; rua=mailto:dmarc@{domain}"\n\n; End state:\n_dmarc.{domain}. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
        "verify": "dig +short TXT _dmarc.{domain}",
        "references": [RFC + "7489"],
    },
    "dmarc-pct": {
        "why": "With pct below 100, the policy is applied to only part of failing mail, so some spoofed messages still get through.",
        "steps": ["Check reports for legitimate senders still failing.", "Raise pct in stages, then remove the tag so the default of 100 applies."],
        "verify": "dig +short TXT _dmarc.{domain}",
        "references": [RFC + "7489"],
    },
    "dmarc-sp": {
        "why": "sp=none leaves subdomains unprotected, so attackers can spoof names like billing.{domain}.",
        "steps": ["Identify subdomains that send mail and make sure they pass SPF or DKIM.", "Remove sp=none, or set sp=reject."],
        "verify": "dig +short TXT _dmarc.{domain}",
        "references": [RFC + "7489"],
    },
    "dmarc-rua": {
        "why": "Without aggregate reports you can't see who is sending as your domain, or safely tighten the policy.",
        "steps": ["Create a mailbox or use a DMARC reporting service.", "Add rua=mailto:address to the record.",
                  "If the address is on a different domain, that domain must publish an authorization record."],
        "example": '_dmarc.{domain}. TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}"',
        "verify": "dig +short TXT _dmarc.{domain}",
        "references": [RFC + "7489"],
    },
    "dkim": {
        "why": "DKIM cryptographically signs mail. Short keys are weaker against forgery, and DMARC depends on DKIM surviving mail forwarding.",
        "steps": ["If no key was found, read the DKIM-Signature header of a real sent message. The s= value is your selector, which this scan can't guess if it's custom.",
                  "Generate a 2048-bit key in your mail provider's admin console.",
                  "Publish the new key under a new selector, and switch signing to it.",
                  "Remove the old selector after a few days."],
        "verify": "dig +short TXT SELECTOR._domainkey.{domain}",
        "references": [RFC + "6376", RFC + "8301"],
    },
    "mta-sts": {
        "why": "Without MTA-STS, a network attacker can strip encryption from mail in transit to your domain.",
        "steps": ["Publish the policy file below at https://mta-sts.{domain}/.well-known/mta-sts.txt with a valid certificate.",
                  "Start in mode: testing, then change to enforce.",
                  "Add the _mta-sts TXT record, and change its id every time the policy changes.",
                  "Add a TLS-RPT record to receive failure reports."],
        "example": 'version: STSv1\nmode: testing\nmx: mail.{domain}\nmax_age: 604800\n\n_mta-sts.{domain}. TXT "v=STSv1; id=20260101"\n_smtp._tls.{domain}. TXT "v=TLSRPTv1; rua=mailto:tls-reports@{domain}"',
        "verify": "dig +short TXT _mta-sts.{domain}\ncurl -s https://mta-sts.{domain}/.well-known/mta-sts.txt",
        "references": [RFC + "8461", RFC + "8460"],
    },
    # ---------------------------------------------------------- TLS
    "cert": {
        "why": "Browsers show a full-page warning for invalid certificates. Users either leave or learn to click through warnings, which also makes interception easier.",
        "steps": ["Check the error shown beside each affected URL: expired, wrong hostname, self-signed or incomplete chain.",
                  "Issue a certificate from a trusted CA that covers every hostname on the server.",
                  "Install the full chain, including intermediates, and reload the server.",
                  "Automate renewal, for example with Certbot or your load balancer's managed certificates, and alert on expiry 30 days ahead."],
        "example": "sudo certbot --nginx -d {host}\nsudo certbot renew --dry-run",
        "verify": "echo | openssl s_client -connect {host}:443 -servername {host} 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
        "references": ["https://letsencrypt.org/getting-started/"],
    },
    "tls-legacy": {
        "why": "TLS 1.0 and 1.1 were formally deprecated in 2021 and have known weaknesses. PCI DSS also prohibits TLS 1.0 and early TLS for card data.",
        "steps": ["Check logs for clients still using old versions, which is rare outside legacy devices.",
                  "Set the minimum version to TLS 1.2 on the server, load balancer or CDN.",
                  "On Cloudflare, set Minimum TLS Version under SSL/TLS, Edge Certificates.",
                  "Reload and verify."],
        "example": "# nginx\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3",
        "verify": "openssl s_client -connect {host}:443 -tls1_1 </dev/null   # should fail",
        "references": [RFC + "8996", MOZILLA_TLS],
    },
    "tls13": {
        "why": "TLS 1.3 is faster, removes older weak options and always gives forward secrecy.",
        "steps": ["Upgrade to a web server and OpenSSL version that support it (OpenSSL 1.1.1 or later).",
                  "Add TLSv1.3 to the enabled protocols.", "Reload and verify."],
        "example": "# nginx\nssl_protocols TLSv1.2 TLSv1.3;",
        "verify": "openssl s_client -connect {host}:443 -tls1_3 </dev/null",
        "references": [RFC + "8446", MOZILLA_TLS],
    },
    "cipher": {
        "why": "Weak ciphers such as RC4, 3DES and NULL can let an attacker decrypt traffic.",
        "steps": ["Generate a current cipher list with the Mozilla SSL Configuration Generator.",
                  "Apply it to every TLS endpoint, including load balancers.", "Reload and verify."],
        "example": "# nginx, TLS 1.2 ciphers from Mozilla's Intermediate profile\nssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;",
        "verify": "openssl s_client -connect {host}:443 -tls1_2 -cipher '3DES:RC4:NULL' </dev/null   # should fail",
        "references": [MOZILLA_TLS],
    },
    # ---------------------------------------------------------- web
    "https": {
        "why": "Without HTTPS, anyone on the network path can read or change what users see and send.",
        "steps": ["Obtain a certificate, for example free from Let's Encrypt or through your CDN.",
                  "Configure the site to serve on port 443.", "Then redirect HTTP to HTTPS and enable HSTS."],
        "example": "sudo certbot --nginx -d {host}",
        "verify": "curl -sI https://{host}/ | head -1",
        "references": ["https://letsencrypt.org/getting-started/"],
    },
    "redirect": {
        "why": "A first visit over HTTP can be intercepted, stripping HTTPS for the whole session.",
        "steps": ["Add a permanent redirect on port 80 for every hostname.",
                  "Fix any internal links that still use http://.", "Enable HSTS after the redirect works."],
        "example": "# nginx\nserver {\n    listen 80;\n    server_name {host};\n    return 301 https://$host$request_uri;\n}",
        "verify": "curl -sI http://{host}/ | grep -iE '^(HTTP|location)'",
        "references": [OWASP + "Transport_Layer_Security_Cheat_Sheet.html"],
    },
    "hsts": {
        "why": "HSTS makes browsers refuse plain HTTP for your site, blocking downgrade attacks after the first visit.",
        "steps": ["Confirm all content works over HTTPS.",
                  "Start with a short max-age such as 300 and raise it step by step to one year.",
                  "Add includeSubDomains only once every subdomain supports HTTPS, because browsers will refuse those that don't."],
        "example": '# nginx\nadd_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n\n# Apache\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"',
        "verify": "curl -sI https://{host}/ | grep -i strict-transport",
        "references": [OWASP + "HTTP_Strict_Transport_Security_Cheat_Sheet.html", MDN + "Strict-Transport-Security"],
    },
    "csp": {
        "why": "CSP limits which scripts can run, so a cross-site scripting bug is much harder to exploit.",
        "steps": ["Deploy in report-only mode first, so nothing breaks.",
                  "Review violations for 1 to 2 weeks and add the sources you actually need.",
                  "Replace inline scripts with external files, nonces or hashes rather than allowing 'unsafe-inline'.",
                  "Switch the header to Content-Security-Policy to enforce it."],
        "example": "# nginx, test first\nadd_header Content-Security-Policy-Report-Only \"default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'\" always;",
        "verify": "curl -sI https://{host}/ | grep -i content-security",
        "references": [OWASP + "Content_Security_Policy_Cheat_Sheet.html", MDN + "Content-Security-Policy"],
    },
    "framing": {
        "why": "If other sites can embed your pages in a frame, they can trick users into clicking hidden buttons (clickjacking).",
        "steps": ["Decide whether any other site legitimately embeds these pages.",
                  "Set frame-ancestors in your CSP, and X-Frame-Options for older browsers.", "Reload and verify."],
        "example": "# nginx\nadd_header Content-Security-Policy \"frame-ancestors 'self'\" always;\nadd_header X-Frame-Options \"SAMEORIGIN\" always;",
        "verify": "curl -sI https://{host}/ | grep -iE 'x-frame|frame-ancestors'",
        "references": [OWASP + "Clickjacking_Defense_Cheat_Sheet.html"],
    },
    "nosniff": {
        "why": "Without it, browsers may guess file types and run an uploaded file as a script.",
        "steps": ["Add the header on all responses.", "Check that your server sends correct Content-Type values, since browsers now rely on them."],
        "example": '# nginx\nadd_header X-Content-Type-Options "nosniff" always;',
        "verify": "curl -sI https://{host}/ | grep -i x-content-type",
        "references": [MDN + "X-Content-Type-Options"],
    },
    "referrer": {
        "why": "Full URLs can leak to other sites through the Referer header, including tokens or private paths.",
        "steps": ["Add the header on all responses.", "Check any analytics or partner integration that relies on referrer data."],
        "example": '# nginx\nadd_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "verify": "curl -sI https://{host}/ | grep -i referrer-policy",
        "references": [MDN + "Referrer-Policy"],
    },
    "banner": {
        "why": "Version numbers tell attackers exactly which known vulnerabilities to try. Hiding them helps a little, but patching is the real fix.",
        "steps": ["Check that the software shown is patched.", "Turn off version disclosure on each server and framework.", "Reload and verify."],
        "example": "# nginx\nserver_tokens off;\n\n# Apache\nServerTokens Prod\nServerSignature Off\n\n# PHP (php.ini)\nexpose_php = Off",
        "verify": "curl -sI https://{host}/ | grep -iE '^(server|x-powered-by)'",
        "references": [OWASP + "HTTP_Headers_Cheat_Sheet.html"],
    },
    "cookie-secure": {
        "why": "Cookies without Secure can be sent over plain HTTP, where they can be stolen.",
        "steps": ["Use the cookie names shown beside each URL to find what sets them: your app, framework or a third party.",
                  "Add the Secure attribute. Most frameworks have a session setting for it.", "Log in again and verify."],
        "example": "Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "verify": "curl -sI https://{host}/ | grep -i set-cookie",
        "references": [OWASP + "Session_Management_Cheat_Sheet.html"],
    },
    "cookie-httponly": {
        "why": "A script injected through XSS can read session cookies without HttpOnly and hijack the session.",
        "steps": ["Enable HttpOnly in your framework's session settings.", "Check that no front-end code needs to read the cookie.", "Log in again and verify."],
        "example": "Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "verify": "curl -sI https://{host}/ | grep -i set-cookie",
        "references": [OWASP + "Session_Management_Cheat_Sheet.html"],
    },
    "cookie-samesite": {
        "why": "SameSite limits cookies on cross-site requests, which reduces cross-site request forgery.",
        "steps": ["Set SameSite=Lax for most cookies, or Strict for sensitive ones.",
                  "Use SameSite=None; Secure only for cookies that must work across sites, such as embedded widgets.",
                  "Test login and any single sign-on flow."],
        "example": "Set-Cookie: session=abc; Path=/; Secure; HttpOnly; SameSite=Lax",
        "verify": "curl -sI https://{host}/ | grep -i set-cookie",
        "references": [MDN + "Set-Cookie"],
    },
    "security-txt": {
        "why": "A security.txt file tells researchers how to report a vulnerability, so reports reach you and not the public.",
        "steps": ["Choose a monitored contact address.", "Publish the file below, with an expiry under a year away.", "Set a reminder to renew it."],
        "example": "# https://{host}/.well-known/security.txt\nContact: mailto:security@{domain}\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en",
        "verify": "curl -s https://{host}/.well-known/security.txt",
        "references": [RFC + "9116", "https://securitytxt.org/"],
    },
    # ---------------------------------------------------------- attack surface
    "dangling": {
        "why": "A CNAME pointing to a deleted service can let an attacker claim that service and serve content from your subdomain, including phishing or cookie theft.",
        "steps": ["For each record listed, check whether the service is still needed.",
                  "If not, delete the CNAME from DNS. This is the safe default.",
                  "If so, re-create or reclaim the target first, before anyone else can.",
                  "Add DNS cleanup to your process for retiring services."],
        "verify": "dig CNAME SUBDOMAIN.{domain}",
        "references": ["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover"],
    },
    "sensitive": {
        "why": "Admin, development and test systems are often less patched and may hold real data. This finding is based on the hostname, so each one needs a manual look.",
        "steps": ["Open each URL listed and confirm what it is and who owns it.",
                  "Delete systems nobody needs, along with their DNS records.",
                  "Put the rest behind a VPN or SSO, or an IP allowlist.",
                  "Make sure test systems don't hold production data or credentials."],
        "references": [OWASP + "Authentication_Cheat_Sheet.html"],
    },
    "private-ip": {
        "why": "Public records with internal addresses reveal your network layout to anyone.",
        "steps": ["Move these records to internal-only DNS (split-horizon).", "Delete them from the public zone.", "Confirm internal users can still resolve them."],
        "verify": "dig +short A HOSTNAME @1.1.1.1   # should return nothing",
    },
    "exposed": {
        "why": "These files can reveal source code, passwords and API keys. Treat any exposed secret as already stolen.",
        "steps": ["Block the path at the web server immediately.",
                  "Remove the file from the web root and from your deployment process.",
                  "Rotate every password, key and token the file contained.",
                  "Review access logs for earlier downloads of the path, and handle any as a security incident."],
        "example": "# nginx: block hidden files, but keep .well-known\nlocation ~ /\\.(?!well-known) {\n    deny all;\n}",
        "verify": "curl -s -o /dev/null -w '%{http_code}\\n' https://{host}/.env   # expect 403 or 404",
        "references": [OWASP + "Secrets_Management_Cheat_Sheet.html"],
    },
    # ---------------------------------------------------------- ports
    "ports": {
        "why": "Databases and remote-access services on the open internet are prime targets for password guessing and exploits.",
        "steps": ["Confirm each listed service is really exposed, as Shodan's data can be weeks old (see the command below).",
                  "Close the port in your firewall or cloud security group if it isn't needed publicly.",
                  "Allow access only through a VPN, bastion host or an IP allowlist.",
                  "Bind databases to private addresses, and turn on authentication.",
                  "Check logs for unauthorized access, especially if there was no password."],
        "example": "# Linux firewall (ufw): allow one admin network, then block everyone else\nsudo ufw allow from 203.0.113.0/24 to any port 3306 proto tcp\nsudo ufw deny 3306/tcp",
        "verify": "nc -vz -w 5 IP_ADDRESS PORT   # only test systems you're authorized to",
    },
    # ---------------------------------------------------------- patching
    "cve": {
        "why": "Attackers scan for known vulnerabilities at scale. Vulnerabilities on CISA's exploited list are being used in real attacks.",
        "steps": ["Find the software and exact version on each listed IP. Shodan infers CVEs from banners, so this may be a false positive.",
                  "Open each CVE link and compare it with your version. Check your vendor's advisory too, since distributions often backport fixes without changing the version number.",
                  "Patch or upgrade, starting with known-exploited and then the highest CVSS.",
                  "If you can't patch straight away, restrict access or add a WAF rule.",
                  "For a known-exploited CVE that really applies, check the host for signs of compromise."],
        "verify": "# On the server:\napt list --installed 2>/dev/null | grep PACKAGE   # or: rpm -q PACKAGE",
        "references": ["https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "https://nvd.nist.gov/"],
    },
    "eol": {
        "why": "End-of-life software gets no more security fixes, so new vulnerabilities stay open permanently.",
        "steps": ["Identify the product and version on each listed host.", "Check the support dates at endoflife.date.",
                  "Plan an upgrade to a supported release, or migrate away.",
                  "Until then, restrict network access and consider paid extended support."],
        "references": ["https://endoflife.date/"],
    },
    "self-signed": {
        "why": "Clients can't verify a self-signed certificate, which leaves connections open to interception and teaches users to ignore warnings.",
        "steps": ["Identify the service on each listed IP.", "Install a certificate from a trusted CA, or put the service behind a VPN if it's internal."],
        "verify": "echo | openssl s_client -connect IP_ADDRESS:443 2>/dev/null | openssl x509 -noout -issuer -subject",
        "references": ["https://letsencrypt.org/getting-started/"],
    },
    # ---------------------------------------------------------- reputation
    "tags": {
        "why": "Shodan saw signs of compromise on this address. It could be under attacker control, and this is worth treating as a possible incident until ruled out.",
        "steps": ["Involve your incident response team or provider. Avoid wiping anything before evidence is preserved.",
                  "Confirm who owns the IP, as it may belong to a shared host or a previous tenant.",
                  "Look for unknown processes, accounts and outbound connections.",
                  "Rebuild from a known-good image, rotate credentials, and patch how they got in."],
        "references": ["https://www.cisa.gov/stopransomware"],
    },
    "dnsbl": {
        "why": "Blocklisted IPs have sent spam or been abused, so your mail may be rejected. It can also signal a compromised server.",
        "steps": ["Find the source: check mail logs for compromised accounts and unexpected sending.",
                  "Fix the cause first, or the IP will be listed again.",
                  "Request removal using the listed blocklist's own process.",
                  "If you share the IP with others, ask your provider for a clean one."],
        "references": ["https://www.spamcop.net/bl.shtml", "https://psbl.org/"],
    },
    "threat-feed": {
        "why": "Cloudflare's security resolver blocks this domain as malicious, so many users and companies may be unable to reach it. It may also mean your site has been compromised.",
        "steps": ["Scan the site for injected content, unknown files and new admin accounts.",
                  "Clean or rebuild the site, patch how attackers got in, and rotate credentials.",
                  "Also check Google Search Console's Security Issues report.",
                  "Request a review through Cloudflare Radar's domain categorization feedback."],
        "verify": "dig +short A {domain} @security.cloudflare-dns.com   # 0.0.0.0 means blocked",
        "references": ["https://developers.cloudflare.com/1.1.1.1/"],
    },
}


def guide_for(check):
    """Exact match first, then the family (ports-high, direct-3389, cve-kev, exposed/.env)."""
    if check in GUIDE:
        return GUIDE[check]
    if check.startswith(("ports-", "direct-")):
        return GUIDE["ports"]
    if check.startswith("cve-"):
        return GUIDE["cve"]
    if check.startswith("exposed"):
        return GUIDE["exposed"]
    if check.startswith("cookie"):
        return GUIDE.get(check)
    return None


def _fill(value, domain, host):
    if isinstance(value, list):
        return [_fill(item, domain, host) for item in value]
    return value.replace("{domain}", domain).replace("{host}", host) if isinstance(value, str) else value


def enrich(result):
    """Attach guidance to a scan result's issues. Returns the same result."""
    domain = result.get("domain", "")
    host = result.get("assets", {}).get("primary_host") or domain
    for finding in result.get("findings", []):
        finding.setdefault("affected", [])
        guide = guide_for(finding["check"]) if finding["status"] in ("fail", "unknown") else None
        if guide:
            finding["recommendation"] = {key: _fill(value, domain, host) for key, value in guide.items()}
    return result
