"""Domain security scanner. Python standard library only.

Default checks are non-intrusive: public data sources (DNS, certificate
transparency, Shodan InternetDB) plus the ordinary HTTPS requests and TLS
handshakes any browser would make. Deep checks (sensitive-path requests and
direct port connections) run only when a scan is explicitly marked as authorized.

A check that could not run is reported as "unknown". It never counts as a pass.
"""
import base64
import binascii
import concurrent.futures as cf
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import warnings

USER_AGENT = "domain-scorecard/1.0 (self-hosted security rating)"
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$")

FACTORS = {
    "network": ("Network & TLS", 20),
    "patching": ("Patching", 20),
    "web": ("Application security", 15),
    "email": ("Email security", 15),
    "dns": ("DNS health", 10),
    "reputation": ("IP & domain reputation", 10),
    "surface": ("Attack surface", 10),
}
DEDUCTION = {"critical": 40, "high": 20, "medium": 10, "low": 3, "info": 0}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

RISKY_PORTS = {
    21: ("FTP", "medium"), 23: ("Telnet", "high"), 135: ("MS-RPC", "high"),
    139: ("NetBIOS", "high"), 445: ("SMB", "critical"), 1433: ("MS SQL", "high"),
    1521: ("Oracle DB", "high"), 2375: ("Docker API", "critical"),
    3306: ("MySQL", "high"), 3389: ("RDP", "high"), 5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"), 5985: ("WinRM", "high"), 6379: ("Redis", "critical"),
    9200: ("Elasticsearch", "critical"), 11211: ("Memcached", "high"),
    27017: ("MongoDB", "critical"),
}
SENSITIVE_LABELS = {
    "admin", "administrator", "backup", "beta", "confluence", "demo", "dev",
    "develop", "development", "git", "gitlab", "grafana", "internal", "intranet",
    "jenkins", "jira", "kibana", "old", "phpmyadmin", "preprod", "qa", "sandbox",
    "stage", "staging", "test", "testing", "uat",
}
DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2",
    "dkim", "mail", "smtp", "mandrill", "mxvault", "zoho", "protonmail", "sendgrid",
]
BAD_TAGS = {"compromised", "malware", "c2", "botnet", "doublepulsar"}
SHARED_CPE = ("cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva")
MAX_SUBDOMAINS = 500
MAX_IPS = 100
MAX_CVE_LOOKUPS = 300
MAX_HOST_CHECKS = 50


class ScanError(Exception):
    """The scan cannot produce a result at all."""


class LookupFailed(Exception):
    """A single data source or lookup failed."""


class BlockedTarget(Exception):
    """A hostname resolved to a non-public address, so it must not be contacted."""


def normalize_domain(raw):
    """Turn user input (URL, host, host:port) into a bare domain, or None if invalid."""
    value = (raw or "").strip().strip("\"'").lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0].split("@")[-1]
    value = value.split(":")[0].rstrip(".")
    if value.startswith("*."):
        value = value[2:]
    if value.startswith("www."):
        value = value[4:]
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return value if DOMAIN_RE.match(value) else None


# ---------------------------------------------------------------- scoring

def grade_for(score):
    if score is None:
        return None
    for floor, letter in ((90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= floor:
            return letter
    return "F"


def compute_scores(findings):
    """Each factor starts at 100 and loses points per failed check.

    A factor with only unknown results has no score and is left out of the
    weighted average. Any critical finding caps the total at 69, any high at 89,
    so a serious problem can't be averaged away. Below 40% coverage no grade is given.
    """
    factors = {}
    for key, (name, weight) in FACTORS.items():
        rows = [f for f in findings if f["factor"] == key]
        scored = [f for f in rows if f["status"] in ("pass", "fail")]
        lost = sum(DEDUCTION[f["severity"]] for f in rows if f["status"] == "fail")
        score = max(0, 100 - lost) if scored else None
        factors[key] = {
            "name": name, "weight": weight, "score": score, "grade": grade_for(score),
            "failed": sum(f["status"] == "fail" for f in rows),
            "passed": sum(f["status"] == "pass" for f in rows),
            "unknown": sum(f["status"] == "unknown" for f in rows),
        }
    known = [f for f in factors.values() if f["score"] is not None]
    coverage = sum(f["weight"] for f in known)
    if coverage < 40:
        return {"score": None, "grade": None, "coverage": coverage, "factors": factors}
    total = round(sum(f["score"] * f["weight"] for f in known) / coverage)
    failed = [f for f in findings if f["status"] == "fail"]
    if any(f["severity"] == "critical" for f in failed):
        total = min(total, 69)
    elif any(f["severity"] == "high" for f in failed):
        total = min(total, 89)
    return {"score": total, "grade": grade_for(total), "coverage": coverage, "factors": factors}


def asset(label, url=None):
    return {"label": label, "url": url}


def link(url, suffix=""):
    return asset(f"{url} — {suffix}" if suffix else url, url)


class Report:
    """Findings with the same check and outcome merge, collecting every affected asset."""

    def __init__(self):
        self.findings = []
        self._lock = threading.Lock()

    def add(self, factor, check, title, status, severity="info", detail="", fix="", affected=None):
        severity = severity if status == "fail" else "info"
        affected = [(link(a) if a.startswith("http") else asset(a)) if isinstance(a, str) else a for a in affected or []]
        with self._lock:
            for existing in self.findings:
                if (existing["factor"], existing["check"], existing["title"], existing["status"],
                        existing["severity"]) == (factor, check, title, status, severity):
                    known = {a["label"] for a in existing["affected"]}
                    existing["affected"].extend(a for a in affected if a["label"] not in known)
                    return
            self.findings.append({
                "factor": factor, "check": check, "title": title, "status": status, "severity": severity,
                "detail": detail, "fix": fix, "affected": affected,
            })

    def passed(self, factor, check, title, detail="", affected=None):
        self.add(factor, check, title, "pass", detail=detail, affected=affected)

    def failed(self, factor, check, title, severity, detail="", fix="", affected=None):
        self.add(factor, check, title, "fail", severity, detail, fix, affected)

    def unknown(self, factor, check, title, detail=""):
        self.add(factor, check, title, "unknown", detail=detail)

    def note(self, factor, check, title, detail=""):
        self.add(factor, check, title, "info", detail=detail)


class SubdomainReport:
    """For extra hosts: keep real results, but an unreachable subdomain isn't worth reporting."""

    def __init__(self, report):
        self.passed, self.failed = report.passed, report.failed

    def unknown(self, *args, **kwargs):
        pass

    def note(self, *args, **kwargs):
        pass


# ---------------------------------------------------------------- network helpers

def http_json(url, headers=None, timeout=15, max_bytes=40_000_000):
    """GET JSON from a fixed public API. Returns (status, parsed); 404 gives (404, None)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read(max_bytes))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return 404, None
        raise LookupFailed(f"HTTP {exc.code} from {urllib.parse.urlsplit(url).hostname}") from exc
    except (OSError, ValueError, http.client.HTTPException) as exc:
        raise LookupFailed(f"{urllib.parse.urlsplit(url).hostname}: {exc}") from exc


class DnsAnswer:
    def __init__(self, data):
        self.status = data.get("Status", 2)
        self.ad = bool(data.get("AD"))
        self.records = [(r.get("type"), r.get("data", "")) for r in data.get("Answer", []) or []]

    def of_type(self, rtype):
        return [value for kind, value in self.records if kind == rtype]


DNS_TYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "DS": 43, "CAA": 257}
RESOLVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


def dns_query(name, rtype, resolvers=RESOLVERS):
    """DNS over HTTPS with fallback. Raises LookupFailed if no resolver gives a usable answer."""
    params = urllib.parse.urlencode({"name": name, "type": rtype})
    last = "no resolver answered"
    for base in resolvers:
        try:
            _, data = http_json(f"{base}?{params}", {"Accept": "application/dns-json"}, timeout=10)
        except LookupFailed as exc:
            last = str(exc)
            continue
        if data is None:
            continue
        answer = DnsAnswer(data)
        if answer.status in (0, 3):
            return answer
        last = f"DNS status {answer.status} for {name} {rtype}"
    raise LookupFailed(last)


def txt_values(answer):
    values = []
    for raw in answer.of_type(DNS_TYPES["TXT"]):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw)
        values.append("".join(parts) if parts else raw)
    return values


def public_addresses(host):
    """Resolve a host for direct contact. Refuses any non-public address, which
    stops a scanned domain or redirect from steering this app at the local network."""
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise LookupFailed(f"cannot resolve {host}: {exc}") from exc
    addresses = list(dict.fromkeys(info[4][0] for info in infos))
    bad = [a for a in addresses if not ipaddress.ip_address(a).is_global]
    if bad or not addresses:
        raise BlockedTarget(f"{host} resolves to non-public address {', '.join(bad)}")
    return addresses


def open_socket(host, port, timeout):
    last = None
    for address in public_addresses(host):
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            last = exc
    raise last or OSError("no address")


def insecure_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


class Page:
    def __init__(self, url, status, headers, body):
        self.url, self.status, self.body = url, status, body
        self.header_list = [(k.lower(), v) for k, v in headers]
        self.headers = {}
        for key, value in self.header_list:
            self.headers.setdefault(key, value)

    def all(self, name):
        return [v for k, v in self.header_list if k == name]


def fetch(url, max_bytes=65536, timeout=10):
    """One HTTP(S) GET with no redirect following, connecting only to a vetted public IP."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname
    secure = parts.scheme == "https"
    port = parts.port or (443 if secure else 80)
    sock = open_socket(host, port, timeout)
    try:
        if secure:
            sock = insecure_context().wrap_socket(sock, server_hostname=host)
            conn = http.client.HTTPSConnection(host, port, timeout=timeout)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.sock = sock
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
        response = conn.getresponse()
        return Page(url, response.status, response.getheaders(), response.read(max_bytes))
    finally:
        sock.close()


def follow(url, hops=6):
    """Follow redirects manually so each hop's target is vetted. Returns the visited pages."""
    chain = []
    for _ in range(hops):
        page = fetch(url)
        chain.append(page)
        location = page.headers.get("location")
        if page.status not in (301, 302, 303, 307, 308) or not location:
            return chain
        url = urllib.parse.urljoin(url, location)
        if urllib.parse.urlsplit(url).scheme not in ("http", "https"):
            return chain
    return chain


# ---------------------------------------------------------------- DNS checks

def check_dns(domain, report):
    ns = dns_query(domain, "NS").of_type(DNS_TYPES["NS"])
    if not ns:
        # A registered domain without NS wouldn't resolve, so this is a subdomain using its parent's DNS.
        report.note("dns", "ns", "Uses its parent domain's nameservers")
    elif len(ns) < 2:
        report.failed("dns", "ns", "Only one nameserver", "medium", ns[0],
                      "Publish at least two nameservers, ideally on separate networks.")
    else:
        report.passed("dns", "ns", f"{len(ns)} nameservers", ", ".join(sorted(ns)[:6]))

    # A subdomain in a signed zone has no DS of its own, so also accept a validated answer.
    if dns_query(domain, "DS").of_type(DNS_TYPES["DS"]) or dns_query(domain, "SOA").ad:
        report.passed("dns", "dnssec", "DNSSEC is enabled")
    else:
        report.failed("dns", "dnssec", "DNSSEC is not enabled", "low",
                      "No DS record, so DNS answers for this domain can't be authenticated.",
                      "Enable DNSSEC at your DNS provider and publish the DS record at your registrar.")

    # CAA is inherited (RFC 8659): the closest record walking up the tree applies.
    labels = domain.split(".")
    caa_owner = next((".".join(labels[i:]) for i in range(len(labels) - 1)
                      if dns_query(".".join(labels[i:]), "CAA").of_type(DNS_TYPES["CAA"])), None)
    if caa_owner:
        report.passed("dns", "caa", "CAA restricts certificate issuers", f"Record at {caa_owner}")
    else:
        report.failed("dns", "caa", "No CAA record", "low",
                      "Any public certificate authority may issue certificates for this domain.",
                      'Add a CAA record, for example: 0 issue "letsencrypt.org".')


# ---------------------------------------------------------------- email checks

def spf_lookup_count(record, depth=0, seen=None):
    """Count DNS-querying SPF terms recursively. RFC 7208 allows at most 10."""
    seen = seen if seen is not None else set()
    count = 0
    for term in record.split()[1:]:
        term = term.lstrip("+-~?").lower()
        name = term.split(":", 1)[0].split("=", 1)[0].split("/", 1)[0]
        if name in ("a", "mx", "ptr", "exists"):
            count += 1
        elif name in ("include", "redirect"):
            count += 1
            target = re.split(r"[:=]", term, maxsplit=1)[-1]
            if depth < 6 and target not in seen and "%" not in target:
                seen.add(target)
                try:
                    for value in txt_values(dns_query(target, "TXT")):
                        if value.lower().startswith("v=spf1"):
                            count += spf_lookup_count(value, depth + 1, seen)
                except LookupFailed:
                    pass
    return count


def evaluate_spf(txts, has_mail, report, lookups=None):
    records = [t for t in txts if t.lower().startswith("v=spf1")]
    if not records:
        report.failed("email", "spf", "No SPF record", "high" if has_mail else "medium",
                      "Anyone can send mail claiming to be this domain and SPF won't object.",
                      'Publish an SPF record. If the domain sends no mail, use "v=spf1 -all".')
        return
    if len(records) > 1:
        report.failed("email", "spf", "Multiple SPF records", "high",
                      "More than one SPF record makes SPF evaluate to a permanent error.",
                      "Merge them into a single TXT record.")
        return
    record = records[0]
    lowered = record.lower()
    if "+all" in lowered or re.search(r"\sall\b", lowered):
        report.failed("email", "spf", "SPF allows any sender (+all)", "high", record,
                      "Replace +all with -all or ~all.")
    elif "?all" in lowered:
        report.failed("email", "spf", "SPF is neutral (?all)", "medium", record,
                      "Replace ?all with -all or ~all.")
    elif "-all" in lowered or "~all" in lowered or "redirect=" in lowered:
        report.passed("email", "spf", "SPF record is enforcing", record)
    else:
        report.failed("email", "spf", "SPF has no 'all' policy", "medium", record,
                      "End the record with -all or ~all.")
    if lookups is not None and lookups > 10:
        report.failed("email", "spf-lookups", f"SPF needs {lookups} DNS lookups (limit is 10)", "medium",
                      "Receivers may treat SPF as a permanent error, so legitimate mail can fail.",
                      "Remove unused includes or flatten the record.")


def parse_tags(record):
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def evaluate_dmarc(txts, report, inherited_from=None):
    records = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if not records:
        report.failed("email", "dmarc", "No DMARC record", "high",
                      "Spoofed mail using this domain isn't rejected, and you get no reports about it.",
                      'Publish _dmarc TXT "v=DMARC1; p=none; rua=mailto:you@yourdomain", then move to quarantine or reject.')
        return
    if len(records) > 1:
        report.failed("email", "dmarc", "Multiple DMARC records", "high",
                      "Receivers ignore DMARC when more than one record exists.",
                      "Keep one _dmarc TXT record.")
        return
    tags = parse_tags(records[0])
    policy = tags.get("p", "").lower()
    source = f" (inherited from {inherited_from})" if inherited_from else ""
    if policy == "none":
        report.failed("email", "dmarc", "DMARC is monitor-only (p=none)", "medium", records[0] + source,
                      "Review reports, then move to p=quarantine and p=reject.")
    elif policy in ("quarantine", "reject"):
        report.passed("email", "dmarc", f"DMARC is enforcing (p={policy})", records[0] + source)
    else:
        report.failed("email", "dmarc", "DMARC policy is invalid", "high", records[0] + source,
                      "Set p=quarantine or p=reject.")
    if policy in ("quarantine", "reject") and tags.get("pct", "100") != "100":
        report.failed("email", "dmarc-pct", f"DMARC applies to only {tags['pct']}% of mail", "low", "",
                      "Raise pct to 100.")
    if policy in ("quarantine", "reject") and tags.get("sp", "").lower() == "none":
        report.failed("email", "dmarc-sp", "DMARC does not protect subdomains (sp=none)", "low", "",
                      "Remove sp=none or set it to quarantine or reject.")
    if "rua" not in tags:
        report.failed("email", "dmarc-rua", "DMARC has no aggregate report address", "low",
                      "Without reports you can't see who is sending as this domain.",
                      "Add rua=mailto:address to the record.")


def check_dkim(domain, report):
    def probe(selector):
        try:
            return selector, txt_values(dns_query(f"{selector}._domainkey.{domain}", "TXT"))
        except LookupFailed:
            return selector, []

    with cf.ThreadPoolExecutor(8) as pool:
        results = list(pool.map(probe, DKIM_SELECTORS))
    found = []
    weak = []
    for selector, values in results:
        for value in values:
            tags = parse_tags(value)
            if "p" not in tags:
                continue
            found.append(selector)
            try:
                if tags["p"] and len(base64.b64decode(tags["p"] + "==")) < 200:
                    weak.append(selector)
            except (binascii.Error, ValueError):
                pass
    if weak:
        report.failed("email", "dkim", "DKIM key is 1024-bit or shorter", "low",
                      "These keys are short enough to be weak against forgery.", "Rotate to a 2048-bit key.",
                      [f"{s}._domainkey.{domain} (TXT record)" for s in sorted(set(weak))])
    elif found:
        report.passed("email", "dkim", "DKIM key found", f"Selectors: {', '.join(sorted(set(found)))}")
    else:
        report.unknown("email", "dkim", "DKIM could not be confirmed",
                       "No key at the common selector names. Selector names are private to each "
                       "sender, so this does not prove DKIM is missing.")


def check_email(domain, report):
    mx_answer = dns_query(domain, "MX")
    mx = sorted(v.split()[-1].rstrip(".") for v in mx_answer.of_type(DNS_TYPES["MX"]))
    null_mx = mx == [""] or mx == ["."]
    has_mail = bool(mx) and not null_mx
    report.note("email", "mx", f"{len(mx)} mail server(s)" if has_mail else "Domain does not receive mail",
                ", ".join(mx[:8]))

    txts = txt_values(dns_query(domain, "TXT"))
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    evaluate_spf(txts, has_mail, report, spf_lookup_count(spf[0]) if len(spf) == 1 else None)

    dmarc_txts = txt_values(dns_query(f"_dmarc.{domain}", "TXT"))
    inherited = None
    labels = domain.split(".")
    for index in range(1, len(labels) - 1):
        if any(t.lower().startswith("v=dmarc1") for t in dmarc_txts):
            break
        parent = ".".join(labels[index:])
        dmarc_txts = txt_values(dns_query(f"_dmarc.{parent}", "TXT"))
        inherited = parent
    evaluate_dmarc(dmarc_txts, report, inherited)

    check_dkim(domain, report)

    if has_mail:
        if any(t.lower().startswith("v=stsv1") for t in txt_values(dns_query(f"_mta-sts.{domain}", "TXT"))):
            report.passed("email", "mta-sts", "MTA-STS is published")
        else:
            report.failed("email", "mta-sts", "No MTA-STS policy", "low",
                          "Inbound mail encryption can be downgraded by a network attacker.",
                          "Publish an MTA-STS policy and DNS record.")
    return mx if has_mail else []


# ---------------------------------------------------------------- TLS checks

def tls_probe(host, version):
    """Does the server accept this TLS version? True, False, or None if undetermined."""
    context = insecure_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, ssl.SSLError):
            return None
    try:
        with open_socket(host, 443, 8) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return None


def weak_cipher_accepted(host):
    context = insecure_context()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            context.set_ciphers("3DES:RC4:DES:EXP:NULL:aNULL:eNULL:@SECLEVEL=0")
            context.minimum_version = ssl.TLSVersion.TLSv1
            context.maximum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, ssl.SSLError):
            return None, ""
    try:
        with open_socket(host, 443, 8) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return True, tls.cipher()[0]
    except ssl.SSLError:
        return False, ""
    except OSError:
        return None, ""


def evaluate_certificate(host, not_after_ts, issuer, report, now=None):
    days = int((not_after_ts - (now or time.time())) / 86400)
    target = [link(f"https://{host}/", f"issuer: {issuer}")]
    if days < 0:
        report.failed("network", "cert", "Certificate has expired", "high", "Browsers will show a security warning.",
                      "Renew the certificate and automate renewal.", target)
    elif days < 14:
        report.failed("network", "cert", f"Certificate expires in {days} days", "high", "",
                      "Renew now and automate renewal.", target)
    elif days < 30:
        report.failed("network", "cert", f"Certificate expires in {days} days", "medium", "",
                      "Renew soon and automate renewal.", target)
    else:
        report.passed("network", "cert", "Certificate is valid and not expiring soon", affected=[
            link(f"https://{host}/", f"{days} days left, issuer: {issuer}")])


def check_tls(host, report):
    url = f"https://{host}/"
    try:
        with open_socket(host, 443, 8) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        message = exc.verify_message or str(exc)
        lowered = message.lower()
        if "expired" in lowered:
            title = "Certificate has expired"
        elif "self" in lowered:
            title = "Certificate is self-signed"
        elif "hostname" in lowered or "ip address" in lowered:
            title = "Certificate does not match the hostname"
        else:
            title = "Certificate failed validation"
        report.failed("network", "cert", title, "high", "Browsers will show a security warning.",
                      "Install a valid certificate from a trusted CA, with the full chain.", [link(url, message)])
        cert = None
    except ssl.SSLError as exc:
        report.unknown("network", "cert", "TLS handshake failed", f"{host}: {exc}")
        return False
    except OSError as exc:
        report.unknown("network", "cert", "HTTPS port is not reachable", f"{host}:443 — {exc}")
        return False

    if cert:
        issuer = dict(item[0] for item in cert.get("issuer", ())).get("organizationName", "unknown")
        evaluate_certificate(host, ssl.cert_time_to_seconds(cert["notAfter"]), issuer, report)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        legacy = {"TLS 1.0": ssl.TLSVersion.TLSv1, "TLS 1.1": ssl.TLSVersion.TLSv1_1}
    results = {name: tls_probe(host, version) for name, version in legacy.items()}
    accepted = [name for name, ok in results.items() if ok]
    if accepted:
        report.failed("network", "tls-legacy", f"Accepts deprecated {' and '.join(accepted)}", "medium",
                      "The server completed a handshake with a deprecated protocol.",
                      "Disable TLS 1.0 and 1.1 and require TLS 1.2 or newer.", [url])
    elif all(ok is False for ok in results.values()):
        report.passed("network", "tls-legacy", "Deprecated TLS versions are refused", affected=[url])
    else:
        report.unknown("network", "tls-legacy", "Could not test deprecated TLS versions", host)

    modern = tls_probe(host, ssl.TLSVersion.TLSv1_3)
    if modern:
        report.passed("network", "tls13", "TLS 1.3 is supported", affected=[url])
    elif modern is False:
        report.failed("network", "tls13", "TLS 1.3 is not supported", "low", "",
                      "Enable TLS 1.3 on the server or load balancer.", [url])
    else:
        report.unknown("network", "tls13", "Could not test TLS 1.3", host)

    weak, cipher = weak_cipher_accepted(host)
    if weak:
        report.failed("network", "cipher", "Accepts a weak cipher", "medium", "",
                      "Remove RC4, 3DES, DES, NULL and export ciphers.", [link(url, cipher)])
    elif weak is False:
        report.passed("network", "cipher", "Weak ciphers are refused", affected=[url])
    else:
        report.unknown("network", "cipher", "Could not test weak ciphers", host)
    return True


# ---------------------------------------------------------------- web checks

def evaluate_headers(page, report):
    headers = page.headers
    url = page.url
    hsts = headers.get("strict-transport-security", "")
    match = re.search(r"max-age=(\d+)", hsts, re.I)
    if not hsts or not match or int(match.group(1)) == 0:
        report.failed("web", "hsts", "HSTS is not enabled", "medium",
                      "Browsers may still try plain HTTP, which allows downgrade attacks.",
                      "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.", [url])
    elif int(match.group(1)) < 15552000:
        report.failed("web", "hsts", "HSTS max-age is under 6 months", "low", "", "Raise max-age to 31536000.",
                      [link(url, hsts)])
    else:
        report.passed("web", "hsts", "HSTS is enabled", affected=[url])

    csp = headers.get("content-security-policy", "")
    if not csp:
        report.failed("web", "csp", "No Content-Security-Policy", "medium",
                      "The browser has no policy limiting the damage from an XSS bug.",
                      "Deploy a CSP, starting with Content-Security-Policy-Report-Only.", [url])
    else:
        script = re.search(r"script-src[^;]*", csp) or re.search(r"default-src[^;]*", csp)
        if script and "'unsafe-inline'" in script.group(0) and "nonce-" not in script.group(0) \
                and "sha256-" not in script.group(0):
            report.failed("web", "csp", "CSP allows unsafe-inline scripts", "low",
                          "Injected inline scripts can still run, which removes most of CSP's XSS protection.",
                          "Use nonces or hashes instead of 'unsafe-inline'.", [link(url, script.group(0)[:300])])
        else:
            report.passed("web", "csp", "Content-Security-Policy is set", affected=[url])

    if "x-frame-options" in headers or "frame-ancestors" in csp:
        report.passed("web", "framing", "Clickjacking protection is set", affected=[url])
    else:
        report.failed("web", "framing", "No clickjacking protection", "low", "",
                      "Add CSP frame-ancestors or X-Frame-Options: DENY.", [url])

    if headers.get("x-content-type-options", "").lower() == "nosniff":
        report.passed("web", "nosniff", "X-Content-Type-Options is nosniff", affected=[url])
    else:
        report.failed("web", "nosniff", "X-Content-Type-Options is missing", "low", "",
                      "Send X-Content-Type-Options: nosniff.", [url])

    if "referrer-policy" in headers:
        report.passed("web", "referrer", "Referrer-Policy is set", affected=[url])
    else:
        report.failed("web", "referrer", "Referrer-Policy is missing", "low", "",
                      "Send Referrer-Policy: strict-origin-when-cross-origin.", [url])

    versions = [f"{name}: {headers[name]}" for name in ("server", "x-powered-by", "x-aspnet-version")
                if name in headers and re.search(r"\d+\.\d+", headers[name])]
    if versions:
        report.failed("web", "banner", "Server reveals software versions", "low", "",
                      "Remove version numbers from response headers.", [link(url, "; ".join(versions))])
    else:
        report.passed("web", "banner", "No software versions in headers", affected=[url])

    cookies = page.all("set-cookie")
    if cookies:
        insecure, script_readable, no_samesite = [], [], []
        for cookie in cookies:
            name = cookie.split("=", 1)[0].strip()
            attributes = [a.strip().lower() for a in cookie.split(";")[1:]]
            keys = {a.split("=", 1)[0] for a in attributes}
            if "secure" not in keys:
                insecure.append(name)
            if "httponly" not in keys and re.search(r"sess|auth|token|sid|login", name, re.I):
                script_readable.append(name)
            if "samesite" not in keys:
                no_samesite.append(name)
        if insecure:
            report.failed("web", "cookie-secure", "Cookies are missing the Secure flag", "medium", "",
                          "Set Secure on every cookie.", [link(url, "cookies: " + ", ".join(insecure))])
        if script_readable:
            report.failed("web", "cookie-httponly", "Session cookies are readable by scripts", "medium", "",
                          "Set HttpOnly on session cookies.", [link(url, "cookies: " + ", ".join(script_readable))])
        if no_samesite:
            report.failed("web", "cookie-samesite", "Cookies are missing SameSite", "low", "",
                          "Set SameSite=Lax or Strict.", [link(url, "cookies: " + ", ".join(no_samesite))])
        if not (insecure or script_readable or no_samesite):
            report.passed("web", "cookies", "Cookie flags are set correctly", affected=[url])


def check_web(host, report, domain=None):
    """With domain set, host is an extra subdomain: redirects off the domain aren't assessed."""
    https_url, http_url = f"https://{host}/", f"http://{host}/"
    https_chain = http_chain = None
    https_error = http_error = ""
    try:
        https_chain = follow(https_url)
    except (OSError, http.client.HTTPException, LookupFailed, BlockedTarget, ValueError) as exc:
        https_error = str(exc)
    try:
        http_chain = follow(http_url)
    except (OSError, http.client.HTTPException, LookupFailed, BlockedTarget, ValueError) as exc:
        http_error = str(exc)

    if not https_chain and not http_chain:
        report.unknown("web", "reachable", "No website responded", f"HTTPS: {https_error}; HTTP: {http_error}")
        return
    if not https_chain:
        report.failed("web", "https", "Website has no working HTTPS", "high", "",
                      "Serve the site over HTTPS with a valid certificate.", [link(http_url, https_error)])
        return
    report.passed("web", "https", "Website is served over HTTPS", affected=[https_url])

    if http_chain:
        if http_chain[-1].url.startswith("https://"):
            report.passed("web", "redirect", "HTTP redirects to HTTPS", affected=[http_url])
        else:
            status = http_chain[-1].status
            if status >= 400:  # no content is served in the clear, so this is hygiene, not exposure
                report.failed("web", "redirect", "HTTP returns an error instead of redirecting to HTTPS", "low",
                              "No page is served over plain HTTP, but visitors get an error and not the secure site.",
                              "Redirect all HTTP requests to HTTPS with a 301.", [link(http_url, f"returned HTTP {status}")])
            else:
                report.failed("web", "redirect", "HTTP is not redirected to HTTPS", "high",
                              "Visitors arriving over plain HTTP stay unencrypted.",
                              "Redirect all HTTP requests to HTTPS with a 301.", [link(http_url, f"returned HTTP {status}")])
    else:
        report.passed("web", "redirect", "Plain HTTP is not offered", affected=[http_url])

    final = https_chain[-1]
    final_host = urllib.parse.urlsplit(final.url).hostname or ""
    if domain and final_host != domain and not final_host.endswith("." + domain):
        return  # sent to a third party such as an SSO provider, whose headers aren't this domain's
    if final.url != https_url:
        report.note("web", "final-url", "Headers were read from the final redirect target", final.url)
    if final.status >= 400:
        report.unknown("web", "headers", f"Security headers not assessed (site returned HTTP {final.status})",
                       "Likely a bot wall or error page, whose headers may not match the real site.")
    else:
        evaluate_headers(final, report)

    if domain:
        return
    security_url = f"https://{host}/.well-known/security.txt"
    try:
        page = follow(security_url)[-1]
        if page.status == 200 and b"contact:" in page.body.lower():
            report.passed("web", "security-txt", "security.txt is published", affected=[security_url])
        else:
            report.failed("web", "security-txt", "No security.txt", "low",
                          "Researchers have no published way to report a vulnerability.",
                          "Publish /.well-known/security.txt (RFC 9116).", [link(security_url, f"returned HTTP {page.status}")])
    except (OSError, http.client.HTTPException, LookupFailed, BlockedTarget, ValueError):
        report.unknown("web", "security-txt", "Could not check security.txt")


# ---------------------------------------------------------------- attack surface

def clean_names(names, domain):
    found = set()
    for name in names:
        for piece in str(name).lower().split():
            piece = piece.lstrip("*.").rstrip(".")
            if piece.endswith("." + domain) and DOMAIN_RE.match(piece):
                found.add(piece)
    return found


def certificate_names(domain):
    """Subdomains from certificate transparency: crt.sh, then Cert Spotter."""
    errors = []
    for attempt in range(2):
        try:
            query = urllib.parse.quote(f"%.{domain}")
            status, rows = http_json(f"https://crt.sh/?q={query}&output=json&exclude=expired", timeout=45)
            if status == 200 and isinstance(rows, list):
                return clean_names((r.get("name_value", "") for r in rows), domain), "crt.sh"
        except LookupFailed as exc:
            errors.append(str(exc))
        time.sleep(1 + attempt)
    try:
        query = urllib.parse.urlencode({"domain": domain, "include_subdomains": "true", "expand": "dns_names"})
        status, rows = http_json(f"https://api.certspotter.com/v1/issuances?{query}", timeout=30)
        if status == 200 and isinstance(rows, list):
            names = [n for r in rows for n in r.get("dns_names", [])]
            return clean_names(names, domain), "Cert Spotter (partial)"
    except LookupFailed as exc:
        errors.append(str(exc))
    raise LookupFailed("; ".join(errors) or "no certificate data")


def is_sensitive(name, domain):
    labels = name[: -len(domain) - 1].split(".")
    return any(token in SENSITIVE_LABELS for label in labels for token in re.split(r"[-_]", label))


def check_surface(domain, report):
    """Returns {subdomain: [public IPv4 addresses]} for hosts that are live."""
    names, source = certificate_names(domain)
    ordered = sorted(names, key=lambda n: (not is_sensitive(n, domain), len(n), n))
    sample = ordered[:MAX_SUBDOMAINS]

    def resolve(name):
        try:
            return name, dns_query(name, "A")
        except LookupFailed:
            return name, None

    with cf.ThreadPoolExecutor(12) as pool:
        answers = list(pool.map(resolve, sample))

    live, dangling, private, failed = {}, [], [], 0
    for name, answer in answers:
        if answer is None:
            failed += 1
            continue
        cnames = answer.of_type(DNS_TYPES["CNAME"])
        addresses = answer.of_type(DNS_TYPES["A"])
        if answer.status == 3 and cnames:
            dangling.append(f"{name} → CNAME {cnames[-1].rstrip('.')}")
        elif addresses:
            public = []
            for address in addresses:
                try:
                    if ipaddress.ip_address(address).is_global:
                        public.append(address)
                    elif name not in private:
                        private.append(name)
                except ValueError:
                    pass
            if public:
                live[name] = public

    checked = len(sample) - failed
    scope = f"Found {len(names)} names in {source}; checked {checked}."
    report.note("surface", "inventory", f"{len(live)} live subdomains found", scope)
    if len(names) > len(sample):
        report.note("surface", "sample", f"Only {len(sample)} of {len(names)} subdomains were checked",
                    "Sensitive-looking names are checked first. These were not examined: "
                    + ", ".join(ordered[len(sample):]))
    if dangling:
        report.failed("surface", "dangling", f"{len(dangling)} dangling DNS record(s)", "high",
                      "These CNAMEs point at names that no longer exist. If a target can be registered, "
                      "an attacker can take over the subdomain.", "Delete the records or reclaim the targets.", dangling)
    else:
        report.passed("surface", "dangling", "No dangling CNAME records", scope)
    exposed = sorted(n for n in live if is_sensitive(n, domain))
    if exposed:
        report.failed("surface", "sensitive", f"{len(exposed)} non-production or admin hostname(s) are public",
                      "low", "The name alone doesn't prove exposure, so review each one.",
                      "Put these behind a VPN or SSO, or remove them if unused.", [f"https://{n}/" for n in exposed])
    else:
        report.passed("surface", "sensitive", "No admin or non-production hostnames are live")
    if private:
        report.failed("surface", "private-ip", f"{len(private)} public DNS name(s) reveal internal addresses", "low",
                      "", "Move internal records to private DNS.", private)
    return live, len(names), checked


# ---------------------------------------------------------------- IP intelligence

def internetdb(ip):
    for attempt in range(3):
        try:
            status, data = http_json(f"https://internetdb.shodan.io/{ip}", timeout=12)
            return "ok" if status == 200 else "nodata", data
        except LookupFailed:
            time.sleep(1.5 * (attempt + 1))
    return "error", None


_cve_cache = {}
_cve_lock = threading.Lock()


def cve_info(cve):
    """CVSS and known-exploited status. Failures are retried and never cached, so rate
    limiting can't quietly turn a known-exploited CVE into an unrated low finding."""
    with _cve_lock:
        if cve in _cve_cache:
            return _cve_cache[cve]
    for attempt in range(4):
        try:
            status, data = http_json(f"https://cvedb.shodan.io/cve/{cve}", timeout=12)
        except LookupFailed:
            time.sleep(1 + 2 * attempt)
            continue
        info = {"cvss": (data or {}).get("cvss_v3") or (data or {}).get("cvss") or 0,
                "kev": bool((data or {}).get("kev"))} if status == 200 else None
        with _cve_lock:
            _cve_cache[cve] = info
        return info
    return None


def score_label(info):
    return f" (CVSS {info['cvss']})" if info and info.get("cvss") else ""


def evaluate_ip_intel(intel, cve_details, report):
    """intel: {ip: {"state", "data", "hosts"}}. Scores open ports, CVEs and tags."""
    answered = {ip: v for ip, v in intel.items() if v["state"] == "ok"}
    no_data = [ip for ip, v in intel.items() if v["state"] == "nodata"]
    errors = [ip for ip, v in intel.items() if v["state"] == "error"]
    coverage = f"{len(answered)} of {len(intel)} IPs had Shodan data"
    coverage += f"; {len(errors)} lookups failed." if errors else "."

    def label(ip):
        return f"{ip} ({', '.join(sorted(intel[ip]['hosts']))})"

    shared = {}
    own = {}
    for ip, value in answered.items():
        data = value["data"]
        cpes = " ".join(data.get("cpes", [])).lower()
        if "cdn" in data.get("tags", []) or any(name in cpes for name in SHARED_CPE):
            shared[ip] = data
        else:
            own[ip] = data
    if shared:
        report.note("network", "shared", f"{len(shared)} IP(s) belong to a shared CDN",
                    "Ports and CVEs on CDN addresses describe the provider, so they are not scored.")

    if not answered:
        detail = "Shodan had no data for these IPs, so absence of findings proves nothing." if no_data and not errors \
            else "Shodan lookups failed."
        report.unknown("network", "ports", "Exposed ports could not be assessed", detail)
        report.unknown("patching", "cves", "Known vulnerabilities could not be assessed", detail)
        report.unknown("reputation", "tags", "Shodan host tags could not be assessed", detail)
        return

    by_severity = {}
    for ip, data in own.items():
        for port in data.get("ports", []):
            if port in RISKY_PORTS:
                service, severity = RISKY_PORTS[port]
                by_severity.setdefault(severity, []).append(f"{service} port {port} on {label(ip)}")
    for severity, items in by_severity.items():
        report.failed("network", f"ports-{severity}", f"{len(items)} risky service(s) exposed to the internet ({severity})",
                      severity, "Seen by Shodan's last scan, which may be weeks old.",
                      "Close these ports or restrict them to a VPN or allowlist.", items)
    if not by_severity:
        report.passed("network", "ports", "No risky ports seen by Shodan", coverage)

    cves = {}
    for ip, data in own.items():
        for cve in data.get("vulns", []):
            cves.setdefault(cve, []).append(ip)
    if not cves:
        report.passed("patching", "cves", "No known CVEs reported by Shodan", coverage)
    else:
        caveat = ("Shodan infers CVEs from software version banners and doesn't test them. "
                  "Vendors often backport fixes, so confirm each one.")
        tiers = {"kev": [], "critical": [], "high": [], "other": [], "unrated": []}
        for cve in sorted(cves):
            info = cve_details.get(cve)
            if info is None:
                tiers["unrated"].append(cve)
            elif info["kev"]:
                tiers["kev"].append(cve)
            elif info["cvss"] >= 9:
                tiers["critical"].append(cve)
            elif info["cvss"] >= 7:
                tiers["high"].append(cve)
            else:
                tiers["other"].append(cve)
        rules = (("kev", "critical", "on CISA's known-exploited list"), ("critical", "high", "with CVSS 9 or higher"),
                 ("high", "medium", "with CVSS 7 to 8.9"), ("other", "low", "with CVSS below 7"),
                 ("unrated", "low", "whose rating could not be retrieved"))
        for tier, severity, phrase in rules:
            items = tiers[tier]
            if items:
                affected = [asset(f"{cve}{score_label(cve_details.get(cve))} on {', '.join(label(ip) for ip in cves[cve])}",
                                  f"https://nvd.nist.gov/vuln/detail/{cve}") for cve in items]
                report.failed("patching", f"cve-{tier}", f"{len(items)} possible CVE(s) {phrase}", severity, caveat,
                              "Confirm the installed version and patch or upgrade.", affected)

    eol = [label(ip) for ip, data in own.items() if "eol-product" in data.get("tags", [])]
    if eol:
        report.failed("patching", "eol", "End-of-life software detected", "high", "",
                      "Upgrade to a supported release.", eol)

    self_signed = [label(ip) for ip, data in own.items() if "self-signed" in data.get("tags", [])]
    if self_signed:
        report.failed("network", "self-signed", "Self-signed certificate on an exposed service", "low", "",
                      "Use a certificate from a trusted CA.", self_signed)

    bad = [f"{label(ip)}: {', '.join(sorted(BAD_TAGS & set(data.get('tags', []))))}"
           for ip, data in own.items() if BAD_TAGS & set(data.get("tags", []))]
    if bad:
        report.failed("reputation", "tags", "Shodan tags an IP as compromised or malicious", "critical", "",
                      "Investigate these hosts as possible incidents.", bad)
    else:
        report.passed("reputation", "tags", "No compromise tags on scanned IPs", coverage)


def blocklist_listed(ip, zone):
    """True or False, or None if the list won't answer through this resolver."""
    reverse = ".".join(reversed(ip.split(".")))
    try:
        answer = dns_query(f"{reverse}.{zone}", "A")
    except LookupFailed:
        return None
    addresses = answer.of_type(DNS_TYPES["A"])
    if any(a.startswith("127.255.255.") for a in addresses):
        return None
    return any(a.startswith("127.") for a in addresses)


def check_blocklists(ips, report):
    zones = [z for z in ("bl.spamcop.net", "psbl.surriel.com") if blocklist_listed("127.0.0.2", z)]
    if not zones:
        report.unknown("reputation", "dnsbl", "Spam blocklists did not answer",
                       "The lists failed their built-in test entry, so results can't be trusted.")
        return
    listed, undetermined = [], 0
    for ip in ips:
        for zone in zones:
            result = blocklist_listed(ip, zone)
            if result:
                listed.append(f"{ip} on {zone}")
            elif result is None:
                undetermined += 1
    if listed:
        report.failed("reputation", "dnsbl", f"{len(listed)} spam blocklist hit(s)", "medium", "",
                      "Find the source of the abuse, then request delisting.", listed)
    elif undetermined:
        report.unknown("reputation", "dnsbl", "Blocklist check was incomplete", f"{undetermined} lookups failed.")
    else:
        report.passed("reputation", "dnsbl", "Not on checked spam blocklists",
                      f"{len(ips)} IP(s) against {', '.join(zones)}.")


def check_threat_feed(domain, report):
    """Cloudflare's malware-blocking resolver answers 0.0.0.0 for domains it classes as malicious."""
    resolver = ("https://security.cloudflare-dns.com/dns-query",)

    def blocked(name):
        return "0.0.0.0" in dns_query(name, "A", resolver).of_type(DNS_TYPES["A"])

    if not blocked("malware.testcategory.com"):
        report.unknown("reputation", "threat-feed", "Malware-domain feed failed its self-test")
    elif blocked(domain) or blocked(f"www.{domain}"):
        report.failed("reputation", "threat-feed", "Domain is classified as malicious", "critical",
                      "Cloudflare's security resolver blocks this domain.",
                      "Investigate for compromise, then request a review from Cloudflare.",
                      [f"https://{domain}/"])
    else:
        report.passed("reputation", "threat-feed", "Not blocked by Cloudflare's malware feed")


# ---------------------------------------------------------------- deep checks (authorized only)

EXPOSURE_PATHS = (
    ("/.git/HEAD", lambda b: b.startswith(b"ref: ") or re.fullmatch(rb"[0-9a-f]{40}\s*", b), "critical",
     "Git repository is publicly readable"),
    ("/.env", lambda b: re.match(rb"\s*(#.*\n\s*)*[A-Z][A-Z0-9_]*=", b) and b"<html" not in b.lower(), "critical",
     "An .env file is publicly readable"),
    ("/server-status", lambda b: b"Apache Server Status" in b, "medium", "Apache server-status is public"),
    ("/phpinfo.php", lambda b: b"phpinfo()" in b, "medium", "phpinfo page is public"),
    ("/.DS_Store", lambda b: b[:8] == b"\x00\x00\x00\x01Bud1", "low", "A .DS_Store file is public"),
)


def check_exposures(host, report):
    """Only the signature match is recorded. Response bodies are never stored."""
    hits = 0
    errors = 0
    for path, signature, severity, title in EXPOSURE_PATHS:
        try:
            page = fetch(f"https://{host}{path}", max_bytes=2048)
        except (OSError, http.client.HTTPException, LookupFailed, BlockedTarget, ValueError):
            errors += 1
            continue
        if page.status == 200 and signature(page.body):
            hits += 1
            report.failed("surface", f"exposed{path}", title, severity, "The file's contents were not stored.",
                          "Block this path at the web server and rotate any exposed secrets.", [f"https://{host}{path}"])
    if errors == len(EXPOSURE_PATHS):
        report.unknown("surface", "exposed", "Sensitive-file checks could not run")
    elif not hits:
        report.passed("surface", "exposed", "Sensitive files are not exposed",
                      ", ".join(p[0] for p in EXPOSURE_PATHS))


def check_direct_ports(host, report):
    def probe(port):
        try:
            with open_socket(host, port, 3):
                return port
        except (OSError, LookupFailed, BlockedTarget):
            return None

    with cf.ThreadPoolExecutor(8) as pool:
        open_ports = [p for p in pool.map(probe, RISKY_PORTS) if p]
    if not open_ports:
        report.passed("network", "direct-ports", "No risky ports answered a direct test", host)
        return
    for port in open_ports:
        service, severity = RISKY_PORTS[port]
        report.failed("network", f"direct-{port}", f"{service} port {port} is open", severity,
                      "The port accepted a TCP connection.", "Close the port or restrict it to a VPN or allowlist.",
                      [f"{host}:{port}"])


# ---------------------------------------------------------------- orchestration

def default_affected(finding, domain):
    """Where a DNS or email issue has to be fixed."""
    check = finding["check"]
    if check.startswith("dmarc"):
        return [asset(f"_dmarc.{domain} (TXT record)")]
    if check.startswith("spf"):
        return [asset(f"{domain} (TXT record)")]
    if check == "mta-sts":
        return [asset(f"_mta-sts.{domain} (TXT record)"), link(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")]
    if check == "caa":
        return [asset(f"{domain} (CAA record)")]
    if check == "dnssec":
        return [asset(f"{domain} (DS record at the registrar)")]
    if check == "ns":
        return [asset(f"{domain} (NS records)")]
    return [asset(domain)]


def guarded(report, factor, check, title, function, *args):
    try:
        return function(*args)
    except Exception as exc:  # one failed source must not lose the rest of the scan
        report.unknown(factor, check, title, f"{type(exc).__name__}: {exc}")
        return None


def scan(domain, deep=False, progress=lambda stage: None):
    report = Report()
    started = time.time()

    progress("Resolving domain")
    try:
        apex = dns_query(domain, "A")
        www = dns_query(f"www.{domain}", "A")
        ns = dns_query(domain, "NS")
    except LookupFailed as exc:
        raise ScanError(f"DNS lookups failed: {exc}") from exc
    if apex.status == 3 and www.status == 3 and ns.status == 3:
        raise ScanError("This domain does not exist (NXDOMAIN).")

    primary = None
    for name, answer in ((domain, apex), (f"www.{domain}", www)):
        if answer.of_type(DNS_TYPES["A"]) and primary is None:
            primary = name
    primary = primary or domain

    progress("Checking DNS, email, TLS, web and subdomains")
    with cf.ThreadPoolExecutor(5) as pool:
        tasks = {
            "dns": pool.submit(guarded, report, "dns", "dns", "DNS checks failed", check_dns, domain, report),
            "email": pool.submit(guarded, report, "email", "email", "Email checks failed", check_email, domain, report),
            "tls": pool.submit(guarded, report, "network", "tls", "TLS checks failed", check_tls, primary, report),
            "web": pool.submit(guarded, report, "web", "web", "Web checks failed", check_web, primary, report),
            "surface": pool.submit(guarded, report, "surface", "ct", "Subdomain discovery failed", check_surface,
                                   domain, report),
        }
        mx = tasks["email"].result() or []
        surface = tasks["surface"].result()
        for task in tasks.values():
            task.result()
    live, names_total, names_checked = surface or ({}, None, None)

    extra_hosts = [h for h in live if h != primary]
    www_name = f"www.{domain}"
    if www_name != primary and www_name not in extra_hosts and www.of_type(DNS_TYPES["A"]):
        extra_hosts.insert(0, www_name)
    tested_hosts = [primary] + extra_hosts[:MAX_HOST_CHECKS]
    if len(extra_hosts) > MAX_HOST_CHECKS:
        report.note("web", "host-sample", f"Web and TLS checks ran on {MAX_HOST_CHECKS + 1} of {len(extra_hosts) + 1} hosts",
                    "Sensitive-looking names go first. Not tested: " + ", ".join(extra_hosts[MAX_HOST_CHECKS:]))
    if extra_hosts:
        progress(f"Checking web and TLS on {len(tested_hosts) - 1} more hosts")
        secondary = SubdomainReport(report)

        def check_host(host):
            guarded(secondary, "network", "tls", "TLS checks failed", check_tls, host, secondary)
            guarded(secondary, "web", "web", "Web checks failed", check_web, host, secondary, domain)

        with cf.ThreadPoolExecutor(8) as pool:
            list(pool.map(check_host, tested_hosts[1:]))

    progress("Looking up IP intelligence")
    ip_hosts = {}

    def add_ips(host, addresses):
        for address in addresses:
            try:
                parsed = ipaddress.ip_address(address)
            except ValueError:
                continue
            if parsed.version == 4 and parsed.is_global:
                ip_hosts.setdefault(address, set()).add(host)

    add_ips(domain, apex.of_type(DNS_TYPES["A"]))
    add_ips(f"www.{domain}", www.of_type(DNS_TYPES["A"]))
    reputation_seed_hosts = []
    for host in mx[:4]:
        try:
            addresses = dns_query(host, "A").of_type(DNS_TYPES["A"])
            add_ips(host, addresses)
            reputation_seed_hosts.extend(addresses)
        except LookupFailed:
            pass
    core_ips = list(ip_hosts)
    for host, addresses in live.items():
        add_ips(host, addresses)

    selected = core_ips + [ip for ip in ip_hosts if ip not in core_ips]
    skipped = max(0, len(selected) - MAX_IPS)
    selected = selected[:MAX_IPS]
    if skipped:
        report.note("network", "ip-sample", f"Only {MAX_IPS} of {MAX_IPS + skipped} IPs were looked up")

    if selected:
        with cf.ThreadPoolExecutor(6) as pool:
            looked_up = dict(zip(selected, pool.map(internetdb, selected)))
        intel = {ip: {"state": looked_up[ip][0], "data": looked_up[ip][1], "hosts": ip_hosts[ip]} for ip in selected}
        cves = sorted({c for v in intel.values() if v["data"] for c in v["data"].get("vulns", [])})
        with cf.ThreadPoolExecutor(3) as pool:
            details = dict(zip(cves[:MAX_CVE_LOOKUPS], pool.map(cve_info, cves[:MAX_CVE_LOOKUPS])))
        guarded(report, "network", "intel", "IP intelligence failed", evaluate_ip_intel, intel, details, report)
    else:
        report.unknown("network", "ports", "No public IPv4 addresses to look up")
        report.unknown("patching", "cves", "No public IPv4 addresses to look up")

    progress("Checking reputation feeds")
    guarded(report, "reputation", "threat-feed", "Malware feed could not be checked", check_threat_feed, domain, report)
    blocklist_ips = list(dict.fromkeys(core_ips + reputation_seed_hosts))[:10]
    if blocklist_ips:
        guarded(report, "reputation", "dnsbl", "Blocklists could not be checked", check_blocklists, blocklist_ips, report)

    if deep:
        progress("Running authorized deep checks")
        guarded(report, "surface", "exposed", "Sensitive-file checks failed", check_exposures, primary, report)
        guarded(report, "network", "direct-ports", "Direct port test failed", check_direct_ports, primary, report)

    findings = sorted(report.findings, key=lambda f: (SEVERITY_ORDER[f["severity"]], f["factor"], f["title"]))
    for finding in findings:
        finding["factor_name"] = FACTORS[finding["factor"]][0]
        if finding["status"] == "fail" and not finding["affected"]:
            finding["affected"] = default_affected(finding, domain)
    scores = compute_scores(findings)
    return {
        "domain": domain, "deep": deep, "started": started, "finished": time.time(),
        **scores, "findings": findings,
        "assets": {
            "primary_host": primary, "mail_servers": mx, "ips": sorted(ip_hosts),
            "subdomains_found": names_total, "subdomains_checked": names_checked,
            "live_subdomains": sorted(live), "hosts_tested": tested_hosts,
        },
    }
