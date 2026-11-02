"""Work out what changed between two scans of a domain.

An issue missing from the newer scan doesn't prove it was fixed: the site may have
been down, behind a bot wall, or the check may not have run. An item only counts as
fixed when the newer scan shows the same kind of check actually re-tested it.
Everything else is reported as "could not confirm".
"""
import re
import urllib.parse

HEADERS = {"hsts", "csp", "framing", "nosniff", "referrer", "banner", "cookies",
           "cookie-secure", "cookie-httponly", "cookie-samesite"}
TLS = {"cert", "tls-legacy", "tls13", "cipher"}
WEB_ACCESS = {"https", "redirect"}
SURFACE = {"dangling", "sensitive", "private-ip"}
SHODAN = {"cve", "ports", "eol", "self-signed"}
SHODAN_NOTE = "Shodan no longer reports this. Its data can lag, so confirm on the server."


def family(check):
    if check.startswith("cve") :
        return "cve"
    if check.startswith("ports"):
        return "ports"
    if check.startswith("direct-"):
        return "direct"
    if check.startswith("exposed"):
        return check if "/" in check else "exposed"
    return check


def asset_key(check, asset):
    """A stable identity for an affected item, ignoring details that change between scans."""
    label, url = asset.get("label", ""), asset.get("url")
    match = re.search(r"CVE-\d{4}-\d+", label)
    if match:
        return match.group(0)
    match = re.search(r"port (\d+) on ([\d.]+)", label)
    if match:
        return f"{match.group(2)}:{match.group(1)}"
    if url:
        parts = urllib.parse.urlsplit(url)
        return f"{parts.scheme}://{(parts.hostname or '').lower()}{parts.path}"
    return re.sub(r"\s*\(.*\)$", "", label)


def host_of(asset):
    url = asset.get("url")
    if url:
        return (urllib.parse.urlsplit(url).hostname or "").lower()
    return ""


def tested(findings):
    """Checks that produced a real result, as family -> hosts (hosts may be empty)."""
    seen = {}
    for finding in findings:
        if finding["status"] in ("pass", "fail"):
            hosts = seen.setdefault(family(finding["check"]), set())
            hosts.update(host_of(a) for a in finding.get("affected", []))
    return seen


def was_retested(check, asset, current, seen):
    """Did the newer scan really test this item? Returns (yes_or_no, note)."""
    fam = family(check)
    host = host_of(asset) if asset else ""

    def host_checked(group):
        return any(host in seen.get(name, ()) for name in group)

    if check in HEADERS:
        return (host_checked(HEADERS), "") if host else (bool(seen.keys() & HEADERS), "")
    if check in TLS:
        return (host_checked(TLS), "") if host else (bool(seen.keys() & TLS), "")
    if check in WEB_ACCESS:
        return (host_checked(WEB_ACCESS), "") if host else (bool(seen.keys() & WEB_ACCESS), "")
    if check.startswith("dmarc"):
        return "dmarc" in seen, ""
    if check.startswith("spf"):
        return "spf" in seen, ""
    if check in SURFACE:
        return bool(seen.keys() & {"dangling", "sensitive"}), ""
    if fam in SHODAN:
        ran = bool(seen.keys() & {"cve", "ports"})
        addresses = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", asset.get("label", "")) if asset else []
        current_ips = set(current.get("assets", {}).get("ips", []))
        if addresses and not current_ips & set(addresses):
            return False, ""  # the address left the scan, which isn't the same as being fixed
        return ran, SHODAN_NOTE
    if fam == "direct" or fam.startswith("exposed"):
        return bool(current.get("deep")) and (fam in seen or fam == "direct" or "exposed" in seen), ""
    return fam in seen, ""


def compare(previous, current):
    """Returns what was fixed, partly fixed, unconfirmed, new and still open since `previous`."""
    current_failures = {}
    for finding in current.get("findings", []):
        if finding["status"] == "fail":
            for asset in finding.get("affected") or [{}]:
                current_failures.setdefault(family(finding["check"]), {})[asset_key(finding["check"], asset)] = finding
    seen = tested(current.get("findings", []))

    previous_keys = {}
    fixed, partly, unconfirmed = [], [], []
    still_open = 0
    for finding in previous.get("findings", []):
        if finding["status"] != "fail":
            continue
        check, fam = finding["check"], family(finding["check"])
        now = current_failures.get(fam, {})
        assets = finding.get("affected") or []
        gone, doubtful, remaining, notes = [], [], 0, set()
        if not assets:  # very old scans didn't record affected items
            if now:
                remaining = 1
            else:
                ok, note = was_retested(check, None, current, seen)
                (gone if ok else doubtful).append({"label": previous.get("domain", ""), "url": None})
                notes.update([note] if note and ok else [])
        for asset in assets:
            key = asset_key(check, asset)
            previous_keys.setdefault(fam, set()).add(key)
            if key in now:
                remaining += 1
                continue
            ok, note = was_retested(check, asset, current, seen)
            (gone if ok else doubtful).append(asset)
            if note and ok:
                notes.add(note)
        still_open += remaining
        base = {"title": finding["title"], "severity": finding["severity"], "factor_name": finding.get("factor_name", ""),
                "check": check, "note": " ".join(sorted(notes))}
        if gone and not remaining and not doubtful:
            fixed.append({**base, "assets": gone})
        elif gone:
            partly.append({**base, "assets": gone, "remaining": remaining + len(doubtful)})
        if doubtful:
            unconfirmed.append({**base, "assets": doubtful,
                                "note": "The rescan didn't re-test this, so it may not be fixed."})
        if not assets:
            previous_keys.setdefault(fam, set()).add("*")

    new = []
    for finding in current.get("findings", []):
        if finding["status"] != "fail":
            continue
        fam = family(finding["check"])
        known = previous_keys.get(fam, set())
        if "*" in known:
            continue
        assets = [a for a in finding.get("affected") or [] if asset_key(finding["check"], a) not in known]
        if assets or (not finding.get("affected") and fam not in previous_keys):
            new.append({"title": finding["title"], "severity": finding["severity"],
                        "factor_name": finding.get("factor_name", ""), "check": finding["check"], "assets": assets})

    return {
        "previous_scanned": previous.get("finished"), "current_scanned": current.get("finished"),
        "previous_score": previous.get("score"), "current_score": current.get("score"),
        "fixed": fixed, "partly_fixed": partly, "unconfirmed": unconfirmed, "new": new, "still_open": still_open,
        "wider_coverage": "hosts_tested" not in previous.get("assets", {}) and "hosts_tested" in current.get("assets", {}),
    }


def counts(change):
    return {"fixed": len(change["fixed"]), "partly_fixed": len(change["partly_fixed"]),
            "unconfirmed": len(change["unconfirmed"]), "new": len(change["new"])}
