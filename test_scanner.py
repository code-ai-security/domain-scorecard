"""Offline unit tests. Run: python3 -m unittest -v"""
import json
import re
import unittest
from pathlib import Path
from unittest import mock

import app
import compare
import remediation
import scanner
from scanner import Page, Report


def by_check(report, check):
    return [f for f in report.findings if f["check"] == check]


class Normalize(unittest.TestCase):
    def test_accepts(self):
        for raw, want in [("Example.COM", "example.com"), ("https://www.example.com/a?b=1", "example.com"),
                          ("sub.example.co.uk:8443", "sub.example.co.uk"), ("*.example.org", "example.org"),
                          ("münchen.de", "xn--mnchen-3ya.de"), ("user@example.net", "example.net")]:
            self.assertEqual(scanner.normalize_domain(raw), want, raw)

    def test_rejects(self):
        for raw in ["", "localhost", "domain", "127.0.0.1", "a b.com", "../../etc", "exa_mple.com", None]:
            self.assertIsNone(scanner.normalize_domain(raw), raw)


class Scoring(unittest.TestCase):
    def finding(self, factor, status, severity="info"):
        return {"factor": factor, "status": status, "severity": severity, "title": "", "check": "", "detail": "", "fix": ""}

    def all_pass(self):
        return [self.finding(k, "pass") for k in scanner.FACTORS]

    def test_all_pass_is_a(self):
        self.assertEqual(scanner.compute_scores(self.all_pass())["grade"], "A")

    def test_unknown_is_not_a_pass_or_a_penalty(self):
        result = scanner.compute_scores([f for f in self.all_pass() if f["factor"] != "patching"]
                                        + [self.finding("patching", "unknown")])
        self.assertIsNone(result["factors"]["patching"]["score"])
        self.assertEqual(result["coverage"], 80)
        self.assertEqual(result["score"], 100)

    def test_critical_caps_total(self):
        result = scanner.compute_scores(self.all_pass() + [self.finding("dns", "fail", "critical")])
        self.assertEqual(result["score"], 69)
        self.assertEqual(result["grade"], "D")

    def test_high_caps_total(self):
        self.assertEqual(scanner.compute_scores(self.all_pass() + [self.finding("dns", "fail", "high")])["score"], 89)

    def test_low_coverage_gets_no_grade(self):
        result = scanner.compute_scores([self.finding("dns", "pass")])
        self.assertIsNone(result["grade"])

    def test_factor_floor(self):
        rows = [self.finding("dns", "fail", "critical") for _ in range(5)]
        self.assertEqual(scanner.compute_scores(rows)["factors"]["dns"]["score"], 0)


class Email(unittest.TestCase):
    def spf(self, record, mail=True):
        report = Report()
        scanner.evaluate_spf([record] if record else [], mail, report)
        return report.findings[0]

    def test_spf(self):
        self.assertEqual(self.spf("v=spf1 include:x.com -all")["status"], "pass")
        self.assertEqual(self.spf("v=spf1 include:x.com ~all")["status"], "pass")
        self.assertEqual(self.spf("v=spf1 +all")["severity"], "high")
        self.assertEqual(self.spf("v=spf1 a all")["severity"], "high")
        self.assertEqual(self.spf("v=spf1 ?all")["severity"], "medium")
        self.assertEqual(self.spf("")["severity"], "high")
        self.assertEqual(self.spf("", mail=False)["severity"], "medium")

    def test_multiple_spf(self):
        report = Report()
        scanner.evaluate_spf(["v=spf1 -all", "v=spf1 ~all"], True, report)
        self.assertIn("Multiple", report.findings[0]["title"])

    def dmarc(self, record):
        report = Report()
        scanner.evaluate_dmarc([record] if record else [], report)
        return report

    def test_dmarc(self):
        self.assertEqual(self.dmarc("").findings[0]["severity"], "high")
        self.assertEqual(by_check(self.dmarc("v=DMARC1; p=none; rua=mailto:a@b.c"), "dmarc")[0]["severity"], "medium")
        self.assertEqual(by_check(self.dmarc("v=DMARC1; p=reject; rua=mailto:a@b.c"), "dmarc")[0]["status"], "pass")
        self.assertTrue(by_check(self.dmarc("v=DMARC1; p=reject"), "dmarc-rua"))
        self.assertTrue(by_check(self.dmarc("v=DMARC1; p=reject; pct=50"), "dmarc-pct"))
        self.assertTrue(by_check(self.dmarc("v=DMARC1; p=reject; sp=none"), "dmarc-sp"))


class Headers(unittest.TestCase):
    def run_headers(self, headers):
        report = Report()
        scanner.evaluate_headers(Page("https://x.test/", 200, headers, b""), report)
        return report

    def test_bare_site_fails_core_checks(self):
        report = self.run_headers([])
        for check in ("hsts", "csp", "framing", "nosniff", "referrer"):
            self.assertEqual(by_check(report, check)[0]["status"], "fail", check)

    def test_hardened_site_passes(self):
        report = self.run_headers([
            ("Strict-Transport-Security", "max-age=31536000"), ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
            ("X-Content-Type-Options", "nosniff"), ("Referrer-Policy", "no-referrer"), ("Server", "nginx"),
            ("Set-Cookie", "sid=1; Secure; HttpOnly; SameSite=Lax"), ("Set-Cookie", "x=1; Path=/; Secure; SameSite=Lax"),
        ])
        self.assertEqual([f["title"] for f in report.findings if f["status"] == "fail"], [])

    def test_cookies_and_banner(self):
        report = self.run_headers([("Set-Cookie", "PHPSESSID=abc"), ("Server", "Apache/2.4.1")])
        for check in ("cookie-secure", "cookie-httponly", "cookie-samesite", "banner"):
            self.assertEqual(by_check(report, check)[0]["status"], "fail", check)

    def test_unsafe_inline(self):
        report = self.run_headers([("Content-Security-Policy", "script-src 'self' 'unsafe-inline'")])
        self.assertEqual(by_check(report, "csp")[0]["severity"], "low")

    def test_short_hsts(self):
        report = self.run_headers([("Strict-Transport-Security", "max-age=60")])
        self.assertEqual(by_check(report, "hsts")[0]["severity"], "low")


class Certificates(unittest.TestCase):
    def severity(self, days):
        report = Report()
        scanner.evaluate_certificate("x.test", 1000 + days * 86400 + 1, "CA", report, now=1000)
        return report.findings[0]

    def test_expiry_tiers(self):
        self.assertEqual(self.severity(-5)["severity"], "high")
        self.assertEqual(self.severity(5)["severity"], "high")
        self.assertEqual(self.severity(20)["severity"], "medium")
        self.assertEqual(self.severity(90)["status"], "pass")


class IpIntel(unittest.TestCase):
    def evaluate(self, data, details=None, state="ok"):
        report = Report()
        scanner.evaluate_ip_intel({"203.0.113.5": {"state": state, "data": data, "hosts": {"x.test"}}}, details or {}, report)
        return report

    def test_no_data_is_unknown_not_clean(self):
        report = self.evaluate(None, state="nodata")
        self.assertEqual(by_check(report, "cves")[0]["status"], "unknown")

    def test_risky_port(self):
        report = self.evaluate({"ports": [443, 3389], "vulns": [], "tags": [], "cpes": []})
        self.assertEqual(by_check(report, "ports-high")[0]["status"], "fail")

    def test_kev_is_critical(self):
        report = self.evaluate({"ports": [], "vulns": ["CVE-1"], "tags": [], "cpes": []}, {"CVE-1": {"cvss": 5, "kev": True}})
        self.assertEqual(by_check(report, "cve-kev")[0]["severity"], "critical")

    def test_cdn_is_not_scored(self):
        report = self.evaluate({"ports": [3389], "vulns": ["CVE-1"], "tags": ["cdn"], "cpes": []})
        self.assertFalse([f for f in report.findings if f["status"] == "fail"])

    def test_compromise_tag(self):
        report = self.evaluate({"ports": [], "vulns": [], "tags": ["compromised"], "cpes": []})
        self.assertEqual(by_check(report, "tags")[0]["severity"], "critical")


class SafeTargets(unittest.TestCase):
    def test_loopback_blocked(self):
        with self.assertRaises(scanner.BlockedTarget):
            scanner.public_addresses("localhost")

    def test_fetch_refuses_loopback(self):
        with self.assertRaises(scanner.BlockedTarget):
            scanner.fetch("http://127.0.0.1:1/")

    def test_clean_names_ignores_foreign_hosts(self):
        names = scanner.clean_names(["*.a.example.com\nb.example.com", "evil.com", "example.com", "<b>.example.com"], "example.com")
        self.assertEqual(names, {"a.example.com", "b.example.com"})


class DeepChecks(unittest.TestCase):
    def run_exposures(self, pages):
        def fake(url, max_bytes=0):
            path = "/" + url.split("/", 3)[3]
            return Page(url, *pages.get(path, (404, [], b"")))

        report = Report()
        with mock.patch.object(scanner, "fetch", fake):
            scanner.check_exposures("x.test", report)
        return report

    def test_exposed_files_are_detected_without_storing_content(self):
        report = self.run_exposures({"/.env": (200, [], b"DB_PASSWORD=hunter2\n"), "/.git/HEAD": (200, [], b"ref: refs/heads/main\n")})
        failed = [f for f in report.findings if f["status"] == "fail"]
        self.assertEqual(sorted(f["severity"] for f in failed), ["critical", "critical"])
        self.assertNotIn("hunter2", json.dumps(report.findings))

    def test_soft_404_is_not_a_finding(self):
        html = (200, [], b"<html><body>Not found</body></html>")
        report = self.run_exposures({p[0]: html for p in scanner.EXPOSURE_PATHS})
        self.assertEqual(by_check(report, "exposed")[0]["status"], "pass")

    def test_direct_ports(self):
        class Conn:
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake(host, port, timeout):
            if port == 6379:
                return Conn()
            raise OSError("closed")

        report = Report()
        with mock.patch.object(scanner, "open_socket", fake):
            scanner.check_direct_ports("x.test", report)
        self.assertEqual(by_check(report, "direct-6379")[0]["severity"], "critical")


class SubdomainDns(unittest.TestCase):
    def test_inherited_records_are_not_penalized(self):
        def fake(name, rtype, *_):
            data = {"Status": 0, "AD": rtype == "SOA", "Answer": []}
            if rtype == "CAA" and name == "example.com":
                data["Answer"] = [{"type": 257, "data": '0 issue "ca.test"'}]
            return scanner.DnsAnswer(data)

        report = Report()
        with mock.patch.object(scanner, "dns_query", fake):
            scanner.check_dns("shop.example.com", report)
        self.assertEqual([f["title"] for f in report.findings if f["status"] == "fail"], [])
        self.assertEqual(by_check(report, "caa")[0]["status"], "pass")
        self.assertEqual(by_check(report, "dnssec")[0]["status"], "pass")


class CveLookup(unittest.TestCase):
    def test_failed_lookup_retries_and_is_not_cached(self):
        calls = iter([scanner.LookupFailed("429"), (200, {"cvss_v3": 9.8, "kev": True})])

        def fake(*_a, **_k):
            value = next(calls)
            if isinstance(value, Exception):
                raise value
            return value

        scanner._cve_cache.pop("CVE-T", None)
        with mock.patch.object(scanner, "http_json", fake), mock.patch.object(scanner.time, "sleep"):
            self.assertEqual(scanner.cve_info("CVE-T"), {"cvss": 9.8, "kev": True})


class Issues(unittest.TestCase):
    def run_web(self, routes):
        def fake(url, max_bytes=0):
            status, headers, body = routes.get(url, (404, [], b""))
            return Page(url, status, headers, body)

        report = Report()
        with mock.patch.object(scanner, "fetch", fake):
            scanner.check_web("x.test", report)
        return report

    def test_http_error_is_low_but_http_content_is_high(self):
        secure = (200, [], b"")
        low = self.run_web({"https://x.test/": secure, "http://x.test/": (403, [], b"")})
        self.assertEqual(by_check(low, "redirect")[0]["severity"], "low")
        high = self.run_web({"https://x.test/": secure, "http://x.test/": (200, [], b"")})
        self.assertEqual(by_check(high, "redirect")[0]["severity"], "high")

    def test_security_txt_behind_a_redirect_is_found(self):
        report = self.run_web({
            "https://x.test/": (200, [], b""), "http://x.test/": (301, [("Location", "https://x.test/")], b""),
            "https://x.test/.well-known/security.txt": (301, [("Location", "https://www.x.test/.well-known/security.txt")], b""),
            "https://www.x.test/.well-known/security.txt": (200, [], b"Contact: mailto:a@x.test"),
        })
        self.assertEqual(by_check(report, "security-txt")[0]["status"], "pass")

    def test_same_issue_on_two_hosts_merges_and_lists_both(self):
        report = Report()
        for host in ("a.x.test", "b.x.test"):
            scanner.evaluate_headers(Page(f"https://{host}/", 200, [], b""), report)
        hsts = by_check(report, "hsts")
        self.assertEqual(len(hsts), 1)
        self.assertEqual([a["url"] for a in hsts[0]["affected"]], ["https://a.x.test/", "https://b.x.test/"])

    def test_lists_are_not_truncated(self):
        ips = {f"203.0.113.{i}": {"state": "ok", "hosts": {"x.test"},
                                  "data": {"ports": [3389], "vulns": [f"CVE-2020-{i}"], "tags": [], "cpes": []}}
               for i in range(1, 41)}
        report = Report()
        scanner.evaluate_ip_intel(ips, {}, report)
        self.assertEqual(len(by_check(report, "ports-high")[0]["affected"]), 40)
        cves = by_check(report, "cve-unrated")[0]["affected"]
        self.assertEqual(len(cves), 40)
        self.assertTrue(all(a["url"].startswith("https://nvd.nist.gov/") for a in cves))

    def test_every_failable_check_has_guidance(self):
        source = Path(scanner.__file__).read_text()
        checks = set(re.findall(r'\.failed\(\s*"[a-z]+",\s*f?"([^"{]+)', source))
        self.assertGreater(len(checks), 25)
        missing = [c for c in checks if not remediation.guide_for(c)]
        self.assertEqual(missing, [])

    def test_guidance_is_filled_in(self):
        result = remediation.enrich({"domain": "x.test", "assets": {"primary_host": "www.x.test"}, "findings": [
            {"check": "hsts", "status": "fail"}, {"check": "hsts", "status": "pass"}]})
        guide = result["findings"][0]["recommendation"]
        self.assertTrue(guide["steps"])
        self.assertIn("www.x.test", guide["verify"])
        self.assertNotIn("recommendation", result["findings"][1])

    def test_csv_blocks_formulas(self):
        self.assertEqual(app.csv_safe("=cmd()"), "'=cmd()")
        self.assertEqual(app.csv_safe("https://x.test/"), "https://x.test/")


class ChangesAfterRescan(unittest.TestCase):
    URL = "https://x.test/"

    def scan(self, *findings, deep=False, ips=()):
        return {"domain": "x.test", "deep": deep, "score": 50, "finished": 1, "assets": {"ips": list(ips), "hosts_tested": ["x.test"]},
                "findings": [{"factor": "web", "factor_name": "App", "check": c, "title": t, "status": st,
                              "severity": "medium" if st == "fail" else "info", "affected": a} for c, t, st, a in findings]}

    def link(self, url=None):
        return [{"label": url or self.URL, "url": url or self.URL}]

    def test_retested_and_passing_is_fixed(self):
        change = compare.compare(self.scan(("hsts", "No HSTS", "fail", self.link())), self.scan(("hsts", "HSTS on", "pass", self.link())))
        self.assertEqual([i["title"] for i in change["fixed"]], ["No HSTS"])
        self.assertEqual(change["unconfirmed"], [])

    def test_bot_wall_is_not_called_fixed(self):
        before = self.scan(("hsts", "No HSTS", "fail", self.link()))
        after = self.scan(("https", "HTTPS works", "pass", self.link()))  # headers were never read
        change = compare.compare(before, after)
        self.assertEqual(change["fixed"], [])
        self.assertEqual(len(change["unconfirmed"]), 1)

    def test_site_down_is_not_called_fixed(self):
        change = compare.compare(self.scan(("cert", "Expired", "fail", self.link())), self.scan())
        self.assertEqual(change["fixed"], [])
        self.assertEqual(len(change["unconfirmed"]), 1)

    def test_changing_title_is_still_the_same_issue(self):
        change = compare.compare(self.scan(("cert", "Expires in 6 days", "fail", self.link())),
                                 self.scan(("cert", "Expires in 5 days", "fail", self.link())))
        self.assertEqual((change["fixed"], change["new"], change["still_open"]), ([], [], 1))

    def test_partial_fix_lists_only_what_was_fixed(self):
        a, b = "https://a.x.test/", "https://b.x.test/"
        change = compare.compare(self.scan(("csp", "No CSP", "fail", self.link(a) + self.link(b))),
                                 self.scan(("csp", "No CSP", "fail", self.link(b)), ("csp", "CSP set", "pass", self.link(a))))
        self.assertEqual([x["url"] for x in change["partly_fixed"][0]["assets"]], [a])
        self.assertEqual(change["partly_fixed"][0]["remaining"], 1)

    def test_new_issue_and_new_url_are_reported(self):
        a, b = "https://a.x.test/", "https://b.x.test/"
        change = compare.compare(self.scan(("csp", "No CSP", "fail", self.link(a))),
                                 self.scan(("csp", "No CSP", "fail", self.link(a) + self.link(b)), ("hsts", "No HSTS", "fail", self.link(a))))
        self.assertEqual(sorted(i["title"] for i in change["new"]), ["No CSP", "No HSTS"])
        self.assertEqual([x["url"] for x in change["new"][0]["assets"]], [b])

    def test_cve_moving_between_severity_tiers_is_not_fixed_or_new(self):
        row = [{"label": "CVE-2021-1 (CVSS 9.0) on 203.0.113.5 (x.test)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1"}]
        change = compare.compare(self.scan(("cve-unrated", "1 unrated", "fail", row)), self.scan(("cve-kev", "1 exploited", "fail", row)), )
        self.assertEqual((change["fixed"], change["new"], change["still_open"]), ([], [], 1))

    def test_cve_gone_while_ip_remains_is_fixed_with_a_caveat(self):
        row = [{"label": "CVE-2021-1 on 203.0.113.5 (x.test)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1"}]
        change = compare.compare(self.scan(("cve-high", "1 CVE", "fail", row)),
                                 self.scan(("cves", "No CVEs", "pass", []), ips=["203.0.113.5"]))
        self.assertEqual(len(change["fixed"]), 1)
        self.assertIn("Shodan", change["fixed"][0]["note"])

    def test_cve_on_an_ip_that_left_the_scan_is_unconfirmed(self):
        row = [{"label": "CVE-2021-1 on 203.0.113.5 (x.test)", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-1"}]
        change = compare.compare(self.scan(("cve-high", "1 CVE", "fail", row)), self.scan(("cves", "No CVEs", "pass", [])))
        self.assertEqual(change["fixed"], [])
        self.assertEqual(len(change["unconfirmed"]), 1)

    def test_deep_issue_is_unconfirmed_after_a_normal_rescan(self):
        row = self.link("https://x.test/.env")
        change = compare.compare(self.scan(("exposed/.env", "Exposed .env", "fail", row), deep=True), self.scan())
        self.assertEqual(change["fixed"], [])
        self.assertEqual(len(change["unconfirmed"]), 1)

    def test_old_scan_without_affected_items_still_compares(self):
        change = compare.compare(self.scan(("dnssec", "No DNSSEC", "fail", [])), self.scan(("dnssec", "DNSSEC on", "pass", [])))
        self.assertEqual(len(change["fixed"]), 1)


class Portfolio(unittest.TestCase):
    def test_submit_requires_authorization_for_deep(self):
        self.assertIn("error", app.submit(["example.com"], True, False))

    def test_file_reader(self):
        import tempfile, os
        with tempfile.NamedTemporaryFile("w", suffix=".csv", delete=False) as handle:
            handle.write("# comment\nexample.com,Acme\n\nb.org  # note\n")
        try:
            self.assertEqual(app.read_domain_file(handle.name), ["example.com", "b.org"])
        finally:
            os.unlink(handle.name)


if __name__ == "__main__":
    unittest.main()
