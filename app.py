#!/usr/bin/env python3
"""Domain Scorecard: local dashboard server. Run: python3 app.py"""
import argparse
import csv
import io
import json
import mimetypes
import queue
import re
import sqlite3
import threading
import time
import traceback
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import remediation
import scanner

ROOT = Path(__file__).resolve().parent
STATIC = ROOT / "static"
DB_PATH = ROOT / "scorecard.db"
WORKERS = 3
MAX_BATCH = 5000
MAX_BODY = 5_000_000

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  domain TEXT NOT NULL,
  status TEXT NOT NULL,
  stage TEXT,
  deep INTEGER NOT NULL DEFAULT 0,
  requested_at REAL NOT NULL,
  finished_at REAL,
  score INTEGER,
  grade TEXT,
  coverage INTEGER,
  summary TEXT,
  result TEXT,
  error TEXT
);
CREATE INDEX IF NOT EXISTS scans_domain ON scans(domain, id);
"""

jobs = queue.Queue()


def db():
    connection = sqlite3.connect(DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    return connection


def init_db():
    with db() as connection:
        connection.executescript(SCHEMA)
        connection.execute(
            "UPDATE scans SET status='error', error='Interrupted when the app stopped.', finished_at=? "
            "WHERE status IN ('queued','running')", (time.time(),))


def enqueue(domains, deep):
    """Queue scans, skipping domains that already have one queued or running."""
    queued, skipped = [], []
    with db() as connection:
        active = {r["domain"] for r in connection.execute(
            "SELECT DISTINCT domain FROM scans WHERE status IN ('queued','running')")}
        for domain in domains:
            if domain in active:
                skipped.append(domain)
                continue
            active.add(domain)
            cursor = connection.execute(
                "INSERT INTO scans(domain,status,stage,deep,requested_at) VALUES(?,?,?,?,?)",
                (domain, "queued", "Waiting", int(deep), time.time()))
            queued.append((cursor.lastrowid, domain, deep))
    for job in queued:
        jobs.put(job)
    return [j[1] for j in queued], skipped


def worker():
    while True:
        scan_id, domain, deep = jobs.get()
        try:
            run_scan(scan_id, domain, deep)
        except Exception:
            traceback.print_exc()
        finally:
            jobs.task_done()


def run_scan(scan_id, domain, deep):
    def progress(stage):
        with db() as connection:
            connection.execute("UPDATE scans SET status='running', stage=? WHERE id=?", (stage, scan_id))

    try:
        result = scanner.scan(domain, deep=deep, progress=progress)
    except scanner.ScanError as exc:
        fail_scan(scan_id, str(exc))
        return
    except Exception as exc:
        traceback.print_exc()
        fail_scan(scan_id, f"Scan failed: {type(exc).__name__}: {exc}")
        return
    counts = {s: 0 for s in ("critical", "high", "medium", "low")}
    for finding in result["findings"]:
        if finding["status"] == "fail":
            counts[finding["severity"]] += 1
    summary = {"factors": {k: v["score"] for k, v in result["factors"].items()}, "counts": counts}
    with db() as connection:
        connection.execute(
            "UPDATE scans SET status='done', stage=NULL, finished_at=?, score=?, grade=?, coverage=?, summary=?, "
            "result=? WHERE id=?",
            (time.time(), result["score"], result["grade"], result["coverage"], json.dumps(summary),
             json.dumps(result), scan_id))


def fail_scan(scan_id, message):
    with db() as connection:
        connection.execute("UPDATE scans SET status='error', stage=NULL, finished_at=?, error=? WHERE id=?",
                           (time.time(), message, scan_id))


def portfolio():
    """One row per domain: its latest scan state plus latest and previous completed results."""
    rows = {}
    with db() as connection:
        cursor = connection.execute(
            "SELECT id,domain,status,stage,deep,requested_at,finished_at,score,grade,coverage,summary,error "
            "FROM scans ORDER BY id")
        for scan in cursor:
            row = rows.setdefault(scan["domain"], {
                "domain": scan["domain"], "score": None, "previous_score": None, "grade": None,
                "coverage": None, "factors": {}, "counts": {}, "last_scanned": None, "scan_id": None})
            row["status"], row["stage"], row["error"] = scan["status"], scan["stage"], scan["error"]
            if scan["status"] == "done":
                row["previous_score"] = row["score"]
                summary = json.loads(scan["summary"] or "{}")
                row.update(score=scan["score"], grade=scan["grade"], coverage=scan["coverage"],
                           factors=summary.get("factors", {}), counts=summary.get("counts", {}),
                           last_scanned=scan["finished_at"], scan_id=scan["id"])
    pending = jobs.qsize()
    return {"domains": sorted(rows.values(), key=lambda r: r["domain"]), "queue": pending,
            "factors": {k: v[0] for k, v in scanner.FACTORS.items()}}


def domain_detail(domain):
    with db() as connection:
        history = connection.execute(
            "SELECT id,status,stage,deep,requested_at,finished_at,score,grade,coverage,error FROM scans "
            "WHERE domain=? ORDER BY id", (domain,)).fetchall()
        latest = connection.execute(
            "SELECT result FROM scans WHERE domain=? AND status='done' ORDER BY id DESC LIMIT 1", (domain,)).fetchone()
    if not history:
        return None
    return {"domain": domain, "history": [dict(h) for h in history],
            "latest": remediation.enrich(json.loads(latest["result"])) if latest else None}


def all_issues(domain=None):
    """Every failed check from each domain's latest completed scan, worst first."""
    query = ("SELECT result FROM scans WHERE id IN "
             "(SELECT MAX(id) FROM scans WHERE status='done' GROUP BY domain)")
    issues = []
    with db() as connection:
        for row in connection.execute(query):
            result = remediation.enrich(json.loads(row["result"]))
            if domain and result["domain"] != domain:
                continue
            for finding in result["findings"]:
                if finding["status"] == "fail":
                    issues.append({**finding, "domain": result["domain"], "scanned": result["finished"]})
    issues.sort(key=lambda f: (scanner.SEVERITY_ORDER[f["severity"]], f["domain"], f["title"]))
    return issues


def csv_safe(value):
    """Scanned sites control some of this text, so stop spreadsheets running it as a formula."""
    text = str(value or "")
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


def issues_csv(domain=None):
    """One row per affected URL or asset."""
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["domain", "severity", "factor", "issue", "affected", "url", "details", "summary_fix",
                     "why_it_matters", "fix_steps", "example", "verify", "references", "scanned_utc"])
    for item in all_issues(domain):
        guide = item.get("recommendation", {})
        steps = " ".join(f"{i}. {step}" for i, step in enumerate(guide.get("steps", []), 1))
        for target in item["affected"] or [{"label": item["domain"], "url": None}]:
            writer.writerow([csv_safe(v) for v in (
                item["domain"], item["severity"], item["factor_name"], item["title"], target["label"], target["url"],
                item["detail"], item["fix"], guide.get("why"), steps, guide.get("example"), guide.get("verify"),
                " ".join(guide.get("references", [])),
                time.strftime("%Y-%m-%d %H:%M", time.gmtime(item["scanned"])))])
    return out.getvalue().encode()


def portfolio_csv():
    data = portfolio()
    out = io.StringIO()
    keys = list(data["factors"])
    writer = csv.writer(out)
    writer.writerow(["domain", "grade", "score", "coverage_pct", *[data["factors"][k] for k in keys],
                     "critical", "high", "medium", "low", "last_scanned_utc"])
    for row in data["domains"]:
        when = time.strftime("%Y-%m-%d %H:%M", time.gmtime(row["last_scanned"])) if row["last_scanned"] else ""
        writer.writerow([row["domain"], row["grade"] or "", "" if row["score"] is None else row["score"],
                         "" if row["coverage"] is None else row["coverage"],
                         *["" if row["factors"].get(k) is None else row["factors"][k] for k in keys],
                         *[row["counts"].get(s, "") for s in ("critical", "high", "medium", "low")], when])
    return out.getvalue().encode()


class Handler(BaseHTTPRequestHandler):
    server_version = "DomainScorecard"
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def send_body(self, status, body, content_type, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data, status=200):
        self.send_body(status, json.dumps(data).encode(), "application/json")

    def trusted_request(self):
        """Stop other websites reaching this local API (DNS rebinding and CSRF)."""
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        if self.headers.get("Host") not in allowed:
            return False
        origin = self.headers.get("Origin")
        return not origin or urllib.parse.urlsplit(origin).netloc in allowed

    def guard(self):
        if self.trusted_request():
            return True
        self.send_json({"error": "Request refused: untrusted Host or Origin."}, 403)
        return False

    def do_GET(self):
        if not self.guard():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/portfolio":
            return self.send_json(portfolio())
        if path == "/api/export.csv":
            return self.send_body(200, portfolio_csv(), "text/csv; charset=utf-8",
                                  {"Content-Disposition": 'attachment; filename="domain-scorecard.csv"'})
        if path == "/api/issues":
            return self.send_json({"issues": all_issues()})
        if path == "/api/issues.csv":
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
            domain = scanner.normalize_domain(query.get("domain", [""])[0])
            name = f"{domain}-issues.csv" if domain else "all-issues.csv"
            return self.send_body(200, issues_csv(domain), "text/csv; charset=utf-8",
                                  {"Content-Disposition": f'attachment; filename="{name}"'})
        match = re.fullmatch(r"/api/domains/([^/]+)(/report\.json)?", path)
        if match:
            detail = domain_detail(urllib.parse.unquote(match.group(1)))
            if detail is None:
                return self.send_json({"error": "Domain not found."}, 404)
            if match.group(2):
                return self.send_body(200, json.dumps(detail, indent=2).encode(), "application/json", {
                    "Content-Disposition": f'attachment; filename="{detail["domain"]}-report.json"'})
            return self.send_json(detail)
        return self.serve_static(path)

    def serve_static(self, path):
        name = "index.html" if path == "/" else path.lstrip("/")
        target = (STATIC / name).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():
            return self.send_json({"error": "Not found."}, 404)
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        return self.send_body(200, target.read_bytes(), f"{content_type}; charset=utf-8")

    def do_POST(self):
        if not self.guard():
            return
        if self.path != "/api/scans":
            return self.send_json({"error": "Not found."}, 404)
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self.send_json({"error": "Expected JSON."}, 415)
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self.close_connection = True
            return self.send_json({"error": "Request is too large."}, 413)
        try:
            payload = json.loads(self.rfile.read(length))
            entries = payload["domains"]
            if not isinstance(entries, list):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            return self.send_json({"error": "Send {\"domains\": [...]}."}, 400)
        return self.send_json(submit(entries, payload.get("deep") is True, payload.get("authorized") is True))

    def do_DELETE(self):
        if not self.guard():
            return
        match = re.fullmatch(r"/api/domains/([^/]+)", urllib.parse.urlsplit(self.path).path)
        if not match:
            return self.send_json({"error": "Not found."}, 404)
        domain = urllib.parse.unquote(match.group(1))
        with db() as connection:
            active = connection.execute("SELECT 1 FROM scans WHERE domain=? AND status IN ('queued','running')",
                                        (domain,)).fetchone()
            if active:
                return self.send_json({"error": "This domain is being scanned. Try again when it finishes."}, 409)
            removed = connection.execute("DELETE FROM scans WHERE domain=?", (domain,)).rowcount
        return self.send_json({"removed": removed})


def submit(entries, deep, authorized):
    if deep and not authorized:
        return {"error": "Deep checks need confirmation that you are authorized.", "queued": [], "skipped": [],
                "invalid": []}
    seen, valid, invalid = set(), [], []
    for entry in entries:
        domain = scanner.normalize_domain(entry) if isinstance(entry, str) else None
        if domain is None:
            invalid.append(str(entry)[:100])
        elif domain not in seen:
            seen.add(domain)
            valid.append(domain)
    if len(valid) > MAX_BATCH:
        return {"error": f"A batch can have at most {MAX_BATCH} domains.", "queued": [], "skipped": [],
                "invalid": invalid[:50]}
    queued, skipped = enqueue(valid, deep)
    return {"queued": queued, "skipped": skipped, "invalid": invalid[:50]}


def read_domain_file(path):
    entries = []
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(re.split(r"[,;\s]", line, maxsplit=1)[0])
    return entries


def main():
    parser = argparse.ArgumentParser(description="Domain Scorecard local dashboard")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--domains", help="Text or CSV file of domains to queue at startup")
    args = parser.parse_args()

    init_db()
    for _ in range(WORKERS):
        threading.Thread(target=worker, daemon=True).start()
    if args.domains:
        result = submit(read_domain_file(args.domains), False, False)
        print(f"Queued {len(result['queued'])} domains; {len(result['invalid'])} invalid entries ignored.")
    # Bound to loopback on purpose: this app has no login.
    server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"Domain Scorecard is running at http://127.0.0.1:{args.port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
