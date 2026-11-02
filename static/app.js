"use strict";
// All remote-derived text (banners, certificate fields, DNS data) goes through
// textContent via h(), so a hostile scanned site can't inject markup here.

const view = document.getElementById("view");
const queueLabel = document.getElementById("queue");
const tooltip = document.getElementById("tooltip");
const state = { issueSearch: "", issueSeverity: "", sort: "domain", dir: 1, search: "", grade: "", draft: "", factor: "", poll: null, data: null, message: null, signature: "" };

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else if (key === "class") el.className = value;
    else if (key === "style") el.style.cssText = value; // the page CSP blocks style attributes, not CSSOM
    else if (key === "value") el.value = value;
    else el.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat(Infinity)) {
    if (child !== null && child !== undefined && child !== false) el.append(child);
  }
  return el;
}

function svg(tag, attrs, ...children) {
  const el = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [key, value] of Object.entries(attrs || {})) el.setAttribute(key, value);
  el.append(...children);
  return el;
}

async function api(path, options) {
  const response = await fetch(path, options);
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function gradeBadge(grade, big) {
  return h("span", { class: `grade ${grade || "none"}${big ? " big" : ""}`, title: grade ? `Grade ${grade}` : "Not graded" }, grade || "–");
}

function when(ts) {
  return ts ? new Date(ts * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : "–";
}

function parseEntries(text) {
  return text.split(/\r?\n/)
    .map((line) => line.split("#")[0])
    .flatMap((line) => line.split(/[,;\s]+/))
    .map((item) => item.trim())
    .filter(Boolean);
}

async function startScan(domains, deep, authorized) {
  const result = await api("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domains, deep, authorized }),
  });
  if (result.error) throw new Error(result.error);
  return result;
}

function describeResult(result) {
  const parts = [];
  if (result.queued.length) parts.push(`Queued ${result.queued.length} domain${result.queued.length === 1 ? "" : "s"}.`);
  if (result.skipped.length) parts.push(`${result.skipped.length} already in progress.`);
  if (result.invalid.length) parts.push(`Ignored ${result.invalid.length} invalid: ${result.invalid.slice(0, 5).join(", ")}${result.invalid.length > 5 ? "…" : ""}`);
  return parts.join(" ") || "Nothing to scan.";
}

// ----------------------------------------------------------- portfolio page

function scanForm() {
  const box = h("textarea", {
    placeholder: "Enter one domain, or paste a list\nexample.com\nanother-domain.org",
    "aria-label": "Domains to scan",
    value: state.draft,
    oninput: (e) => { state.draft = e.target.value; },
    onkeydown: (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) { e.preventDefault(); submit(); } },
  });
  const deep = h("input", { type: "checkbox", id: "deep" });
  const file = h("input", {
    type: "file", accept: ".txt,.csv,text/plain,text/csv", hidden: true,
    onchange: async (e) => {
      const chosen = e.target.files[0];
      if (!chosen) return;
      const lines = (await chosen.text()).split(/\r?\n/).map((l) => l.split(/[,;\t]/)[0]);
      state.draft = (box.value ? box.value + "\n" : "") + lines.join("\n");
      box.value = state.draft;
      e.target.value = "";
    },
  });
  const message = h("div", { class: "message small", role: "status" });
  if (state.message) {
    message.textContent = state.message.text;
    message.classList.toggle("error-text", state.message.error);
  }

  async function submit() {
    const domains = parseEntries(box.value);
    if (!domains.length) { state.message = { text: "Enter at least one domain.", error: true }; rerender(true); return; }
    try {
      const result = await startScan(domains, deep.checked, deep.checked);
      state.message = { text: describeResult(result), error: false };
      state.draft = "";
    } catch (error) {
      state.message = { text: error.message, error: true };
    }
    rerender(true);
  }

  return h("section", { class: "card" },
    h("h2", {}, "Scan domains"),
    box,
    h("div", { class: "scan-actions" },
      h("button", { class: "primary", onclick: submit }, "Run scan"),
      h("button", { onclick: () => file.click() }, "Upload list (.txt or .csv)"),
      file,
    ),
    h("label", { class: "check small", for: "deep" }, deep,
      h("span", {}, h("strong", {}, "Add deep checks. "),
        "I own these domains or have written permission to test them. This requests sensitive paths such as /.env and connects directly to risky ports, which can trigger security alerts.")),
    message,
  );
}

function tiles(rows) {
  const scored = rows.filter((r) => r.score !== null);
  const average = scored.length ? Math.round(scored.reduce((sum, r) => sum + r.score, 0) / scored.length) : "–";
  const atRisk = scored.filter((r) => r.grade === "D" || r.grade === "F").length;
  const critical = rows.reduce((sum, r) => sum + (r.counts.critical || 0), 0);
  const tile = (value, label) => h("div", { class: "tile" }, h("div", { class: "value" }, String(value)), h("div", { class: "muted small" }, label));
  return h("div", { class: "tiles" },
    tile(rows.length, "Domains"),
    tile(average, "Average score"),
    tile(atRisk, "Graded D or F"),
    tile(critical, "Critical findings"),
  );
}

function gradeBars(rows) {
  const scored = rows.filter((r) => r.grade);
  const grades = ["A", "B", "C", "D", "F"];
  const counts = grades.map((g) => scored.filter((r) => r.grade === g).length);
  const max = Math.max(1, ...counts);
  return h("section", { class: "card" },
    h("h2", {}, "Grade distribution"),
    h("div", { class: "bars" }, grades.map((g, i) =>
      h("div", { class: "bar-row", title: `${g}: ${counts[i]} domain${counts[i] === 1 ? "" : "s"}` },
        h("span", {}, g),
        h("div", { class: "track" }, h("div", { class: "fill", style: `width:${(counts[i] / max) * 100}%` })),
        h("span", { class: "num" }, String(counts[i]))))),
  );
}

function sortValue(row, key) {
  if (key === "domain") return row.domain;
  if (key === "score") return row.score;
  if (key === "scanned") return row.last_scanned;
  if (key === "critical" || key === "high") return row.counts[key] ?? null;
  return row.factors[key] ?? null;
}

function sortedRows(rows) {
  const filtered = rows.filter((r) =>
    (!state.search || r.domain.includes(state.search.toLowerCase())) &&
    (!state.grade || (state.grade === "none" ? !r.grade : r.grade === state.grade)));
  return filtered.sort((a, b) => {
    const x = sortValue(a, state.sort), y = sortValue(b, state.sort);
    if (x === null && y === null) return a.domain.localeCompare(b.domain);
    if (x === null) return 1;   // unscored rows stay last in either direction
    if (y === null) return -1;
    return (x < y ? -1 : x > y ? 1 : 0) * state.dir || a.domain.localeCompare(b.domain);
  });
}

function header(label, key, numeric) {
  const active = state.sort === key;
  return h("th", { class: numeric ? "num" : null, "aria-sort": active ? (state.dir > 0 ? "ascending" : "descending") : null },
    h("button", {
      onclick: () => {
        if (state.sort === key) state.dir = -state.dir;
        else { state.sort = key; state.dir = key === "domain" ? 1 : -1; }
        rerender(true);
      },
    }, label + (active ? (state.dir > 0 ? " ↑" : " ↓") : "")));
}

function statusCell(row) {
  if (row.status === "running") return h("span", { class: "running" }, row.stage || "Scanning");
  if (row.status === "queued") return h("span", { class: "muted" }, "Queued");
  if (row.status === "error") return h("span", { class: "error-text", title: row.error }, row.score === null ? "Failed" : "Last rescan failed");
  return h("span", { class: "muted" }, when(row.last_scanned));
}

function table(data) {
  const rows = sortedRows(data.domains);
  const factorKeys = Object.keys(data.factors);
  const short = { network: "Network", patching: "Patching", web: "App", email: "Email", dns: "DNS", reputation: "Reputation", surface: "Surface" };
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {},
      header("Domain", "domain"), header("Score", "score", true), h("th", {}, "Change"),
      factorKeys.map((k) => header(short[k] || k, k, true)),
      header("Critical", "critical", true), header("High", "high", true),
      header("Last scan", "scanned"), h("th", {}, h("span", { hidden: true }, "Actions")))),
    h("tbody", {}, rows.map((row) => {
      const change = row.score !== null && row.previous_score !== null ? row.score - row.previous_score : null;
      return h("tr", {},
        h("td", { class: "domain" }, h("a", { href: `#/d/${encodeURIComponent(row.domain)}` }, row.domain)),
        h("td", { class: "num" }, h("span", { style: "display:inline-flex;gap:8px;align-items:center" },
          row.score === null ? "–" : String(row.score), gradeBadge(row.grade))),
        h("td", { class: "muted" }, change === null ? "–" : change === 0 ? "No change" : `${change > 0 ? "▲ +" : "▼ "}${change}`),
        factorKeys.map((k) => h("td", { class: "num" }, row.factors[k] === undefined || row.factors[k] === null ? "–" : String(row.factors[k]))),
        h("td", { class: "num" }, String(row.counts.critical ?? "–")),
        h("td", { class: "num" }, String(row.counts.high ?? "–")),
        h("td", {}, statusCell(row)),
        h("td", {}, h("button", {
          class: "small", disabled: row.status === "running" || row.status === "queued",
          onclick: async () => { await startScan([row.domain], false, false); rerender(true); },
        }, "Rescan")));
    })),
  ));
}

function renderPortfolio(data) {
  const blocks = [scanForm()];
  if (!data.domains.length) {
    blocks.push(h("section", { class: "card empty" }, "No domains yet. Enter one above or upload your list to get started."));
    return blocks;
  }
  blocks.push(tiles(data.domains), gradeBars(data.domains));
  const search = h("input", {
    type: "search", placeholder: "Filter domains", "aria-label": "Filter domains", value: state.search,
    oninput: (e) => { state.search = e.target.value; const pane = document.getElementById("rows"); pane.replaceChildren(table(data)); },
  });
  const grade = h("select", {
    "aria-label": "Filter by grade",
    onchange: (e) => { state.grade = e.target.value; document.getElementById("rows").replaceChildren(table(data)); },
  }, [["", "All grades"], ["A", "A"], ["B", "B"], ["C", "C"], ["D", "D"], ["F", "F"], ["none", "Not graded"]].map(([value, label]) =>
    h("option", { value, selected: state.grade === value }, label)));
  blocks.push(h("section", { class: "card" },
    h("div", { class: "toolbar" }, h("div", { class: "filters" }, search, grade),
      h("div", { class: "filters" }, h("a", { class: "button", href: "#/issues" }, "View all issues"),
        h("a", { class: "button", href: "/api/issues.csv" }, "Export issues CSV"),
        h("a", { class: "button", href: "/api/export.csv" }, "Export scores CSV"))),
    h("div", { id: "rows" }, table(data)),
  ));
  return blocks;
}

// ----------------------------------------------------------- domain page

function trendChart(history) {
  const points = history.filter((s) => s.status === "done" && s.score !== null);
  if (points.length < 2) {
    return h("p", { class: "muted" }, "The trend appears after a second completed scan.");
  }
  const W = 520, H = 170, L = 30, R = 12, T = 10, B = 26;
  const first = points[0].finished_at, last = points[points.length - 1].finished_at;
  const x = (t) => L + ((t - first) / Math.max(1, last - first)) * (W - L - R);
  const y = (s) => T + (1 - s / 100) * (H - T - B);
  const root = svg("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": `Score trend across ${points.length} scans` });
  for (const tick of [0, 50, 100]) {
    root.append(svg("line", { class: "gridline", x1: L, x2: W - R, y1: y(tick), y2: y(tick) }));
    const label = svg("text", { x: L - 6, y: y(tick) + 4, "text-anchor": "end" }); label.textContent = tick; root.append(label);
  }
  const dateLabel = (t, xPos, anchor) => {
    const el = svg("text", { x: xPos, y: H - 7, "text-anchor": anchor });
    el.textContent = new Date(t * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" });
    root.append(el);
  };
  dateLabel(first, L, "start"); dateLabel(last, W - R, "end");
  root.append(svg("polyline", { class: "line", points: points.map((p) => `${x(p.finished_at)},${y(p.score)}`).join(" ") }));
  for (const point of points) {
    const hit = svg("circle", { class: "hit", cx: x(point.finished_at), cy: y(point.score), r: 13, tabindex: 0 });
    const text = `${when(point.finished_at)}: ${point.score} (${point.grade})`;
    const show = (e) => {
      const box = hit.getBoundingClientRect();
      tooltip.textContent = text; tooltip.hidden = false;
      const tipBox = tooltip.getBoundingClientRect();
      tooltip.style.left = `${Math.min(window.innerWidth - tipBox.width - 8, Math.max(8, box.left + box.width / 2 - tipBox.width / 2))}px`;
      tooltip.style.top = `${Math.max(8, box.top - tipBox.height - 4)}px`;
    };
    const hide = () => { tooltip.hidden = true; };
    hit.addEventListener("mouseenter", show); hit.addEventListener("focus", show);
    hit.addEventListener("mouseleave", hide); hit.addEventListener("blur", hide);
    root.append(hit, svg("circle", { class: "dot", cx: x(point.finished_at), cy: y(point.score), r: 4 }));
  }
  return h("div", { class: "chart" }, root);
}

function externalLink(url, label) {
  return h("a", { href: url, target: "_blank", rel: "noopener noreferrer" }, label);
}

function affectedList(item) {
  if (!item.affected || !item.affected.length) return null;
  const heading = item.status === "fail" ? "Affected" : "Checked";
  return h("div", { class: "block" },
    h("h4", {}, `${heading} (${item.affected.length})`),
    h("ul", { class: "affected" }, item.affected.map((target) => {
      if (!target.url) return h("li", {}, target.label);
      const rest = target.label.startsWith(target.url) ? target.label.slice(target.url.length) : null;
      return h("li", {}, rest === null ? externalLink(target.url, target.label) : [externalLink(target.url, target.url), rest]);
    })));
}

function recommendation(item) {
  const guide = item.recommendation;
  if (!guide) return item.fix ? h("div", { class: "block" }, h("h4", {}, "How to fix"), h("p", {}, item.fix)) : null;
  return [
    guide.why && h("div", { class: "block" }, h("h4", {}, "Why it matters"), h("p", {}, guide.why)),
    h("div", { class: "block" }, h("h4", {}, "How to fix"),
      item.fix && h("p", {}, item.fix),
      guide.steps && h("ol", {}, guide.steps.map((step) => h("li", {}, step)))),
    guide.example && h("div", { class: "block" }, h("h4", {}, "Example"), h("pre", {}, guide.example)),
    guide.verify && h("div", { class: "block" }, h("h4", {}, "Check the fix"), h("pre", {}, guide.verify)),
    guide.references && h("div", { class: "block" }, h("h4", {}, "References"),
      h("ul", { class: "affected" }, guide.references.map((url) => h("li", {}, externalLink(url, url))))),
  ];
}

function finding(item, options) {
  const opts = options || {};
  const label = item.status === "fail" ? item.severity : item.status === "pass" ? "pass" : item.status === "unknown" ? "unknown" : "info";
  const names = { critical: "Critical", high: "High", medium: "Medium", low: "Low", pass: "Passed", unknown: "Unknown", info: "Info" };
  const count = (item.affected || []).length;
  const showGuide = item.status === "fail" || item.status === "unknown";
  return h("details", { class: "finding", open: !!opts.open },
    h("summary", {},
      h("span", { class: `pill ${label}` }, names[label]),
      h("span", { class: "title" }, opts.domain ? `${item.domain}: ${item.title}` : item.title),
      count > 0 && item.status === "fail" && h("span", { class: "muted small" }, `${count} affected`),
      h("span", { class: "muted small factor-name" }, item.factor_name)),
    h("div", { class: "body" },
      item.detail && h("p", {}, item.detail),
      affectedList(item),
      showGuide && recommendation(item)),
  );
}

function expandButtons(scope) {
  const toggle = (open) => () => document.querySelectorAll(`${scope} details.finding`).forEach((d) => { d.open = open; });
  return [h("button", { class: "small", onclick: toggle(true) }, "Expand all"), h("button", { class: "small", onclick: toggle(false) }, "Collapse all")];
}

// ----------------------------------------------------------- all-issues page

function renderIssues(issues) {
  const severities = ["critical", "high", "medium", "low"];
  const pane = h("div", { id: "issue-list" });
  const draw = () => {
    const text = state.issueSearch.toLowerCase();
    const shown = issues.filter((i) => (!state.issueSeverity || i.severity === state.issueSeverity) &&
      (!text || `${i.domain} ${i.title} ${(i.affected || []).map((a) => a.label).join(" ")}`.toLowerCase().includes(text)));
    pane.replaceChildren(
      h("p", { class: "muted small" }, `Showing ${shown.length} of ${issues.length} issues`),
      ...shown.map((i) => finding(i, { domain: true })));
  };
  draw();
  return [
    h("a", { class: "back", href: "#/" }, "← All domains"),
    h("div", { class: "tiles" }, severities.map((s) => h("div", { class: "tile" },
      h("div", { class: "value" }, String(issues.filter((i) => i.severity === s).length)),
      h("div", { class: "muted small" }, `${s[0].toUpperCase()}${s.slice(1)} issues`)))),
    h("section", { class: "card" },
      h("div", { class: "toolbar" },
        h("div", { class: "filters" },
          h("input", { type: "search", placeholder: "Filter by domain, issue or URL", "aria-label": "Filter issues", value: state.issueSearch,
            oninput: (e) => { state.issueSearch = e.target.value; draw(); } }),
          h("select", { "aria-label": "Filter by severity", onchange: (e) => { state.issueSeverity = e.target.value; draw(); } },
            h("option", { value: "" }, "All severities"),
            severities.map((s) => h("option", { value: s, selected: state.issueSeverity === s }, `${s[0].toUpperCase()}${s.slice(1)}`)))),
        h("div", { class: "filters" }, expandButtons("#issue-list"), h("a", { class: "button", href: "/api/issues.csv" }, "Export issues CSV"))),
      issues.length ? pane : h("p", { class: "empty" }, "No issues yet. Scan a domain to see results here.")),
  ];
}

function renderDomain(detail) {
  const latest = detail.latest;
  const current = detail.history[detail.history.length - 1];
  const busy = current.status === "queued" || current.status === "running";
  const blocks = [h("a", { class: "back", href: "#/" }, "← All domains")];
  let confirmDelete = false;
  const remove = h("button", {
    class: "danger", disabled: busy,
    onclick: async (e) => {
      if (!confirmDelete) { confirmDelete = true; e.target.textContent = "Confirm: delete all history"; return; }
      await api(`/api/domains/${encodeURIComponent(detail.domain)}`, { method: "DELETE" });
      location.hash = "#/";
    },
  }, "Delete");

  blocks.push(h("section", { class: "card hero" },
    gradeBadge(latest && latest.grade, true),
    h("div", { class: "grow" },
      h("h1", {}, detail.domain),
      h("div", { class: "score" }, latest
        ? (latest.score === null ? "Not enough data for a grade" : `Score ${latest.score} of 100`) + ` · ${latest.coverage}% of checks by weight ran`
        : "No completed scan yet"),
      h("div", { class: "muted small" }, busy
        ? h("span", { class: "running" }, current.stage || "Queued")
        : latest ? `Scanned ${when(latest.finished)}${latest.deep ? " · included deep checks" : ""}` : ""),
      current.status === "error" && h("div", { class: "error-text small" }, current.error)),
    h("div", { class: "actions" },
      h("button", { class: "primary", disabled: busy, onclick: async () => { await startScan([detail.domain], false, false); rerender(true); } }, busy ? "Scanning…" : "Rescan"),
      latest && h("a", { class: "button", href: `/api/issues.csv?domain=${encodeURIComponent(detail.domain)}` }, "Export issues CSV"),
      latest && h("a", { class: "button", href: `/api/domains/${encodeURIComponent(detail.domain)}/report.json` }, "Download JSON"),
      remove),
  ));
  if (!latest) return blocks;

  blocks.push(h("div", { class: "two" },
    h("section", { class: "card" }, h("h2", {}, "Factor scores"),
      Object.entries(latest.factors).map(([key, factor]) =>
        h("button", {
          class: `factor${state.factor === key ? " on" : ""}`, "aria-pressed": state.factor === key ? "true" : "false",
          title: `Weight ${factor.weight}%. Click to filter findings.`,
          onclick: () => { state.factor = state.factor === key ? "" : key; rerender(true); },
        },
          h("span", {}, factor.name),
          h("span", { class: "track" }, h("div", { class: "fill", style: `width:${factor.score ?? 0}%` })),
          h("span", { class: "val" }, factor.score === null ? "No data" : `${factor.score} ${factor.grade}`)))),
    h("section", { class: "card" }, h("h2", {}, "Score history"), trendChart(detail.history)),
  ));

  const items = latest.findings.filter((f) => !state.factor || f.factor === state.factor);
  const failing = items.filter((f) => f.status === "fail");
  const unknown = items.filter((f) => f.status === "unknown");
  const passed = items.filter((f) => f.status === "pass");
  const notes = items.filter((f) => f.status === "info");
  const group = (title, list, open) => list.length ? [h("h3", { class: "section-title" }, `${title} (${list.length})`), list.map((f) => finding(f, { open }))] : [];
  blocks.push(h("section", { class: "card", id: "findings" },
    h("div", { class: "toolbar" },
      h("h2", {}, state.factor ? `Findings: ${latest.factors[state.factor].name}` : "Findings"),
      h("div", { class: "filters" }, expandButtons("#findings"))),
    group("Issues", failing, true), group("Could not verify", unknown), group("Passed", passed), group("Notes", notes),
    !items.length && h("p", { class: "muted" }, "Nothing recorded for this factor."),
  ));

  const assets = latest.assets;
  blocks.push(h("section", { class: "card" }, h("h2", {}, "Discovered assets"),
    h("dl", { class: "assets" },
      h("div", {}, h("dt", {}, "Host tested"), h("dd", {}, assets.primary_host)),
      h("div", {}, h("dt", {}, "Mail servers"), h("dd", {}, assets.mail_servers.join(", ") || "None")),
      h("div", {}, h("dt", {}, `IP addresses (${assets.ips.length})`), h("dd", {}, assets.ips.join(", ") || "None")),
      h("div", {}, h("dt", {}, `Live subdomains (${assets.live_subdomains.length})`), h("dd", {}, assets.live_subdomains.join(", ") || "None")),
      assets.hosts_tested && h("div", {}, h("dt", {}, `Hosts given web and TLS checks (${assets.hosts_tested.length})`), h("dd", {}, assets.hosts_tested.join(", "))),
    )));

  blocks.push(h("section", { class: "card" }, h("h2", {}, "Scan history"),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Date"), h("th", { class: "num" }, "Score"), h("th", {}, "Grade"), h("th", { class: "num" }, "Coverage"), h("th", {}, "Result"))),
      h("tbody", {}, detail.history.slice().reverse().map((s) => h("tr", {},
        h("td", {}, when(s.finished_at || s.requested_at)),
        h("td", { class: "num" }, s.score === null ? "–" : String(s.score)),
        h("td", {}, s.grade || "–"),
        h("td", { class: "num" }, s.coverage === null ? "–" : `${s.coverage}%`),
        h("td", {}, s.status === "error" ? s.error : s.status === "done" ? (s.deep ? "Done, deep" : "Done") : s.status))))))));
  return blocks;
}

// ----------------------------------------------------------- routing and refresh

function route() {
  const match = location.hash.match(/^#\/d\/(.+)$/);
  return match ? decodeURIComponent(match[1]) : null;
}

let rendering = false;
async function rerender(force) {
  if (rendering) return;
  rendering = true;
  clearTimeout(state.poll);
  let active = false;
  try {
    const domain = route();
    // Background refreshes must not wipe text being typed or expanded findings.
    const editing = document.activeElement && ["TEXTAREA", "INPUT", "SELECT"].includes(document.activeElement.tagName);
    if (location.hash === "#/issues") {
      const { issues } = await api("/api/issues");
      const portfolioData = await api("/api/portfolio");
      active = portfolioData.domains.some((r) => r.status === "queued" || r.status === "running");
      const signature = JSON.stringify(["issues", issues.length, issues.map((i) => i.scanned)]);
      if (force || (signature !== state.signature && !editing)) {
        view.replaceChildren(...renderIssues(issues));
        state.signature = signature;
      }
      queueLabel.textContent = "";
    } else if (domain) {
      const detail = await api(`/api/domains/${encodeURIComponent(domain)}`);
      const current = detail.history[detail.history.length - 1];
      active = current.status === "queued" || current.status === "running";
      const signature = JSON.stringify([domain, state.factor, detail.history]);
      if (force || signature !== state.signature) {
        const open = new Set([...view.querySelectorAll("details[open] .title")].map((n) => n.textContent));
        view.replaceChildren(...renderDomain(detail));
        view.querySelectorAll("details").forEach((d) => { if (open.has(d.querySelector(".title").textContent)) d.open = true; });
        state.signature = signature;
      }
      queueLabel.textContent = "";
    } else {
      const data = await api("/api/portfolio");
      state.data = data;
      active = data.domains.some((r) => r.status === "queued" || r.status === "running");
      const signature = JSON.stringify(["list", data.domains]);
      if (force || (signature !== state.signature && !editing)) {
        view.replaceChildren(...renderPortfolio(data));
        state.signature = signature;
      }
      const running = data.domains.filter((r) => r.status === "running").length;
      const waiting = data.domains.filter((r) => r.status === "queued").length;
      queueLabel.textContent = running + waiting ? `Scanning ${running}, ${waiting} waiting` : "";
    }
  } catch (error) {
    view.replaceChildren(h("section", { class: "card empty" }, error.message, h("div", {}, h("a", { href: "#/" }, "Back to all domains"))));
  } finally {
    rendering = false;
    state.poll = setTimeout(() => rerender(false), active ? 2000 : 10000);
  }
}

window.addEventListener("hashchange", () => { state.factor = ""; tooltip.hidden = true; rerender(true); });
rerender(true);
