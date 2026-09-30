const select = (selector) => document.querySelector(selector);
const escape = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ],
  );
const icons = () => window.lucide?.createIcons();
let session;
let report;
let stages = [];
let catalog = [];
let stageIndex = 0;
let selectedTest;

async function api(path, options = {}) {
  const response = await fetch(`/api/${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(session?.csrf ? { "X-CSRF-Token": session.csrf } : {}),
      ...options.headers,
    },
  });
  const value = await response.json();
  if (!response.ok)
    throw new Error(value.error || `Request failed (${response.status})`);
  return value;
}
function table(headings, rows, empty) {
  if (!rows.length) return `<p class="empty">${escape(empty)}</p>`;
  return `<div class="table-wrap"><table><thead><tr>${headings.map((heading) => `<th scope="col">${escape(heading)}</th>`).join("")}</tr></thead><tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${escape(cell)}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}
function navigate() {
  const view = location.hash.slice(1) || "overview";
  const titles = {
    overview: "Code to Cloud Security Dojo",
    story: "Code-to-cloud story",
    findings: "Findings & alerts",
    lab: "Admin lab",
    status: "Deployment status",
    reports: "Executive reports",
  };
  const active = Object.hasOwn(titles, view) ? view : "overview";
  for (const panel of document.querySelectorAll("[data-panel]"))
    panel.hidden = panel.dataset.panel !== active;
  for (const link of document.querySelectorAll("[data-view]"))
    link.setAttribute(
      "aria-current",
      link.dataset.view === active ? "page" : "false",
    );
  select("#page-title").textContent = titles[active];
}
function showError(error) {
  select("#error").textContent = error.message;
  select("#error").hidden = false;
}
function renderFindings() {
  const filter = select("#finding-filter").value;
  select("#findings").innerHTML = table(
    ["Assessment", "Status", "Evidence"],
    report.findings
      .filter((item) => filter === "all" || item.state === filter)
      .map((item) => [item.title, item.state, item.description || item.id]),
    "No assessments returned. Coverage and ingestion are not yet verified.",
  );
}
function renderStory() {
  const stage = stages[stageIndex];
  if (!stage) return;
  select("#story-number").textContent =
    `STAGE ${stageIndex + 1} OF ${stages.length}`;
  select("#story-title").textContent = stage.title;
  select("#story-text").textContent = stage.text;
  select("#story-steps").innerHTML = stages
    .map(
      (item, index) =>
        `<button role="tab" aria-selected="${index === stageIndex}" data-stage="${index}">${escape(item.title)}</button>`,
    )
    .join("");
  select("#story-evidence").innerHTML =
    `<dl><dt>Repository</dt><dd>${escape(report.source.repository)}</dd><dt>Revision</dt><dd><code>${escape(report.source.revision)}</code></dd><dt>Image digest</dt><dd><code>${escape(report.release?.dojoDigest || "Not deployed / not collected")}</code></dd><dt>Observed at</dt><dd>${escape(report.generatedAt)}</dd></dl>`;
  select("#previous").disabled = stageIndex === 0;
  select("#next").disabled = stageIndex === stages.length - 1;
}
function render() {
  const live = report.mode === "live";
  const enabled = report.checks.filter(
    (check) => check.state === "enabled",
  ).length;
  const gaps = report.checks.filter((check) =>
    ["gap", "unknown", "pending"].includes(check.state),
  ).length;
  select("#scope").textContent =
    `${report.scope.resourceGroup} / ${report.scope.location} / ${report.scope.subscriptionId}`;
  select("#outcome-title").textContent = live
    ? gaps
      ? "Verification pending"
      : "Configuration observed"
    : "Not live-verified";
  select("#outcome-detail").textContent = live
    ? `${gaps} unresolved checks. Assessment and detection require separate evidence.`
    : "Read-only preview. No Azure collection or test execution.";
  select("#collected").textContent = live
    ? "LIVE OBSERVATIONS"
    : "NOT COLLECTED";
  select("#metrics").innerHTML = [
    [live ? report.resources.length : "--", "Resources observed"],
    [live ? enabled : "--", "Defender plans enabled"],
    [
      live
        ? report.findings.filter((item) => item.state === "Unhealthy").length
        : "--",
      "Unhealthy assessments",
    ],
    [live ? report.alerts.length : "--", "Target-scoped alerts"],
  ]
    .map(
      ([value, label]) =>
        `<div class="metric"><span class="value">${escape(value)}</span><span class="label">${escape(label)}</span></div>`,
    )
    .join("");
  select("#coverage").innerHTML = table(
    ["Control", "State", "Readback"],
    report.checks.map((check) => [check.id, check.state, check.detail]),
    "No control readback yet. Plan enablement alone does not demonstrate protection.",
  );
  renderFindings();
  select("#alerts").innerHTML = table(
    ["Alert", "Severity", "Activity time"],
    report.alerts.map((alert) => [alert.title, alert.severity, alert.time]),
    "No target-scoped alerts collected. This is not proof of prevention.",
  );
  select("#runs").innerHTML = table(
    ["Test / run", "Request result", "Alert evidence"],
    report.runs.map((run) => [
      `${run.testId} / ${run.id}`,
      `${run.state}${run.httpStatus ? ` / HTTP ${run.httpStatus}` : ""}`,
      `${run.candidateAlertIds?.length || 0} resource/time candidates. ${run.attribution}`,
    ]),
    "No recorded test runs.",
  );
  select("#binding").innerHTML = Object.entries({
    ...report.scope,
    dojoDigest: report.release?.dojoDigest || "Not collected",
    portalDigest: report.release?.portalDigest || "Not collected",
  })
    .map(([key, value]) => `<dt>${escape(key)}</dt><dd>${escape(value)}</dd>`)
    .join("");
  select("#resources").innerHTML = table(
    ["Resource", "Type", "Location"],
    report.resources.map((resource) => [
      resource.name,
      resource.type,
      resource.location,
    ]),
    "Resource inventory has not been collected.",
  );
  select("#limitations").innerHTML = report.limitations
    .map((item) => `<li>${escape(item)}</li>`)
    .join("");
  select("#report-summary").textContent =
    `${report.generatedAt} / ${report.mode}. Scope, coverage, findings, test evidence, limitations and executive actions.`;
  select("#tests").innerHTML = catalog
    .map(
      (test) =>
        `<article class="test"><i data-lucide="${test.id === "health" ? "heart-pulse" : "flask-conical"}"></i><p class="eyebrow">${escape(test.kind)}</p><h3>${escape(test.title)}</h3><p>${escape(test.expected)}</p><button data-test="${escape(test.id)}" ${session.preview ? "disabled" : ""}><i data-lucide="play"></i>Run test</button></article>`,
    )
    .join("");
  renderStory();
  icons();
}
async function refresh() {
  select("#refresh").disabled = true;
  select("#error").hidden = true;
  try {
    report = await api("report");
    render();
  } catch (error) {
    showError(error);
  } finally {
    select("#refresh").disabled = false;
  }
}
async function initialize() {
  try {
    session = await api("session");
    const accessible = session.user || session.preview;
    select("#login").hidden = !!accessible;
    select("#workspace").hidden = !accessible;
    select("#logout").hidden = !session.user;
    select("#identity").textContent =
      session.user || (session.preview ? "Read-only preview" : "Not signed in");
    select("#notice").hidden = !session.preview;
    select("#notice").textContent =
      "PREVIEW / No Azure calls. Credentials, resources and protection have not been verified.";
    if (accessible) {
      [stages, catalog] = await Promise.all([api("story"), api("tests")]);
      await refresh();
    }
  } catch (error) {
    showError(error);
  }
  navigate();
  icons();
}
select("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector("button");
  button.disabled = true;
  try {
    await api("login", {
      method: "POST",
      body: JSON.stringify(Object.fromEntries(new FormData(form))),
    });
    form.password.value = "";
    await initialize();
  } catch (error) {
    select("#login-error").textContent = error.message;
  } finally {
    button.disabled = false;
  }
});
select("#logout").addEventListener("click", async () => {
  try {
    await api("logout", { method: "POST", body: "{}" });
    report = null;
    await initialize();
  } catch (error) {
    showError(error);
  }
});
select("#refresh").addEventListener("click", refresh);
select("#finding-filter").addEventListener("change", renderFindings);
select("#story-steps").addEventListener("click", (event) => {
  const button = event.target.closest("[data-stage]");
  if (button) {
    stageIndex = Number(button.dataset.stage);
    renderStory();
  }
});
select("#previous").addEventListener("click", () => {
  stageIndex--;
  renderStory();
});
select("#next").addEventListener("click", () => {
  stageIndex++;
  renderStory();
});
select("#tests").addEventListener("click", (event) => {
  const button = event.target.closest("[data-test]");
  if (!button || session.preview) return;
  selectedTest = catalog.find((test) => test.id === button.dataset.test);
  select("#consent-title").textContent = selectedTest.title;
  select("#consent-expectation").textContent = selectedTest.expected;
  select("#authorized").checked = false;
  select("#execute").disabled = true;
  select("#consent").showModal();
});
select("#authorized").addEventListener("change", (event) => {
  select("#execute").disabled = !event.target.checked;
});
select("#consent").addEventListener("close", async (event) => {
  if (event.target.returnValue !== "execute" || !select("#authorized").checked)
    return;
  for (const button of document.querySelectorAll("[data-test]"))
    button.disabled = true;
  try {
    await api(`tests/${selectedTest.id}`, {
      method: "POST",
      body: JSON.stringify({ confirm: "authorized-training" }),
    });
    await refresh();
  } catch (error) {
    showError(error);
  } finally {
    for (const button of document.querySelectorAll("[data-test]"))
      button.disabled = !!session.preview;
  }
});
async function compare() {
  const before = select("#before").files[0];
  const after = select("#after").files[0];
  if (!before || !after) return;
  try {
    if (before.size > 2e6 || after.size > 2e6)
      throw new Error("Snapshots must be under 2 MB");
    const snapshots = await Promise.all(
      [before, after].map(async (file) => JSON.parse(await file.text())),
    );
    if (
      snapshots.some(
        (item) =>
          item.schemaVersion !== 1 ||
          !Array.isArray(item.findings) ||
          !Array.isArray(item.alerts) ||
          !item.scope,
      )
    )
      throw new Error("Select version 1 dojo report snapshots");
    if (
      JSON.stringify(snapshots[0].scope) !== JSON.stringify(snapshots[1].scope)
    )
      throw new Error("Snapshots have different scopes; comparison refused");
    const unhealthy = (snapshot) =>
      snapshot.findings.filter((item) => item.state === "Unhealthy").length;
    select("#comparison").textContent =
      `Unhealthy assessments: ${unhealthy(snapshots[0])} -> ${unhealthy(snapshots[1])}. Alerts: ${snapshots[0].alerts.length} -> ${snapshots[1].alerts.length}. Source: ${snapshots[0].source?.revision || "unknown"} -> ${snapshots[1].source?.revision || "unknown"}. Counts reflect collection times, not proven remediation or prevention.`;
  } catch (error) {
    select("#comparison").textContent = error.message;
  }
}
select("#before").addEventListener("change", compare);
select("#after").addEventListener("change", compare);
select("#theme").addEventListener("click", () => {
  const theme =
    document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = theme;
  localStorage.setItem("dojo-theme", theme);
});
try {
  document.documentElement.dataset.theme =
    localStorage.getItem("dojo-theme") === "dark" ? "dark" : "light";
} catch {}
window.addEventListener("hashchange", navigate);
initialize();
