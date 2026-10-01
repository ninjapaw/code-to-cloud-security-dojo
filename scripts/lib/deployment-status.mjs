import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const stages = [
  ["doctor", "Preflight"],
  ["provision", "Foundation"],
  ["protection", "Defender protection"],
  ["build", "Build and scan"],
  ["what-if", "Release preview"],
  ["deploy", "Release"],
  ["verify", "Verification"],
  ["report", "Evidence report"],
];
const additionalStages = {
  repair: "Repair release",
  rotate: "Credential rotation",
  inventory: "Removal inventory",
  deprovision: "Teardown",
};

const escapeHtml = (value) =>
  String(value).replace(
    /[&<>"']/g,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character],
  );

export function renderDeploymentStatus(state) {
  const completed = state.stages.filter(
    (stage) => stage.state === "succeeded",
  ).length;
  const current = state.stages.find((stage) => stage.state === "in_progress");
  const failed = state.stages.find((stage) => stage.state === "failed");
  const title = current
    ? `${current.label} in progress`
    : failed
      ? `${failed.label} needs attention`
      : "Deployment status";
  const rows = state.stages
    .map(
      (stage) => `
      <li class="step ${stage.state}">
        <span class="marker" aria-hidden="true"></span>
        <span class="step-body"><strong>${escapeHtml(stage.label)}</strong><small>${escapeHtml(stage.detail || "Not started")}</small></span>
        <span class="badge">${escapeHtml(stage.state.replaceAll("_", " "))}</span>
      </li>`,
    )
    .join("");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  ${current ? '<meta http-equiv="refresh" content="5">' : ""}
  <title>Deployment status | Code to Cloud Security Dojo</title>
  <style>
    :root { color-scheme: light; --ink: #20272c; --muted: #52616a; --line: #d5dedb; --good: #14745c; --work: #1c6785; --bad: #b34132; --observed: #946412; --background: #f5f8f6; }
    * { box-sizing: border-box; }
    body { margin: 0; background: var(--background); color: var(--ink); font: 15px/1.5 Verdana, sans-serif; }
    header { border-bottom: 1px solid var(--line); background: #fff; }
    main, header > div { max-width: 880px; margin: 0 auto; padding: 24px; }
    h1 { margin: 0 0 8px; font: 600 28px/1.2 Georgia, serif; }
    p { margin: 0; color: var(--muted); overflow-wrap: anywhere; }
    .eyebrow { color: var(--good); font-size: 12px; font-weight: bold; text-transform: uppercase; }
    .summary { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px; margin: 4px 0 20px; }
    .summary strong { color: var(--ink); }
    progress { display: block; width: 100%; height: 8px; margin: 0 0 26px; accent-color: var(--good); }
    ol { padding: 0; margin: 0; list-style: none; border-top: 1px solid var(--line); }
    .step { display: flex; gap: 14px; align-items: center; min-height: 76px; padding: 14px 2px; border-bottom: 1px solid var(--line); }
    .marker { width: 12px; height: 12px; flex: 0 0 12px; border: 2px solid #899a95; border-radius: 50%; }
    .succeeded .marker { border-color: var(--good); background: var(--good); }
    .in_progress .marker { border-color: var(--work); background: var(--work); }
    .failed .marker { border-color: var(--bad); background: var(--bad); }
    .observed .marker { border-color: var(--observed); background: var(--observed); }
    .step-body { display: grid; gap: 2px; min-width: 0; flex: 1; }
    .step-body small { color: var(--muted); overflow-wrap: anywhere; }
    .badge { color: var(--muted); font-size: 12px; text-transform: capitalize; white-space: nowrap; }
    .in_progress .badge { color: var(--work); }
    .failed .badge { color: var(--bad); }
    .succeeded .badge { color: var(--good); }
    .observed .badge { color: var(--observed); }
    footer { padding: 22px 0; color: var(--muted); font-size: 12px; }
    @media (max-width: 540px) { main, header > div { padding: 18px; } h1 { font-size: 24px; } .step { align-items: flex-start; } .badge { text-align: right; } }
  </style>
</head>
<body>
  <header><div><p class="eyebrow">Code to Cloud Security Dojo</p><h1>${escapeHtml(title)}</h1><p>${escapeHtml(state.scope.resourceGroup)} / ${escapeHtml(state.scope.location)} / ${escapeHtml(state.scope.subscriptionId)}</p></div></header>
  <main>
    <div class="summary"><span><strong>${completed} of ${state.stages.length}</strong> stages completed</span><span>Updated ${escapeHtml(state.updatedAt)}</span></div>
    <progress max="${state.stages.length}" value="${completed}" aria-label="Completed deployment stages"></progress>
    <ol>${rows}
    </ol>
    <footer>Local operator status. Deployment success is not runtime or security verification.</footer>
  </main>
</body>
</html>`;
}

export async function createDeploymentStatus(config, output, action) {
  const scope = {
    labId: config.labId,
    subscriptionId: config.subscriptionId,
    resourceGroup: config.resourceGroup,
    location: config.location,
  };
  const jsonPath = join(output, "deployment-status.json");
  const htmlPath = join(output, "deployment-status.html");
  let state;
  try {
    state = JSON.parse(await readFile(jsonPath, "utf8"));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (!state || JSON.stringify(state.scope) !== JSON.stringify(scope)) {
    state = {
      schemaVersion: 1,
      scope,
      updatedAt: new Date().toISOString(),
      stages: stages.map(([id, label]) => ({
        id,
        label,
        state: "pending",
        detail: "",
      })),
    };
  }
  let stage = state.stages.find((item) => item.id === action);
  if (!stage && additionalStages[action]) {
    stage = {
      id: action,
      label: additionalStages[action],
      state: "pending",
      detail: "",
    };
    state.stages.push(stage);
  }
  if (!stage)
    throw new Error(`Unsupported deployment status action: ${action}`);
  for (const item of state.stages) {
    if (item.state === "in_progress") {
      item.state = "failed";
      item.detail =
        "Interrupted before completion. Review the previous command.";
      item.finishedAt = new Date().toISOString();
    }
  }
  async function publish() {
    state.updatedAt = new Date().toISOString();
    await mkdir(output, { recursive: true });
    await writeFile(jsonPath, `${JSON.stringify(state, null, 2)}\n`);
    await writeFile(htmlPath, renderDeploymentStatus(state));
  }
  stage.state = "in_progress";
  stage.detail = "Checking target and prerequisites";
  stage.startedAt = new Date().toISOString();
  delete stage.finishedAt;
  await publish();
  return {
    url: pathToFileURL(htmlPath).href,
    async observe(id, detail) {
      const observed = state.stages.find((item) => item.id === id);
      if (!observed || observed.state !== "pending") return;
      observed.state = "observed";
      observed.detail = detail;
      await publish();
    },
    async update(detail) {
      stage.detail = detail;
      await publish();
    },
    async finish(failed = false) {
      stage.state = failed ? "failed" : "succeeded";
      stage.detail = failed
        ? "Step failed. Review the terminal output before retrying."
        : "Completed";
      stage.finishedAt = new Date().toISOString();
      await publish();
    },
  };
}
