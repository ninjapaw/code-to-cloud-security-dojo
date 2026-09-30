#!/usr/bin/env node

// Interactive wizard for the Code-to-Cloud Security Dojo.
// Wraps scripts/deploy.mjs and scripts/build-dojo.mjs behind one guided menu so
// configure, deploy, verify, and remove all live in a single entry point.
// Automation should call scripts/deploy.mjs directly; this file adds no new gates.

import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { root, configPath, validateConfig } from "../shared/config.mjs";
import { run } from "./lib/lifecycle.mjs";
import {
  banner,
  showTarget,
  menu,
  info,
  ok,
  warn,
  fail,
  dim,
} from "./lib/wizard-ui.mjs";

if (!stdin.isTTY) {
  fail(
    "The wizard requires an interactive terminal. Use `node scripts/deploy.mjs <action>` for automation.",
  );
  process.exit(1);
}

const prompt = createInterface({ input: stdin, output: stdout });
// configPath is a URL when resolved from the repo and a plain string when it
// comes from DOJO_CONFIG, so normalise it for display.
const displayPath =
  typeof configPath === "string" ? configPath : fileURLToPath(configPath);

const ask = async (question) => (await prompt.question(question)).trim();

// Anything other than y/yes is a decline, so an accidental Enter is always safe.
const confirmYesNo = async (question) =>
  /^y(es)?$/i.test(await ask(`${question} [y/N] `));

// inherit streams the lifecycle output straight to the terminal, which is what
// the operator needs to watch for every step except the two parsed below.
function deployAction(action, args = []) {
  run("node", ["scripts/deploy.mjs", action, ...args], { inherit: true });
}

/**
 * Runs a lifecycle action and returns its stdout so the wizard can read the
 * exact confirmation string the tool requires, instead of asking an operator to
 * retype a 64-character hash.
 */
function captureAction(action, args = []) {
  const output = run("node", ["scripts/deploy.mjs", action, ...args]);
  console.log(output);
  return output;
}

/**
 * Reads the approval token that deploy.mjs prints as "Required confirmation:".
 * Only what-if and inventory emit it; both bind the token to an evidence hash
 * that changes whenever the release or the resource inventory changes.
 */
function requiredConfirmation(output) {
  const match = output.match(/^Required confirmation:\s*(.+)$/m);
  if (!match)
    throw new Error(
      "Could not read the required confirmation from the lifecycle output",
    );
  return match[1].trim();
}

/**
 * Typing the resource group name is the human gate for billable and destructive
 * steps, matching the pawton uninstall convention.
 */
async function groupTyped(config) {
  const typed = await ask(
    `Type the resource group name to confirm (${config.resourceGroup}): `,
  );
  if (typed !== config.resourceGroup) {
    warn("Name did not match. Cancelled.");
    return false;
  }
  return true;
}

async function acceptCosts() {
  if ((await ask("Accept recurring Azure costs? Type yes: ")) === "yes")
    return true;
  warn("Cost approval declined. Cancelled.");
  return false;
}

// Blocks Azure-touching actions until configure has run, so the operator gets a
// pointer to option 2 instead of a validation stack trace.
function requireConfigured(config) {
  if (config.subscriptionId && config.resourceGroup) return true;
  warn("This lab is not configured yet. Run Configure (option 2) first.");
  return false;
}

/**
 * Drives the actions whose approval token is deterministic
 * ("<action>:<subscription>:<group>"), so there is nothing to parse first.
 * Returns false when the operator declines at any prompt, which lets the guided
 * install stop the remaining steps.
 */
async function gatedAction(config, action, { costs = false, note } = {}) {
  if (!requireConfigured(config)) return false;
  showTarget(config);
  if (note) warn(note);
  if (!(await confirmYesNo(`Run ${action}?`))) {
    warn("Cancelled.");
    return false;
  }
  if (!(await groupTyped(config))) return false;
  const args = [
    "--confirm",
    `${action}:${config.subscriptionId}:${config.resourceGroup}`,
  ];
  if (costs) {
    if (!(await acceptCosts())) return false;
    args.push("--accept-costs");
  }
  deployAction(action, args);
  return true;
}

/**
 * Selects the target subscription and lab settings, then writes the gitignored
 * local configuration. validateConfig runs before the write so a bad object ID
 * or CIDR is rejected here rather than mid-deployment.
 */
async function configure(config) {
  banner("Configure the training lab");
  info("Listing enabled subscriptions. Use a dedicated training subscription.");
  const accounts = run("az", ["account", "list", "--all", "--output", "json"], {
    json: true,
  });
  accounts.forEach((account, index) =>
    console.log(
      `  ${index + 1}) ${account.name} ${dim(`| ${account.id} | tenant ${account.tenantId} | ${account.state}`)}`,
    ),
  );
  const selected = accounts[Number(await ask("\nSubscription number: ")) - 1];
  if (!selected || selected.state !== "Enabled")
    throw new Error("Choose an enabled training subscription");
  config.subscriptionId = selected.id;
  config.tenantId = selected.tenantId;
  for (const [key, label] of [
    ["resourceGroup", "New dedicated resource group"],
    ["labId", "Stable lab ID"],
    ["location", "Azure region"],
    ["operatorObjectId", "Operator Entra object ID (not application/client ID)"],
    ["adminCidr", "Your public IPv4 address with /32"],
  ]) {
    config[key] =
      (await ask(`${label} [${config[key] || ""}]: `)) || config[key];
  }
  validateConfig(config);
  const localPath = new URL("config/deploy.local.json", root);
  // 0600 because this file names the subscription, operator and admin CIDR.
  await writeFile(localPath, `${JSON.stringify(config, null, 2)}\n`, {
    mode: 0o600,
  });
  ok(
    `Saved ${fileURLToPath(localPath)}. No global Azure subscription setting was changed.`,
  );
}

/**
 * Previews the pending release and applies it only after review. The deploy
 * token embeds a hash of the release manifest, so it must come from this
 * what-if run rather than a remembered value.
 */
async function release(config) {
  if (!requireConfigured(config)) return;
  showTarget(config);
  info("Running what-if against the reviewed release. Nothing is applied yet.");
  const confirmation = requiredConfirmation(captureAction("what-if"));
  warn("Review the what-if output above before applying the release.");
  if (!(await confirmYesNo("Apply this release?"))) return warn("Cancelled.");
  if (!(await groupTyped(config))) return;
  deployAction("deploy", ["--confirm", confirmation]);
}

/**
 * Deletes the lab. Evidence is unrecoverable afterwards, so this asks for the
 * export acknowledgement before the typed resource group name.
 */
async function remove(config) {
  if (!requireConfigured(config)) return;
  showTarget(config);
  info("Collecting the deletion inventory for this lab.");
  const confirmation = requiredConfirmation(captureAction("inventory"));
  warn(
    `This deletes the resource group '${config.resourceGroup}' and everything listed above.`,
  );
  if ((await ask("Exported all evidence and reports? Type yes: ")) !== "yes")
    return warn("Export evidence first. Cancelled.");
  if (!(await groupTyped(config))) return;
  deployAction("deprovision", [
    "--confirm",
    confirmation,
    "--evidence-exported",
  ]);
}

/**
 * Walks the ordered lifecycle a new lab needs. Every step keeps its own
 * confirmation, and declining one stops the rest so a half-approved install
 * never continues on to deployment.
 */
async function install(config) {
  if (!requireConfigured(config)) return;
  banner("Guided install");
  info(
    "Runs the full lifecycle in order. Each step is confirmed separately and you can stop at any point.",
  );
  const steps = [
    [
      "provision",
      {
        costs: true,
        note: "Creates billable resources and grants the portal subscription Security Reader.",
      },
    ],
    [
      "protection",
      { costs: true, note: "Changes subscription-wide Defender billing." },
    ],
    [
      "build",
      {
        note: "Builds, scans, and pushes images, then records a release manifest.",
      },
    ],
  ];
  for (const [action, options] of steps) {
    if (!(await gatedAction(config, action, options)))
      return warn(`Stopped before ${action}. Nothing further was run.`);
  }
  await release(config);
  ok("Guided install finished. Run Verify and Report next.");
}

async function advanced(config) {
  const options = [
    ["1", "source-upstream", "list upstream WebGoat refs (read-only)"],
    ["2", "source-sync", "sync the pinned WebGoat snapshot"],
    ["3", "source-check", "verify the pinned snapshot"],
    ["4", "image-build", "build the dojo image locally (not pushed)"],
    ["5", "provision", "deploy foundation.bicep (billable)"],
    ["6", "protection", "reconcile Defender plans (billable)"],
    ["7", "build", "build, scan, and push a release"],
    ["8", "what-if", "preview the release deployment"],
    ["9", "repair", "reapply the approved release"],
    ["10", "rotate", "rotate Key Vault credentials"],
    ["11", "inventory", "list resources a removal would delete"],
    ["0", "Back", ""],
  ];
  banner("Advanced lifecycle steps");
  menu(options);
  const choice = await ask("\nSelect a step: ");
  if (choice === "0" || choice === "") return;
  const picked = options.find(([key]) => key === choice);
  if (!picked) return warn("Invalid selection.");
  const [, action] = picked;
  if (action === "image-build")
    return run("node", ["scripts/build-dojo.mjs"], { inherit: true });
  if (["provision", "protection"].includes(action))
    return void (await gatedAction(config, action, { costs: true }));
  if (["build", "rotate"].includes(action))
    return void (await gatedAction(config, action));
  if (action === "repair") return release(config);
  // source-* actions work on the local snapshot and never reach Azure.
  if (!action.startsWith("source-") && !requireConfigured(config)) return;
  deployAction(action);
}

// void keeps the short-circuit handlers returning undefined, so the dispatcher
// below never treats a helper's boolean as a result.
const actions = {
  1: () => deployAction("plan"),
  2: configure,
  3: (config) => void (requireConfigured(config) && deployAction("doctor")),
  4: install,
  5: release,
  6: (config) => void (requireConfigured(config) && deployAction("verify")),
  7: (config) => void (requireConfigured(config) && deployAction("report")),
  8: remove,
  9: advanced,
};

async function main() {
  for (;;) {
    // Reread on every pass so Configure is reflected without a restart, and
    // parse raw because an unconfigured lab must still reach the menu.
    const config = JSON.parse(await readFile(configPath, "utf8"));
    banner("Code-to-Cloud Security Dojo — lifecycle wizard");
    console.log(`  Config file  ${displayPath}`);
    showTarget(config);
    warn(
      "This lab runs intentionally vulnerable software. Use a dedicated training subscription.",
    );
    menu([
      ["1", "Plan", "offline; show what would be deployed"],
      ["2", "Configure", "choose the subscription and lab settings"],
      ["3", "Doctor", "read-only Azure preflight checks"],
      ["4", "Install", "guided provision, protection, build, and deploy"],
      ["5", "Deploy", "what-if, then apply the reviewed release"],
      ["6", "Verify", "check runtime and Azure state"],
      ["7", "Report", "collect posture and evidence reports"],
      ["8", "Remove", "delete this lab's resource group"],
      ["9", "Advanced", "individual lifecycle steps"],
      ["0", "Exit", ""],
    ]);
    const choice = await ask("\nSelect an action: ");
    if (choice === "0" || choice === "") return;
    const selected = actions[choice];
    if (!selected) {
      warn("Invalid selection.");
      continue;
    }
    try {
      await selected(config);
    } catch (error) {
      // One failed action should not end the session; report and re-prompt.
      fail(error.message);
    }
    await ask(dim("\nPress Enter to return to the menu..."));
  }
}

try {
  await main();
} finally {
  // Without this the readline interface keeps the event loop alive on exit.
  prompt.close();
}
