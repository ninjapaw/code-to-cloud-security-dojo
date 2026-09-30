import { stdout } from "node:process";

const enabled = Boolean(stdout.isTTY) && !process.env.NO_COLOR;
const wrap = (code) => (text) => (enabled ? `\u001b[${code}m${text}\u001b[0m` : text);

export const blue = wrap("34");
export const green = wrap("32");
export const yellow = wrap("33");
export const red = wrap("31");
export const dim = wrap("2");

export const info = (message) => console.log(`${blue("==>")} ${message}`);
export const ok = (message) => console.log(`${green("\u2713")} ${message}`);
export const warn = (message) => console.log(`${yellow("!")} ${message}`);
export const fail = (message) => console.error(`${red("ERROR:")} ${message}`);

export function banner(title) {
  console.log(`\n${blue(`=== ${title} ===`)}`);
}

/**
 * Renders the configured Azure target so every billable or destructive step
 * states which lab it is about to touch, as the pawton wizard does.
 */
export function showTarget(config) {
  const value = (input) => input || dim("(not configured)");
  console.log(
    [
      `  Lab ID       ${value(config.labId)}`,
      `  Tenant       ${value(config.tenantId)}`,
      `  Subscription ${value(config.subscriptionId)}`,
      `  Group        ${value(config.resourceGroup)}`,
      `  Region       ${value(config.location)}`,
    ].join("\n"),
  );
}

export function menu(options) {
  console.log();
  options.forEach(([key, label, description]) => {
    const suffix = description ? ` ${dim(`— ${description}`)}` : "";
    console.log(`  ${blue(`${key})`)} ${label}${suffix}`);
  });
}
