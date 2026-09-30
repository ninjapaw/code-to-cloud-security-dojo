import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { readFile, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { root, configPath, validateConfig } from "../shared/config.mjs";
import { run } from "./lib/lifecycle.mjs";

if (!stdin.isTTY)
  throw new Error(
    "Wizard requires an interactive terminal. Use node scripts/deploy.mjs plan for automation.",
  );
const prompt = createInterface({ input: stdin, output: stdout });
try {
  const config = JSON.parse(await readFile(configPath, "utf8"));
  console.log(
    "Code to Cloud Security Dojo / Training lifecycle\nNo environment is inferred from a Git branch.",
  );
  const action = await prompt.question(
    "Action [plan/source-upstream/source-sync/source-check/image-build/configure/doctor/provision/protection/build/what-if/deploy/repair/verify/report/rotate/inventory/deprovision]: ",
  );
  if (action === "configure") {
    const accounts = run(
      "az",
      ["account", "list", "--all", "--output", "json"],
      { json: true },
    );
    accounts.forEach((account, index) =>
      console.log(
        `${index + 1}: ${account.name} | ${account.id} | tenant ${account.tenantId} | ${account.state}`,
      ),
    );
    const selected =
      accounts[
        Number(
          await prompt.question(
            "Subscription number (dedicated training only): ",
          ),
        ) - 1
      ];
    if (!selected || selected.state !== "Enabled")
      throw new Error("Choose an enabled training subscription");
    config.subscriptionId = selected.id;
    config.tenantId = selected.tenantId;
    for (const [key, label] of [
      ["resourceGroup", "New dedicated resource group"],
      ["labId", "Stable lab ID"],
      ["location", "Azure region"],
      [
        "operatorObjectId",
        "Operator Entra object ID (not application/client ID)",
      ],
      ["adminCidr", "Your public IPv4 address with /32"],
    ]) {
      config[key] =
        (await prompt.question(`${label} [${config[key]}]: `)).trim() ||
        config[key];
    }
    validateConfig(config);
    const localPath = new URL("config/deploy.local.json", root);
    await writeFile(localPath, `${JSON.stringify(config, null, 2)}\n`, {
      mode: 0o600,
    });
    console.log(
      `Saved ${fileURLToPath(localPath)}. No global Azure subscription setting was changed.`,
    );
  } else {
    const args =
      action === "image-build"
        ? ["scripts/build-dojo.mjs"]
        : ["scripts/deploy.mjs", action || "plan"];
    if (
      [
        "provision",
        "protection",
        "build",
        "deploy",
        "repair",
        "rotate",
        "deprovision",
      ].includes(action)
    ) {
      console.log(
        `Tenant ${config.tenantId}\nSubscription ${config.subscriptionId}\nGroup ${config.resourceGroup}\nRegion ${config.location}`,
      );
      console.log(
        "provision creates billable resources and grants portal subscription Security Reader. protection changes subscription-wide billing. deploy requires a reviewed release hash.",
      );
      if (action === "deprovision")
        run("node", ["scripts/deploy.mjs", "inventory"], { inherit: true });
      args.push(
        "--confirm",
        await prompt.question(
          "Exact confirmation (action:subscription:group; deploy/deprovision include evidence hash): ",
        ),
      );
      if (
        ["provision", "protection"].includes(action) &&
        (await prompt.question("Accept recurring costs? Type yes: ")) === "yes"
      )
        args.push("--accept-costs");
      if (
        action === "deprovision" &&
        (await prompt.question(
          "Exported all evidence and reviewed deletion inventory? Type yes: ",
        )) === "yes"
      )
        args.push("--evidence-exported");
    }
    run("node", args, { inherit: true });
  }
} finally {
  prompt.close();
}
