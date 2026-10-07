import test from "node:test";
import assert from "node:assert/strict";
import { readFile, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { runInNewContext } from "node:vm";
import { workflowConfig } from "../scripts/workflow-config.mjs";
import { configHash } from "../scripts/lib/lifecycle.mjs";

const base = JSON.parse(await readFile(
  new URL("../config/deploy.config.json", import.meta.url), "utf8",
));
const environment = {
  DOJO_TENANT_ID: "11111111-1111-4111-8111-111111111111",
  DOJO_SUBSCRIPTION_ID: "22222222-2222-4222-8222-222222222222",
  DOJO_RESOURCE_GROUP: "workflow-test",
  DOJO_LOCATION: "centralus",
  DOJO_OPERATOR_OBJECT_ID: "33333333-3333-4333-8333-333333333333",
  DOJO_ADMIN_CIDR: "203.0.113.10/32",
};

test("workflow configuration preserves committed image and network choices when variables are absent", () => {
  const defaults = workflowConfig(base, environment);
  assert.equal(defaults.drowsyDragonEnabled, false);
  assert.equal(defaults.nginxProxyEnabled, false);
  const selected = {
    ...base, drowsyDragonEnabled: true, nginxProxyEnabled: true,
    nginxProxyMode: "remediated", evidencePublicAccess: false,
    dojoPublicAccess: false,
  };
  const result = workflowConfig(selected, {
    ...environment,
    DOJO_DROWSY_DRAGON_ENABLED: "",
    DOJO_NGINX_PROXY_ENABLED: "",
    DOJO_NGINX_PROXY_MODE: "",
    DOJO_EVIDENCE_PUBLIC_ACCESS: "",
  });
  assert.equal(result.drowsyDragonEnabled, true);
  assert.equal(result.nginxProxyEnabled, true);
  assert.equal(result.nginxProxyMode, "remediated");
  assert.equal(result.evidencePublicAccess, false);
  assert.equal(result.dojoPublicAccess, false);
  assert.equal(selected.subscriptionId, base.subscriptionId);
  assert.equal(result.subscriptionId, environment.DOJO_SUBSCRIPTION_ID);
});

test("protected variables select every optional-image combination with configuration-bound releases", () => {
  const hashes = new Set();
  for (const dragon of [false, true]) {
    for (const nginx of [false, true]) {
      for (const mode of ["vulnerable", "remediated"]) {
        const result = workflowConfig(base, {
          ...environment,
          DOJO_DROWSY_DRAGON_ENABLED: String(dragon),
          DOJO_NGINX_PROXY_ENABLED: String(nginx),
          DOJO_NGINX_PROXY_MODE: mode,
          DOJO_EVIDENCE_PUBLIC_ACCESS: "false",
        });
        assert.equal(result.drowsyDragonEnabled, dragon);
        assert.equal(result.nginxProxyEnabled, nginx);
        assert.equal(result.nginxProxyMode, mode);
        assert.equal(result.evidencePublicAccess, false);
        assert.equal(result.adminCidr, environment.DOJO_ADMIN_CIDR);
        hashes.add(configHash(result));
      }
    }
  }
  assert.equal(hashes.size, 8);
});

test("invalid feature flags and missing target fields fail rather than disabling images silently", () => {
  for (const flag of ["DOJO_DROWSY_DRAGON_ENABLED", "DOJO_NGINX_PROXY_ENABLED", "DOJO_EVIDENCE_PUBLIC_ACCESS"]) {
    for (const value of ["yes", "0", "1", "null", " false ", null, 1]) {
      assert.throws(() => workflowConfig(base, { ...environment, [flag]: value }), /must be true or false/);
    }
  }
  assert.throws(
    () => workflowConfig(base, { ...environment, DOJO_NGINX_PROXY_MODE: "latest" }),
    /nginxProxyMode/,
  );
  assert.throws(() => workflowConfig(base, {}), /tenantId/);
});

test("workflow CLI writes a private configuration with NGINX enabled and refuses overwrite", async () => {
  const directory = await mkdtemp(join(tmpdir(), "dojo-workflow-config-"));
  const target = join(directory, "workflow.json");
  const script = fileURLToPath(new URL("../scripts/workflow-config.mjs", import.meta.url));
  try {
    const env = {
      ...process.env,
      ...environment,
      DOJO_DROWSY_DRAGON_ENABLED: "true",
      DOJO_NGINX_PROXY_ENABLED: "true",
      DOJO_NGINX_PROXY_MODE: "vulnerable",
      DOJO_EVIDENCE_PUBLIC_ACCESS: "false",
    };
    const result = spawnSync(process.execPath, [script, target], { env, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const text = await readFile(target, "utf8");
    const config = JSON.parse(text);
    assert.equal(config.nginxProxyEnabled, true);
    assert.equal(config.drowsyDragonEnabled, true);
    assert.equal(config.evidencePublicAccess, false);
    if (process.platform !== "win32")
      assert.equal((await stat(target)).mode & 0o777, 0o600);
    const overwrite = spawnSync(process.execPath, [script, target], { env, encoding: "utf8" });
    assert.notEqual(overwrite.status, 0);
    assert.equal(await readFile(target, "utf8"), text);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deployment workflow forwards protected feature choices and the private portal transport", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8",
  );
  for (const variable of [
    "DOJO_DROWSY_DRAGON_ENABLED", "DOJO_NGINX_PROXY_ENABLED",
    "DOJO_NGINX_PROXY_MODE", "DOJO_EVIDENCE_PUBLIC_ACCESS", "DOJO_VIA_PORTAL",
  ])
    assert.ok(workflow.includes(`${variable}: \${{ vars.${variable} }}`), variable);
  assert.match(workflow, /node scripts\/workflow-config\.mjs "\$config_path"/);
  assert.doesNotMatch(workflow, /\.(?:drowsyDragonEnabled|nginxProxyEnabled) = false/);
  assert.match(workflow, /true\) portal_args\+=\(--via-portal\)/);
  assert.match(workflow, /verify\|report\)[\s\S]*?scripts\/deploy\.mjs "\$OPERATION" "\$\{portal_args\[@\]\}"/);
  assert.match(workflow, /deploy_args\+=\("\$\{portal_args\[@\]\}"\)/);
  assert.match(workflow, /if \[\[ "\$ACCEPT_COSTS" == "true" \]\]; then deploy_args\+=\(--accept-costs\)/);
});

test("the publisher job cannot select the deployment identity or operation", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8",
  );
  assert.match(workflow, /on:\r?\n  push:\r?\n    branches: \[dev\]/);
  assert.doesNotMatch(workflow, /^  pull_request(?:_target)?:/m);
  const environment = workflow.match(/^    environment: \$\{\{ (.+) \}\}$/m)?.[1];
  const operation = workflow.match(/^      OPERATION: \$\{\{ (.+) \}\}$/m)?.[1];
  const concurrency = workflow.match(/^  group: \$\{\{ (.+) \}\}$/m)?.[1];
  const enabled = workflow.match(/^    if: (.+)$/m)?.[1];
  assert.ok(environment && operation && concurrency && enabled);
  assert.equal((workflow.match(/^\s+OPERATION:/gm) || []).length, 1);
  for (const [event, input, expectedOperation, expectedEnvironment] of [
    ["push", undefined, "build", "code-to-cloud-images"],
    ["push", "deploy", "build", "code-to-cloud-images"],
    ["workflow_dispatch", "build", "build", "code-to-cloud-images"],
    ...["doctor", "provision", "protection", "what-if", "deploy", "verify", "report"]
      .map((input) => ["workflow_dispatch", input, input, "code-to-cloud-training"]),
  ]) {
    const context = { github: { event_name: event, ref: "refs/heads/dev" }, inputs: { operation: input } };
    assert.equal(runInNewContext(enabled, context), true);
    assert.equal(runInNewContext(operation, context), expectedOperation);
    assert.equal(runInNewContext(environment, context), expectedEnvironment);
    assert.equal(
      runInNewContext(concurrency, context),
      expectedOperation === "build" ? "dojo-images-code-to-cloud-training" : "dojo-deployment-code-to-cloud-training",
    );
  }
  for (const [event, ref] of [
    ["pull_request", "refs/heads/dev"], ["pull_request_target", "refs/heads/dev"],
    ["push", "refs/heads/main"], ["workflow_dispatch", "refs/heads/main"],
  ])
    assert.equal(runInNewContext(enabled, {
      github: { event_name: event, ref }, inputs: { operation: "build" },
    }), false);
  assert.match(workflow, /CONFIRM_RESOURCE_GROUP: \$\{\{ github\.event_name == 'push' && vars\.DOJO_RESOURCE_GROUP \|\| inputs\.confirm-resource-group \}\}/);
  assert.match(workflow, /\(\.event == "workflow_dispatch" or \.event == "push"\)/);
  assert.match(workflow, /\.head_sha == \$sha/);
  assert.match(workflow, /\.operation == "build"/);
  assert.match(workflow, /if: env\.OPERATION == 'build'/);
  assert.doesNotMatch(workflow, /pending_deployments|state.?=.?'approved'|deployments: write/);
});

test("automatic rollout depends on the same successful build, is dev-only, and always cleans runner access", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8",
  );
  const rollout = workflow.split(/\r?\n  rollout:\r?\n/)[1];
  assert.ok(rollout);
  assert.match(rollout, /needs: lifecycle/);
  assert.match(rollout, /environment: code-to-cloud-training/);
  assert.match(rollout, /group: dojo-deployment-code-to-cloud-training/);
  const condition = rollout.match(/^    if: (.+)$/m)?.[1];
  const context = {
    needs: { lifecycle: { result: "success" } },
    github: { ref: "refs/heads/dev", event_name: "push" },
    inputs: {}, vars: { DOJO_AUTOMATIC_ROLLOUT: "true" },
  };
  assert.equal(runInNewContext(condition, context), true);
  for (const override of [
    { needs: { lifecycle: { result: "failure" } } },
    { vars: { DOJO_AUTOMATIC_ROLLOUT: "false" } },
    { github: { ref: "refs/heads/main", event_name: "push" } },
    { github: { ref: "refs/heads/dev", event_name: "pull_request" } },
  ])
    assert.equal(runInNewContext(condition, { ...context, ...override }), false);
  assert.match(rollout, /name: dojo-release-\$\{\{ github\.run_id \}\}/);
  assert.match(rollout, /\.runId == \$runId[\s\S]*?\.sha == \$sha[\s\S]*?\.operation == "build"/);
  assert.match(rollout, /deploy --automatic --via-portal --accept-costs/);
  assert.match(rollout, /if: always\(\) && steps\.rollout-login\.outcome == 'success' && steps\.runner-address\.outcome == 'success'/);
  assert.match(rollout, /await updateRunnerAccess\(config, new AzureClient\(config\), false\)/);
  assert.doesNotMatch(rollout, /protection --|deprovision|provision --|rotate|pending_deployments/);
});
test("automatic publisher has registry-scoped push and read-only ownership access, not deployment rights", async () => {
  const template = await readFile(
    new URL("../infra/image-publisher.bicep", import.meta.url), "utf8",
  );
  assert.match(template, /Microsoft\.ManagedIdentity\/userAssignedIdentities@2024-11-30/);
  assert.match(template, /federatedIdentityCredentials@2024-11-30/);
  assert.match(template, /issuer: 'https:\/\/token\.actions\.githubusercontent\.com'/);
  assert.match(template, /audiences: \['api:\/\/AzureADTokenExchange'\]/);
  assert.match(template, /subject: githubEnvironmentSubject/);
  assert.match(template, /var acrPushRole = '8311e382-0749-4cb8-b61a-304f252e45ec'/);
  assert.match(template, /var readerRole = 'acdd72a7-3385-48ef-bd42-f606fba81ae7'/);
  assert.match(template, /resource push[\s\S]*?scope: registry[\s\S]*?roleDefinitionId:.*acrPushRole/);
  assert.equal((template.match(/Microsoft\.Authorization\/roleAssignments@/g) || []).length, 2);
  assert.doesNotMatch(template, /b24988ac-6180-42a0-ab88-20f7382dd24c|f58310d9-a9f6-439a-9e8d-f62e7b41a168|b86a8fe4-44ce-4948-aee5-eccb2c155cd7|ba92f5b4-2d11-453d-a403-e96b0029c9fe|client.?secret|listKeys/i);
});

test("release image artifacts are scan-bound and separate from deployment evidence", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/deploy.yml", import.meta.url), "utf8",
  );
  assert.match(workflow, /name: dojo-container-images-\$\{\{ github\.run_id \}\}/);
  assert.match(workflow, /name: dojo-release-\$\{\{ github\.run_id \}\}/);
  assert.match(workflow, /expectedImageId: entry\.imageId/);
  for (const recipe of [
    "output/code-to-cloud-training/Dojo.Dockerfile",
    "apps/control-portal/Dockerfile", "apps/drowsy-dragon/Dockerfile",
    "apps/nginx-proxy/upstream/Dockerfile",
  ])
    assert.ok(workflow.includes(recipe), recipe);
  assert.match(workflow, /path: output\/container-images\/\r?\n\s+if-no-files-found: error\r?\n\s+compression-level: 1\r?\n\s+retention-days: 7/);
  assert.match(workflow, /runs-on: \$\{\{ fromJSON\(vars\.DOJO_DEPLOY_RUNNER_LABELS/);
  assert.match(workflow, /runner cannot reach the protected portal/);
  assert.doesNotMatch(workflow, /az webapp config access-restriction add/);
  assert.ok(workflow.indexOf("name: Upload the app-named container images") <
    workflow.indexOf("name: Record build workflow provenance"));
});

test("validation exports all image recipes without Azure credentials or deploying CI images", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/dojo.yml", import.meta.url), "utf8",
  );
  for (const name of [
    "nginx-proxy-${{ matrix.mode }}-container", "drowsy-dragon-container",
    "webgoat-and-portal-containers",
  ])
    assert.ok(workflow.includes(`name: ${name}`), name);
  for (const recipe of [
    "apps/nginx-proxy/upstream/Dockerfile", "apps/drowsy-dragon/Dockerfile",
    "apps/control-portal/Dockerfile", "Dojo.Dockerfile",
  ])
    assert.ok(workflow.includes(recipe), recipe);
  assert.ok(workflow.indexOf("name: Export WebGoat and portal images") >
    workflow.indexOf("name: Gate portal high and critical vulnerabilities"));
  assert.doesNotMatch(workflow, /azure\/login|id-token: write|docker push|scripts\/deploy\.mjs deploy/);
});

test("Drowsy Dragon is selected for dev pushes and defaults on for manual dev builds", async () => {
  const workflow = await readFile(
    new URL("../.github/workflows/dojo.yml", import.meta.url), "utf8",
  );
  const input = workflow.match(/^      drowsy-dragon:\r?\n([\s\S]*?)^      nginx-proxy:/m)?.[1];
  assert.ok(input, "Manual Drowsy Dragon input must exist");
  assert.match(input, /type: boolean/);
  assert.match(input, /default: true/);
  const job = workflow.match(/^  drowsy-dragon:\r?\n([\s\S]*?)^  validate-and-scan:/m)?.[1];
  assert.ok(job, "Protected Drowsy Dragon job must exist");
  assert.equal(
    job.match(/    if: ([^\r\n]+)/)?.[1],
    "github.ref == 'refs/heads/dev' && (github.event_name == 'push' || (github.event_name == 'workflow_dispatch' && inputs.drowsy-dragon))",
  );
  assert.match(job, /environment: drowsy-dragon-images/);
  assert.match(job, /npm run image:build:dragon -- --tag drowsy-dragon:scan/);
  assert.match(job, /name: drowsy-dragon-container/);
});

test("DHI access accepts complete organization Docker credentials or complete DHI overrides", async () => {
  for (const name of ["deploy", "dojo"]) {
    const workflow = await readFile(
      new URL(`../.github/workflows/${name}.yml`, import.meta.url), "utf8",
    );
    assert.match(workflow, /DHI_USERNAME: \$\{\{ secrets\.DHI_USERNAME \}\}/);
    assert.match(workflow, /DHI_TOKEN: \$\{\{ secrets\.DHI_TOKEN \}\}/);
    assert.match(workflow, /DOCKER_USERNAME: \$\{\{ secrets\.DOCKER_USERNAME \}\}/);
    assert.match(workflow, /DOCKER_TOKEN: \$\{\{ secrets\.DOCKER_TOKEN \}\}/);
    assert.match(workflow, /if \[\[ -n "\$DHI_USERNAME" \|\| -n "\$DHI_TOKEN" \]\]/);
    for (const variable of ["DHI_USERNAME", "DHI_TOKEN", "DOCKER_USERNAME", "DOCKER_TOKEN"])
      assert.ok(workflow.includes(`: "\${${variable}:?`), `${name}: incomplete ${variable} must fail`);
    assert.match(
      workflow,
      /DHI_USERNAME="\$DOCKER_USERNAME"\r?\n\s+DHI_TOKEN="\$DOCKER_TOKEN"\r?\n\s+fi\r?\n\s+printf '%s' "\$DHI_TOKEN" \| docker login/,
    );
    assert.match(workflow, /docker login dhi\.io --username "\$DHI_USERNAME" --password-stdin/);
    assert.match(workflow, /docker pull --platform linux\/amd64 "\$base_image"/);
    assert.match(workflow, /if: always\(\) && steps\.dhi-login\.outputs\.authenticated == 'true'/);
    assert.doesNotMatch(workflow, /docker login.*--password /);
    assert.doesNotMatch(workflow, /checking public access|secrets\.DHI_(USERNAME|TOKEN) \|\|/);
  }
});
