# Code to Cloud Security Dojo

> **Authorized training only.** WebGoat is deliberately vulnerable. Use a dedicated
> training subscription, never production data or credentials. The deployed WebGoat
> website is public by default. Use disposable lesson accounts and remove the lab
> when finished. This is an independent community project, not a Microsoft or OWASP
> product, endorsement or security assurance.

A lifecycle wizard and separate admin portal follow pinned WebGoat
source through scanning, ACR, a configurable HTTPS App Service runtime, Defender observations,
bounded test requests and executive evidence reports.

[Drowsy Dragon](apps/drowsy-dragon/README.md) adds an opt-in, digest-pinned
DHI .NET 8 SDK package-assessment demo. It inventories `libc6`, `libc-bin`, `tar`
and `libgcrypt20`, then sleeps in an Azure Container Instance with no public
ingress. Its build, scan, release, package findings and cleanup use the same
approved lifecycle; the existing WebGoat deployment remains the default.

The original [NGINX Proxy](apps/nginx-proxy/README.md) is another optional image
story, imported from the earlier NinjaPaws dojo. Compare the affected NGINX 1.30.3
map/regex configuration with the 1.30.4 target-CVE remediation on its own private
App Service. It can run alongside both WebGoat and Drowsy Dragon.

**Status:** experimental training software, not production security infrastructure.
Local tests and image builds do not establish live Azure readiness or protection.
Validate deployment, access controls, rotation and detections on a disposable target.

## Contents

- [Start locally](#start-locally)
- [Architecture](#architecture)
- [Source and image lifecycle](apps/dojo/README.md)
- [Drowsy Dragon package demo](apps/drowsy-dragon/README.md)
- [Original NGINX proxy image story](apps/nginx-proxy/README.md)
- [Defender and code-to-cloud story](#defender-and-code-to-cloud-story)
- [Deployment and operation](#deployment-and-operation)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [Validation and live acceptance](#validation)
- [Official references](#official-references)

## Start Locally

Requires Node.js 22+ and npm. From the repository root:

```text
npm ci
npm test
npm run plan
npm run preview
```

Open <http://127.0.0.1:4397>. Preview binds only to loopback, has no credentials,
makes no Azure calls and cannot execute tests. It is not a simulated success report.

For Azure setup, follow [Deployment and operation](#deployment-and-operation).
Resource provisioning and paid Defender changes require separate cost approval.

## Architecture

The `dojo` workload uses a pinned WebGoat source snapshot. The Node/Express
`control-portal` is a separate application, identity and trust boundary.
[Foundation IaC](infra/foundation.bicep) creates dependencies before
[release IaC](infra/main.bicep) selects reviewed image digests.

Each deployed ACR image repository matches its Azure app resource name:
`dojo-<suffix>-app` for WebGoat, `dojo-<suffix>-portal` for the admin portal,
`dojo-<suffix>-dragon` for Drowsy Dragon, and `dojo-<suffix>-proxy` for NGINX.
The build, release validation, IaC and runtime evidence use the same names.
Deployments remain pinned to `registry/app-name@sha256:...`; training tags
identify builds but are not used as mutable deployment references. Standalone
local demo builds retain their short image names.

After upgrading from the legacy `dojo`, `control-portal`, `drowsy-dragon` and
`nginx-proxy` repositories, build and scan a new release before running
`what-if` and `deploy`. Legacy release manifests are rejected rather than
silently deploying an image under the wrong app name. Old repositories and
release evidence are not automatically deleted and remain available for rollback
with their matching source revision.

- Two Linux App Service plans (default B2), one Basic ACR and two pull identities.
- Optional Drowsy Dragon ACI with its own ACR-only pull identity, no IP address,
  no exposed ports and no portal/evidence credentials. It has no HTTP endpoint.
- Optional NGINX Proxy on a third, separate App Service plan with private ingress
  and its own ACR-only identity. It proxies its original dashboard, not the other
  workloads. Its private endpoint reuses the App Service DNS zone/VNet link.
- Public HTTPS Dojo website by default, with its private endpoint retained
  for portal-to-workload traffic. WebWolf is not exposed; SCM/FTP publishing stays blocked.
- Portal VNet integration and a single authorized public IPv4 `/32` restriction.
- Key Vault with RBAC, purge protection, private endpoint and authenticated public access by default.
- Admin username plus random admin password and session signing key stored directly
  in Key Vault through the SDK. No secret arguments, committed credentials or local secret files.
- Versionless Key Vault references for the portal; managed identity for Azure/Blob
  access. WebGoat receives neither portal credentials nor evidence permissions.
- Private-endpoint Blob evidence store with shared-key and public blob access off;
  operator-IP access supports collection. Log Analytics receives app diagnostics.
- Portal resource-group Reader and subscription Security Reader, no deployment or
  Defender-write privileges. Review that subscription-wide read scope explicitly.

The training portal uses one administrator credential, not an enterprise SSO/MFA
system. It adds Secure/HttpOnly/SameSite cookies, signed revocable one-hour sessions,
same-origin CSRF checks, login limits, a cross-instance test lease and cooldown.
Do not repurpose it as a production control plane.

## Defender and Code-to-Cloud Story

The desired configuration enables paid Defender CSPM (`CloudPosture`), Containers,
App Service and Key Vault protection. It requests `AgentlessServerlessPosture` and
`ContainerRegistriesVulnerabilityAssessments`. Reconciliation preserves unrelated
extensions and refuses an existing paid subplan conflict; it does not turn other
workload protections off. API availability, permissions and policies are checked
through actual requests and readback, not assumed from a deployment success.

The [workflow](.github/workflows/dojo.yml) runs tests, compiles IaC, scans source
with Microsoft Security DevOps, builds and scans both images, and retains evidence.
It has **no Azure deployment credentials or write operations**. WebGoat
vulnerabilities are intentional and require review; high or critical portal image
vulnerabilities fail the release build.

The separate [manual deployment workflow](.github/workflows/deploy.yml) uses
GitHub OIDC and the protected `code-to-cloud-training` environment. Configure its
`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`,
`DOJO_RESOURCE_GROUP`, `DOJO_LOCATION`, `DOJO_OPERATOR_OBJECT_ID`, and
`DOJO_ADMIN_CIDR` environment variables, then require an environment reviewer.
The Entra application's federated credential must use audience
`api://AzureADTokenExchange` and subject
`repo:ninjapaw@301718044/code-to-cloud-security-dojo@1395015776:environment:code-to-cloud-training`.
Create or reconcile the complete trust with the dry-run-by-default bootstrap:

```text
npm run setup:github-oidc -- --subscription <subscription-id> \
  --resource-group code-to-cloud-training --location centralus \
  --operator-object-id <entra-object-id> --admin-cidr <public-ip>/32 \
  --reviewer-id <github-user-id>

# After reviewing every `would` line:
npm run setup:github-oidc -- --apply --subscription <subscription-id> \
  --resource-group code-to-cloud-training --location centralus \
  --operator-object-id <entra-object-id> --admin-cidr <public-ip>/32 \
  --reviewer-id <github-user-id>
```

The bootstrap follows Pawprint's ID-qualified subject pattern, creates no client
secret, refuses unowned app-name collisions, pre-registers providers, creates the
ownership-tagged group and portal identity, and writes ignored state to
`.azure/oidc-bootstrap.json`. The infrastructure identity receives group-scoped
deployment/data roles, a role-conditioned group RBAC assignment, and read-only
Defender pricing access. A separate protection identity can only read/write
Defender pricing. The portal identity receives the fixed subscription Security
Reader assignment, so the workflow has no subscription RBAC administrator role.
Re-running `--apply` must report every item as `ok`.

After the guarded lab deprovision removes the resource group, retire standing
workflow trust separately. Retirement refuses a present group and requires the
exact token so it cannot disable a live lab accidentally:

```text
npm run setup:github-oidc -- --remove \
  --confirm-remove retire:<subscription-id>:code-to-cloud-training \
  --subscription <subscription-id> --resource-group code-to-cloud-training \
  --operator-object-id <entra-object-id> --admin-cidr <public-ip>/32
```

The environment is restricted to `dev` with self-review disabled. Add a separate
trusted reviewer before dispatching from the account that configured the trust;
the bootstrap cannot manufacture an independent human approval boundary.
It exposes the guarded lifecycle as separate runs: provision and protection need
cost consent; build uploads immutable release evidence; what-if consumes that
build run; deploy consumes the same run and requires the exact token printed by
what-if. It runs only from `dev`, never uses client secrets, and does not automate
cleanup, credential rotation, GitHub connector consent, or plan downgrades.

Optional-image selection comes from committed defaults and protected GitHub
environment variables; the workflow does not force the demos off:

| Protected environment variable | Effect when set |
| --- | --- |
| `DOJO_DROWSY_DRAGON_ENABLED` | `true` or `false`: include/exclude the sleeping ACI image. |
| `DOJO_NGINX_PROXY_ENABLED` | `true` or `false`: include/exclude the private NGINX image. |
| `DOJO_NGINX_PROXY_MODE` | `vulnerable` or `remediated`: select the reviewed NGINX package/configuration. |
| `DOJO_EVIDENCE_PUBLIC_ACCESS` | `false` keeps Blob evidence private during provisioning. |
| `DOJO_VIA_PORTAL` | `true` uses the authenticated private-evidence path for deploy, verify and report. |

Set both image flags to `true` for the complete four-application release.
Unset configuration variables preserve committed defaults, which keep optional
demos off. Keep the values unchanged across build, what-if and deploy: changing
them invalidates the configuration-bound release. NGINX must be provisioned
before its first release, and optional-image deployments require `accept-costs`.
The OIDC setup registers `Microsoft.ContainerInstance` for Dragon; `provision`
verifies registration rather than silently registering providers.

`DOJO_VIA_PORTAL` defaults to `false`. A runner using it must reach the portal
from an authorized IP/private path and read its credentials from Key Vault.
Setting it does not allowlist a public GitHub-hosted runner or change network
rules. DHI image access must be available on the selected runner; this workflow
does not copy credentials from the separate validation environment.

The optional Drowsy Dragon CI job is manually enabled and needs DHI pull
credentials, not Azure credentials. Store them only in a protected
`drowsy-dragon-images` environment restricted to `dev`, not as repository-wide
secrets. The job retains all-severity Trivy JSON/SARIF and package inventory
without inventing an expected CVE list. Its portal/report tracking keeps Trivy
evidence separate from Defender observations.
The independent NGINX CI job builds/scans both affected and target-CVE remediated
modes on pushes and pull requests. Drowsy Dragon remains manual because it needs
DHI credentials. Both optional demos use the same package/scan evidence helpers,
and may be enabled together for a four-image release including the admin portal.

Defender GitHub consent, repository discovery, native GitHub security features and
agentless scanner eligibility are separate prerequisites. Connect this repository
and verify discovery of its imported Maven/Java source. Scanner exclusions for
vendored code and Java analysis support must be checked independently of Maven
dependency analysis. See [GitHub setup and coverage](#connect-github-and-verify-coverage).

App Service is not AKS. No pod sensor, Kubernetes attack-path or guaranteed
repo-to-runtime edge is claimed. Private Dojo workload is ineligible for serverless
vulnerability assessment; use ACR assessment. `ServerlessContainers` is not enabled
for this App Service architecture. Alerts and attack paths may legitimately be absent.

## Deployment and Operation

Run `npm run manage` for the guided wizard, or `node scripts/deploy.mjs <action>`
for automation. The wizard is a numbered menu over the same lifecycle actions:
plan, configure, doctor, install, deploy, verify, report, remove, and an advanced
submenu for individual steps. Add `--audit` to any lifecycle action for an
offline, no-write plan. Azure mutations require exact action/subscription/group
approval; release and cleanup also bind approval to their evidence hashes. The
wizard shows the target lab, requires the resource group name to be typed for
billable and destructive steps, and supplies the same confirmation string the
CLI demands; it never weakens a gate. No environment is inferred from a Git branch.

Each live lifecycle action prints a local `file:///` deployment report link and
updates `output/<lab-id>/deployment-status.html` and its JSON counterpart as
stages progress. The HTML refreshes while a step runs and retains failed steps;
observed ARM resources are not mistaken for completed credential or HTTP checks.
GitHub Actions logs show the same progress and retain both status files as an
artifact after every operation. `--audit` and offline source checks write no
status files. The deployment status is separate from the security evidence report.

### Configure the Training Scope

Install Node.js 22+, npm, Git, Azure CLI with Bicep, Docker and Trivy. The release
build compiles Java 25/Maven inside Docker; local Java is not required. Ensure
Docker is running and review regional SKU availability, quotas and policies first.

```text
npm ci
npm run manage
```

Choose `2) Configure`. Select the subscription by name, ID and tenant; enter the
dedicated resource group, stable lab ID, Azure region, operator's **Entra object ID**
and current authorized public IPv4 `/32`. Subsequent commands use the ignored
local configuration. `DOJO_CONFIG` can select another private configuration.
Never put passwords, tokens or real training accounts in committed configuration.
The wizard also offers Drowsy Dragon, disabled by default. Enabling
`drowsyDragonEnabled` adds an ACI release with separate recurring-cost approval;
see its [walkthrough](apps/drowsy-dragon/README.md#opt-in-to-deployment).
The wizard separately offers `nginxProxyEnabled` and `nginxProxyMode`
(`vulnerable` or `remediated`). Rerun approved provisioning when enabling NGINX
to create its additional plan and identity. Defaults do not enable either demo.

#### Network Access Settings

The wizard also configures the following settings. Edit them in the ignored
`config/deploy.local.json`, or select another JSON file with `DOJO_CONFIG`.
Older files that omit these fields use the defaults below without being rewritten.
The [deployment workflow](.github/workflows/deploy.yml) preserves these fields
from [committed defaults](config/deploy.config.json) in its per-run configuration.
Direct Bicep deployments accept the same parameter names: vault settings belong
to [foundation.bicep](infra/foundation.bicep), and Dojo settings to
[main.bicep](infra/main.bicep).

| Setting | Default | Effect |
| --- | --- | --- |
| `keyVaultPublicAccess` | `true` | Enable the vault's public endpoint; `false` requires private connectivity. |
| `keyVaultRestrictToAdminIp` | `false` | When public access is enabled, `true` limits it to the configured admin `/32`; `false` allows all networks. |
| `keyVaultPublicAccessTags` | `{"SecurityControl":"Ignore"}` | Vault-only tags for your public-network policy exception. Use `{}` for no exception, or provide your organization's reviewed tags. |
| `dojoPublicAccess` | `true` | Enable the WebGoat website's public endpoint; `false` requires private connectivity. |
| `dojoRestrictToAdminIp` | `false` | When public access is enabled, `true` limits it to the configured admin `/32`; `false` allows all networks. |
| `evidencePublicAccess` | `true` | Enable the evidence account's admin-IP-restricted public endpoint. Set `false` to require Private Link and use `--via-portal` or an authorized private-network runner. Shared keys and anonymous blob access remain disabled. |

Public-access switches must be JSON booleans, not `"true"`/`"false"` strings.
Policy tags must have nonempty names and string values, and cannot override lab
ownership tags. They are not applied when `keyVaultPublicAccess` is `false`.
Changing tags does not bypass a policy that does not recognize them.

For a private-only deployment, set both `keyVaultPublicAccess` and
`dojoPublicAccess` to `false`. For admin-IP-only public endpoints, leave those
two switches `true` and set both `RestrictToAdminIp` switches to `true`.
The restriction switches have no effect while their public endpoint is disabled.
RBAC, purge protection, HTTPS, private endpoints, outbound isolation and SCM/FTP
restrictions remain enabled; the portal stays admin-IP-only and NGINX stays private.
Application routing uses the App Service site's
`outboundVnetRouting.applicationTraffic` property, rather than the legacy nested
route-all setting. Image-pull and other configuration traffic are controlled
separately, so registry pulls do not enter the workload's Internet-denied subnet.

Run `npm run plan` to see the resolved choices before deploying. Vault changes
require an approved `provision`; website changes require an approved `deploy`.
Configuration changes invalidate existing release manifests, so rebuild and
review the release for the new configuration. A private vault also requires
the private execution/bootstrap path described below.
SDK provisioning and rotation must run from an allowed IP or approved private
path for restricted vaults; public GitHub-hosted runners are not automatically
allowlisted.

The bootstrap operator needs resource creation and role-assignment rights at the
lab group, subscription role-assignment rights for portal Security Reader, and
Security Admin or equivalent rights for the separately approved Defender pricing
operation. The default principal type is a human User. Do not substitute a client
ID for an object ID or run bootstrap as an unreviewed CI identity. The applications
must not receive bootstrap or Defender-write permissions.

```text
npm run plan
node scripts/deploy.mjs doctor
```

`plan` is offline. `doctor` reads context, ownership, tools, providers and plan
state, rejecting wrong cloud/tenant/subscription or missing build tools. It does
not prove RBAC sufficiency, quota, policy compatibility or private connectivity;
those require live preflight/what-if and acceptance checks. No command silently
switches tenants or changes the CLI's global subscription selection.

### Provision and Enable Protection

Use the wizard's `4) Install` step, or run `provision` directly. Review the target
and recurring charges, then provide the exact action/subscription/group
confirmation and cost consent:

```text
node scripts/deploy.mjs provision --confirm "provision:<subscription-id>:<resource-group>" --accept-costs
```

The OIDC bootstrap registers providers, creates the ownership-tagged group and
grants the portal subscription Security Reader role. Provision verifies that
state, previews and deploys the foundation, then creates the missing admin username,
password and session key directly in Key Vault. Existing valid values are preserved;
adding the username does not rotate the password or signing key. An existing
untagged group is not adopted. RBAC propagation can delay secret creation.
If configuration or policy disables public vault access, the SDK secret step requires an approved
VNet-connected execution path to the private endpoint; a successful ARM deployment
alone does not complete installation. Do not expose the vault publicly or place
secret values in deployment parameters to work around private-link access.

For a private-only vault, use the temporary bootstrap worker after foundation
provisioning. It uses the existing portal plan and delegated subnet, has no public
ingress, and receives only ACR pull and vault-scoped Secrets Officer roles. Commit
reviewed code first, then run:

```text
node scripts/bootstrap-secrets.mjs prepare --audit
node scripts/bootstrap-secrets.mjs prepare --confirm "bootstrap-build:<subscription-id>:<resource-group>"
node scripts/bootstrap-secrets.mjs apply --confirm "bootstrap:<preview-hash>:<subscription-id>:<resource-group>"
```

`prepare` builds and scans a pinned worker image, pushes it by digest, and prints
the state-bound token from ARM what-if. `apply` repeats what-if, verifies all three
required values inside the VNet, then stamps their existing versions with a non-secret
run ID. ARM rereads their tags, enabled state and expiry without returning secret
values. It removes the temporary site, identity and grants on completion or
failure, preserving the portal plan. A fresh ARM readback and cleanup are required
before `deploy` accepts the ignored, short-lived bootstrap proof. Log Analytics
console events are diagnostic only. Review the stored preview;
never pass secret values on the command line or enable public vault access.

No application image is selected in this stage. Two hosting plans, ACR, private
endpoints, logs, storage and Key Vault incur charges even before release. Review
current pricing for the chosen subscription/region; this project does not provide
a verified cost estimate.

Review `doctor` and the subscription's current settings before separately approving
paid protection:

```text
node scripts/deploy.mjs protection --confirm "protection:<subscription-id>:<resource-group>" --accept-costs
```

This change is **subscription-wide**, including other eligible workloads. A
non-secret before-snapshot is saved in ignored output. Reconciliation preserves
unrelated extensions and their properties, refuses conflicting paid subplans,
and independently rereads changes. Failed extension operation status is not healthy
coverage even when `isEnabled` is true. An API or policy failure must be investigated,
not bypassed. Ordinary cleanup never downgrades subscription plans or disables
other workloads' VM, Kubernetes or sensitive-data protections.

### Connect GitHub and Verify Coverage

An authorized organization owner/subscription administrator must complete
[GitHub connector onboarding](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-github).
Select only this repository and any separately authorized source fork needed for
the exercise. Reuse a matching authorized connector where appropriate. Consent is
interactive; a connector resource alone does not establish consent, health or
repository discovery. Verify those after ingestion.

Enable GitHub dependency graph, Dependabot alerts, code scanning and secret scanning
where supported, permitted and licensed. GitHub-native alerts, pipeline SARIF and
Defender findings are distinct evidence sources. The workflow retains SARIF as
artifacts; it does not automatically upload it as native GitHub code-scanning alerts.

[Agentless code scanning](https://learn.microsoft.com/azure/defender-for-cloud/agentless-code-scanning)
evaluates supported connected repositories/default branches independently of CI.
Confirm current [support](https://learn.microsoft.com/azure/defender-for-cloud/devops-support),
particularly Java source analysis versus Maven dependency analysis. This repository
contains the pinned source and Maven manifest under `apps/dojo/upstream`; verify
scanner scope and exclusions include that directory. The portal deliberately keeps
connector/native coverage unknown when it cannot independently verify it.
The imported NGINX JavaScript/dependency snapshot lives under
`apps/nginx-proxy/upstream`; verify its scanner coverage and exclusions separately.

Ordinary push and pull-request validation has no Azure credentials or writes. Only
the manual, protected deployment workflow uses environment-scoped OIDC, and deploy
requires the exact token produced while reviewing the same build artifact.

### Build, Review and Release

The [source lifecycle](apps/dojo/README.md) documents the imported source, licenses,
upstream refresh and integrity checks. Review the full source commit before syncing:

```text
npm run source:upstream
npm run source:sync
npm run source:check
npm run image:build
```

Commit the reviewed source snapshot, lock and configuration pin together before
creating a release. The tool never creates commits. Local `image:build` does not
scan or publish; the environment `build` action performs the release pipeline:

```text
node scripts/deploy.mjs build --confirm "build:<subscription-id>:<resource-group>"
```

It verifies the imported snapshot, compiles its JAR in Java 25, retains the upstream
runtime recipe, builds the separate portal, and scans both images with Trivy before
pushing either. Portal HIGH/CRITICAL findings fail the build. Intentional Dojo
findings still require review and must be distinguished from scanner failures.
Source labels, tree/content hashes and scan hashes accompany immutable ACR digests
in the ignored release manifest. A changed configuration invalidates that manifest.

#### Dockerfile and Deployment Inventory

| Recipe | Deployment use |
| --- | --- |
| [Control portal](apps/control-portal/Dockerfile) | Pinned non-root Node runtime, port 8080, digest-pinned App Service. Its dependency stage is not deployed separately. |
| [WebGoat runtime](apps/dojo/upstream/Dockerfile) | Input to the [owned recipe generator](scripts/lib/dojo-source.mjs), which pins Java 25, builds the JAR, and produces the Dojo image for App Service on port 8080. |
| [Drowsy Dragon](apps/drowsy-dragon/Dockerfile) | Pinned SDK image with `sleep infinity`, deployed to no-ingress ACI when enabled; it has no HTTP health endpoint. |
| [NGINX Proxy](apps/nginx-proxy/upstream/Dockerfile) | Original reviewed training recipe; App Service routes and probes port 80 through NGINX to its Node dashboard on port 3000. Deployed privately when enabled. |
| [Credential utility](scripts/Dockerfile.secret-bootstrap) | Scanned ACR image run only for private credential bootstrap, then its temporary site/identity/grants are removed. |
| [Upstream desktop example](apps/dojo/upstream/Dockerfile_desktop) | Preserved WebGoat desktop/ZAP example, not an Azure workload and not part of the release. |

Every enabled application image must finish scanning before any push. The release
validates ACR manifest digests before deployment. Upstream NGINX and WebGoat
recipes remain unmodified imports; their source-lock checks fail on unreviewed
changes. The original NGINX Docker healthcheck probes Node's port 3000, while the
Azure health probe explicitly tests NGINX's port 80 and its forwarded `/health`.
NGINX's training package version and upstream tag-based Ubuntu/Node dependencies
are not a production-hardening claim; the actual released image is pinned in ACR.

When Drowsy Dragon is enabled, the same build includes its pinned SDK image,
package inventory and complete Trivy scan. A release refuses missing or
tampered demo evidence; all enabled images must finish scanning before any push.
Enabled NGINX releases also verify the original source snapshot, selected package
version and full-image Trivy evidence. Its affected and target-CVE-remediated
modes are documented in the [image story](apps/nginx-proxy/README.md).

```text
node scripts/deploy.mjs what-if
node scripts/deploy.mjs deploy
```

An unconfirmed deploy prints the exact required token and exits without deployment.
`what-if` now prints the same token, so the wizard's `5) Deploy` step can show the
what-if output and then apply the reviewed release after the resource group name
is typed. Review both scans and what-if before approving the exact release:

```text
node scripts/deploy.mjs deploy --confirm "deploy:<release-hash>:<subscription-id>:<resource-group>"
```

The script verifies scan hashes and registry digests, requires configured Defender
readback, checks credentials, then applies the image-release template. A failed
build never changes the running app. `repair` reapplies the reviewed release; it
does not rebuild, rotate all credentials or weaken protection. Retain the previous
manifest and scans for rollback. `--release <manifest-path>` selects a reviewed
prior manifest with its original source/configuration binding. Do not commit
sensitive release records or confuse a restart/digest with verified HTTP health.
Enabled Drowsy Dragon releases also require `--accept-costs` and preserve a
digest/scan-hash-bound receipt in the private evidence store. ACI readback and
package findings appear in the portal and HTML/JSON reports; no HTTP test is
sent to the sleeping container.

#### Publish and Verify Through the Private Portal Connection

When the workstation cannot reach private Blob storage, use the existing
admin-IP-restricted portal as the authenticated evidence path:

```text
node scripts/deploy.mjs deploy --confirm "deploy:<release-hash>:<subscription-id>:<resource-group>" --accept-costs --via-portal
node scripts/deploy.mjs verify --via-portal
node scripts/deploy.mjs report --via-portal
```

The CLI reads the shared username/password from Key Vault using the signed-in
Azure identity, holds credentials and session tokens only in memory, and revokes
its session after the operation. The portal enforces its usual origin, session,
CSRF and rate limits before accepting a bounded image receipt. Only the reviewed
Drowsy Dragon and NGINX receipt formats are accepted; all artifact hashes and
package coverage are checked. Receipt keys are derived from the demo, ACR digest
and scan hash. Writes are create-only with exact readback; matching retries are
idempotent and conflicting evidence stops deployment. Receipt publication must
succeed before ARM deployment; no direct-deployment bypass is required.

The portal must already include the receipt endpoint. For an older installation,
first build/scan/push a reviewed portal image and apply only its digest while
preserving its settings, identity and network controls, then run the full guarded
release above. If the vault is private too, run the CLI from an authorized path
that can read its credentials. Do not expose storage, widen vault access, or
export credentials to work around connectivity.

`--via-portal` verification collects private scan receipts, run records and NGINX
startup measurements through the portal's VNet connection. It still reports
unknown Defender connector/detection evidence rather than treating it as success.

### Sign In and Walk Through the Story

Open the printed portal URL from the configured admin IP. Retrieve `admin-username`
and `admin-password` directly through an authorized Key Vault session, then use
that pair to sign in. The initial username is `admin`; a valid existing username
is preserved. Never
send credentials through chat, command-line arguments, reports or browser JavaScript.
Sessions last one hour; logout revokes the stored session.

In the Azure portal, open the lab's Key Vault, then **Secrets > admin-username >
current version > Show Secret Value**; repeat for `admin-password`.

| Purpose | Key Vault entry |
| --- | --- |
| Portal login username | `admin-username` |
| Portal login password | `admin-password` |
| Portal session signing, not a login credential | `session-key` |

The portal reads its username through the same versionless Key Vault reference
mechanism as the password and signing key; it has no hard-coded login fallback.
Usernames must start with a letter or digit, contain only letters, digits,
`.`, `_`, `@`, `+` or `-`, and be at most 128 characters. After deliberately
changing the username in Key Vault, use the credential rotation workflow below to
refresh references and restart the portal; retrieve the new password afterward.
Rotation preserves the username while renewing its expiration and regenerating
the password and signing key.

Azure registry, storage and service access uses managed identities, not shared
username/password pairs. Individual WebGoat lesson accounts remain separate and
are not copied into this vault.

By default the vault accepts public
connections from all networks. An admin-IP-only profile requires the configured
IP, and a private-only profile requires approved private connectivity. Reading a
secret always requires an authenticated Entra identity with Key Vault data-plane
permissions. Public access is not anonymous access.

By default the foundation tags only the public training vault with `SecurityControl=Ignore`, the
inherited management policy's explicit exception, so that policy does not rewrite
`publicNetworkAccess` to `Disabled`. Customize or disable these tags with
`keyVaultPublicAccessTags`; private-only vaults do not receive them.
RBAC, purge protection and the private endpoint
remain enabled. This exception does not apply to the resource group, evidence
storage or workloads; the portal's admin-IP restriction is unchanged. Do not use
this training configuration for production credentials.

Follow Source, Build & Assess, Cloud Posture, Runtime Validation, Remediate & Compare,
and Report & Retire. Refresh collects actual configuration and evidence. API errors,
permission failures, incomplete queries, missing assessments and pending scans must
not be converted into passing results. A configured control is not a demonstrated
detection. Subscription Security Reader is read-only but broad; review its boundary.

Open the printed WebGoat URL
(`https://<dojo-app-name>.azurewebsites.net/WebGoat/`) for interactive lessons.
The bare app URL redirects to that canonical path instead of returning Tomcat's
default 404, and the release IaC also returns the canonical URL as `dojoUrl`.
WebGoat uses its own lesson accounts: create disposable training credentials,
never reuse the portal admin password.
The default profile permits all public IPs over HTTPS. Admin-IP-only and private
profiles require their configured network path. Its private endpoint and
Internet-denied outbound subnet remain in place; it is not reverse-proxied into
the portal. The shared app module keeps `restrictToAdminIp` enabled by default,
and the Dojo deployment chooses its value from `dojoRestrictToAdminIp`.
The portal retains its admin-IP restriction,
the optional NGINX Proxy stays private, and SCM/FTP access remains blocked.

The fixed test runner still uses private connectivity. From the authorized `/32`,
`GET /health/dojo` on the portal checks only the fixed private Dojo health path
over its VNet integration: HTTP 200 means the Dojo responded; 503 or a redirect
does not. No credentials, attack request or Blob evidence are involved. The
`verify` report records this HTTP result separately from the portal's own
`/health` and from private Blob run evidence, which may remain unavailable to
a workstation outside the VNet. `GET /health/evidence` on the same restricted
portal returns only whether its managed identity can read private evidence-container
metadata; it does not list or expose run records. The verifier reports that
connectivity separately and still requires an authenticated portal session for full run
evidence. WebWolf on port 9090 is not exposed;
use upstream localhost instructions for dependent lessons. Do not broaden the
remaining isolation controls to make an exercise or attack-path finding appear.

### Run Tests and Compare Evidence

Admin tests require authentication, same-origin/CSRF checks and explicit consent.
The server selects a fixed deployment target and request, records evidence before
sending, uses HTTPS/timeouts and refuses redirects. Blob leases serialize tests
across instances with a 60-second cooldown. Failed evidence writes stop the request.
There are no arbitrary URLs, payloads, commands, external targets, metadata probes
or network-wide scans. The SQL-shaped input probe is not a successful exploit or
authenticated WebGoat lesson.

Microsoft's App Service validation suffix is `/This_Will_Generate_ASC_Alert`.
New sites may require 24 hours for registration, with alerts taking approximately
2-4 hours. Follow the [validation procedure](https://learn.microsoft.com/azure/defender-for-cloud/alert-validation)
and check hosting eligibility first. Those timings are not guarantees.
Microsoft-generated sample alerts use simulated resources and cannot be presented
as detections of this lab.

Reports filter alerts to the exact enabled training resources and use activity time for per-run
candidates. Keep these outcomes distinct: request executed/rejected/failed; alert
matched by resource/time only; matching run-specific evidence where actually
available; no alert observed yet; and API unavailable or scan pending. The current
candidate matching does not establish causation. An alert does not prove prevention,
and a successful request does not prove detection.

For remediation, pin a reviewed fix, rebuild, rescan and approve the new digest.
Wait for actual reassessment before comparing same-scope JSON snapshots. Count or
revision differences alone do not prove remediation. Export HTML for browser PDF
printing and JSON for archival; retain failed/incomplete reports and the full Blob
audit history, not just the latest 100 runs displayed in the portal.

Public reachability alone does not establish eligibility for serverless vulnerability
assessment. Verify service prerequisites and actual assessments; ACR image assessment
is separate evidence. Other posture/App Service capabilities require independent
checks. No Kubernetes sensor, generated attack path or complete source-to-App-Service
runtime mapping is guaranteed by image labels.

### Rotate Credentials and Clean Up

Credentials expire after 90 days. Rotate before expiry:

```text
node scripts/deploy.mjs rotate --confirm "rotate:<subscription-id>:<resource-group>"
node scripts/deploy.mjs verify
node scripts/deploy.mjs report
```

Rotation creates new Key Vault versions, retaining the username and renewing its
expiration, requests reference refresh and restarts the portal. Verify the new
password and rejection of old sessions before sharing
access. This is an explicit operator workflow, not unattended rotation, and its
live behavior remains unverified.

Export required HTML/JSON reports and Blob run/audit records before deletion.
These can contain subscription IDs and security findings; protect and redact them
before external sharing. Review the whole dedicated group, including its ACR images:

```text
node scripts/deploy.mjs inventory
node scripts/deploy.mjs deprovision --confirm "deprovision:<inventory-hash>:<subscription-id>:<resource-group>" --evidence-exported
```

The wizard's `8) Remove` step runs the same two commands, printing the inventory
and requiring both an evidence-export acknowledgement and the typed resource group
name before deletion.

Changed inventory invalidates the approval hash. Deletion rereads ownership and
removes the group plus the matching owned portal subscription reader assignment.
Never place unrelated resources in this group.
This also removes an enabled Drowsy Dragon container and its pull identity.
Turning its option off does not remove resources in incremental mode; an
observed retained instance is reported as a gap, not silently treated as stopped.
NGINX site/plan/private-endpoint resources follow the same cleanup boundary.
An optional NGINX plan can keep billing even before the site has been deployed;
disabling its flag is not a cleanup operation.

Subscription Defender plans and GitHub consent are retained. Purge-protected vaults
retain deleted credentials for at least seven days and may block immediate name
reuse. Recovery or a reviewed new lab ID is an explicit decision; the wizard does
not purge vaults or disable other workloads' protection. Verify resource absence,
retained permissions/services and continuing charges afterward.

## Troubleshooting

- **Portal/private-workload 403:** check the public admin IP, private DNS/endpoints
  and RBAC propagation. Do not broaden those endpoints as a workaround.
- **Public WebGoat 403:** verify the deployed settings match `dojoPublicAccess`
  and `dojoRestrictToAdminIp`. Admin-IP-only access requires the configured `/32`;
  private-only access requires the VNet path. SCM must still default to `Deny`.
- **Key Vault secret 403:** verify the deployed network mode matches your vault
  configuration, any required policy exception is present, and your identity has
  Key Vault data-plane read permissions. Use the approved IP or private route for
  restricted profiles. A public endpoint does not grant access to secrets.
- **Unresolved Key Vault reference:** check the portal identity's Secrets User role,
  enabled/unexpired secrets, private DNS and VNet routing. Startup fails closed.
- **Unknown report checks:** inspect Reader/Security Reader permissions, API
  availability and ingestion. Errors are deliberately not converted into zero findings.
- **Missing Trivy:** install it before release builds; there is no skip-scan release path.
- **Provider, SKU or policy failure:** review the error against the approved target.
  Scripts must not silently change regions, subscriptions or security settings.

## Security

Read [SECURITY.md](SECURITY.md) before deploying or reporting a vulnerability.
Never publish credentials, environment-specific configuration, exports, build
receipts, screenshots with identifiers or Azure state. Ignored files are not a
substitute for reviewing what Git will publish; already tracked files remain tracked.

```text
npm run check:public
npm audit --omit=dev
```

The publication guard checks tracked/non-ignored files, public defaults and source
integrity without printing matched values. Its sole reviewed upstream marker
exception is tied to an exact file hash. It is not exhaustive secret detection and
does not scan remote history or unpack archives. Enable GitHub secret scanning and
push protection where available; use a dedicated history scan before publication.

The imported WebGoat source intentionally contains vulnerable examples and public
training fixtures. Do not reuse them as real credentials or disable scanning of
the control portal. Preserve upstream licenses and explanatory training comments;
the workload and portal must remain separate. Private ingress and RBAC do not prove
complete outbound containment, and the shared admin login does not provide SSO/MFA
or individual operator accountability.

## Validation

```text
npm test
npm run check:public
npm run test:browser
```

Browser tests use installed Edge on Windows; elsewhere install Chromium with
`npx playwright install --with-deps chromium`. Screenshots go to ignored output.
Run Bicep compilation on the three root templates, ShellCheck on both wrappers,
and Actionlint on the workflow. A full release also requires Docker/Trivy and an
approved disposable Azure target. Local tests are not a substitute for that gate.

`verify` and `report` return exit code 2 when collected checks contain gaps or
unknowns, including connector coverage that this collector cannot independently
verify. Exported reports are still available; do not treat that exit code as proof
that every deployed service failed.

Before a live workshop, run provision/protection/release twice on an approved
disposable target and confirm no unwanted second-run changes. Verify deterministic
roles, actual image startup, Key Vault references, login/logout/rotation, private
test connectivity, unauthorized access denial and plan/extension readback. Run only
an explicitly authorized bounded test, export its actual evidence, then prove
cleanup and identify retained subscription-wide costs and permissions. Compilation
and mocked tests do not establish these live results.

## Official References

- [Defender pricing](https://azure.microsoft.com/pricing/details/defender-for-cloud/)
- [Defender App Service alert validation](https://learn.microsoft.com/azure/defender-for-cloud/alert-validation)
- [App Service alert reference](https://learn.microsoft.com/azure/defender-for-cloud/alerts-azure-app-service)
- [Serverless protection eligibility](https://learn.microsoft.com/azure/defender-for-cloud/serverless-protection)
- [Serverless container posture and supported services](https://learn.microsoft.com/azure/defender-for-cloud/posture-for-serverless-containers)
- [Defender for Containers enablement](https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-enable-plan)
- [ACR vulnerability assessment](https://learn.microsoft.com/azure/defender-for-cloud/agentless-vulnerability-assessment-azure)
- [GitHub connector and consent](https://learn.microsoft.com/azure/defender-for-cloud/quickstart-onboard-github)
- [DevOps support matrix](https://learn.microsoft.com/azure/defender-for-cloud/devops-support)
- [Agentless code scanning](https://learn.microsoft.com/azure/defender-for-cloud/agentless-code-scanning)
- [Container code-to-runtime mapping](https://learn.microsoft.com/azure/defender-for-cloud/container-image-mapping)
