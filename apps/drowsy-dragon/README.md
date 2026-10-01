# Drowsy Dragon

**The dragon is sleeping. The package scanner is not.**

An opt-in code-to-cloud package-vulnerability demonstration using the exact
digest-pinned DHI .NET 8 SDK recipe below. It prints four Debian package versions
at build time, then sleeps indefinitely. It does **not** compile or serve a .NET
application, expose HTTP, or run an exploit.

```dockerfile
FROM dhi.io/dotnet:8-sdk@sha256:a04b53a72db39c248b8947109d1cce6718a7449b7828d85bdb1b8e1cc4e1b6ef

RUN dpkg-query -W libc6 libc-bin tar libgcrypt20

CMD ["sleep", "infinity"]
```

The executable [Dockerfile](Dockerfile) and
[approved demo metadata](../../shared/drowsy-dragon.mjs) must agree. Builds fail
if the base pin or commands drift. Images are built for `linux/amd64`.

## What this demonstrates

| Step | Evidence to keep | What it does not prove |
| --- | --- | --- |
| Code | Reviewed Dockerfile, Git revision, base digest and recipe hash | Imported .NET application source or a native repository-to-runtime edge |
| Build | Derived image ID and `dpkg-query` inventory | That a hardened or digest-pinned image is vulnerability-free |
| Scan | Full Trivy JSON, SARIF, timestamps and hashes | Defender ingestion, runtime exploitability or a guaranteed CVE list |
| Cloud | ACR release digest, ACI image/state and no-ingress readback | Application HTTP health or exploit detection |
| Compare | Package versions, finding IDs, scanner timestamps and before/after digests | Remediation based only on changing finding counts |
| Retire | Approved resource-group inventory and evidence export | Removal of subscription-wide Defender charges |

Track `libc6`, `libc-bin`, `tar` and `libgcrypt20`. The full image scan is retained,
including findings outside those packages. There are deliberately **no hard-coded
CVE IDs or expected vulnerability counts**: record what the scanner actually
reports for this platform, digest and database version. Missing, failed or
incomplete scans are not a clean result. Even an observed zero is only a snapshot.

## Build and scan locally

Requires the repository's Node/npm dependencies, a running Linux Docker engine
and Trivy with `image --list-all-pkgs` and `convert` support (CI pins 0.69.3).
Authenticate to `dhi.io` with an authorized Docker account if required:

```text
docker login dhi.io
npm run image:build:dragon
```

Use Docker's credential store and interactive login; never put registry tokens
in Git, deployment configuration, Dockerfiles, build arguments or reports.
The build context contains only this demo directory.

The helper builds the unchanged recipe, collects inventory from a short-lived,
read-only container with networking and Linux capabilities disabled, and scans
all severities. It saves `packages.txt`, `scan.json`, `scan.sarif` and
`local-image.json` under the ignored `output/images/drowsy-dragon/` directory.
The normal container command remains `sleep infinity`; the temporary inventory
container explicitly runs `dpkg-query` and exits. Local builds never push or
deploy, and scanner failures stop the command.

## Opt in to deployment

Follow the root [deployment guide](../../README.md#deployment-and-operation).
Choose Drowsy Dragon during `npm run manage` configuration, or set this boolean
in the ignored local configuration selected by `DOJO_CONFIG`:

```json
{ "drowsyDragonEnabled": true }
```

This is one property of the existing configuration, not a replacement file.
The committed default is `false`; older local configurations without this
property retain the two-image WebGoat/portal behavior.

Run the approved `provision` action after enabling the option so the
`Microsoft.ContainerInstance` provider is registered. Provision does not start
the dragon. Commit reviewed source changes before an environment release build;
the lifecycle refuses dirty releases and never creates commits for you.

```text
node scripts/deploy.mjs build --confirm "build:<subscription-id>:<resource-group>"
node scripts/deploy.mjs what-if
node scripts/deploy.mjs deploy --confirm "deploy:<release-hash>:<subscription-id>:<resource-group>" --accept-costs
node scripts/deploy.mjs verify
node scripts/deploy.mjs report
```

The enabled release builds/scans a third image and pushes it to the lab ACR.
Portal HIGH/CRITICAL findings still block release; Drowsy Dragon findings are
retained for review rather than suppressed or converted to a production exception.
Changing configuration invalidates the old release manifest.
Rollbacks also require the matching reviewed demo recipe and metadata, not only
an old release manifest with the same configuration.

The [ACI module](../../infra/modules/drowsy-dragon.bicep) deploys one Linux
container with 1 vCPU and 1 GiB requested memory, **no IP address or exposed
ports**, and a separate managed identity granted only ACR pull. It receives no
portal credentials, evidence-store permissions or Defender-write access.
There is no App Service health probe or command override.

This is no-public-ingress isolation, not a promise of outbound network
containment. The container keeps running and billing until explicitly removed.
Review regional capacity, policy and pricing; `deploy` and `repair` require
`--accept-costs` whenever the option is enabled. The wizard asks for the same
approval. No Azure resources are created by CI or by a local image build.

## Present the demonstration

1. Show the approved base digest and the four installed package versions.
2. Review Trivy JSON/SARIF, including installed/fixed versions, severity and
   advisory identifiers actually returned. Distinguish tracked-package findings
   from the complete image findings count.
3. Approve the derived ACR digest, not the base-image digest as a substitute.
   The release verifies artifact hashes before publishing a scan receipt to the
   private Blob evidence store and applying the ACI template.
4. Open **Overview**, **Code-to-cloud story**, **Findings & alerts** and
   **Deployment status** in the portal. Collection reads the actual ACI state
   and image, then loads the receipt identified by that digest and the
   `dojo.scanHash` tag. The receipt carries the original inventory, Dockerfile
   and Trivy JSON; collection verifies their hashes and scan coverage of all four
   packages before reporting findings.
5. Inspect Defender's ACR assessments independently after ingestion. Trivy
   findings are never relabeled as Defender findings. No ACI sensor, alert or
   attack path is guaranteed. The portal's HTTP test buttons remain WebGoat-only.
6. Export HTML/JSON reports and the full Blob/local evidence before cleanup.
   Reports include the package inventory, observed image, findings, timestamps
   and hashes, but do not expose the full scanner artifact through the UI.

For remediation, review a newer base digest, update the Dockerfile and approved
metadata together, then rebuild, rescan and deploy through the same gates.
Compare same-scope snapshots and individual findings; a lower count alone is
not proof that a particular CVE was fixed.

## Optional CI evidence

The [validation workflow](../../.github/workflows/dojo.yml) always tests the
integration. Its additional image job runs only on an explicit manual dispatch
with the `drowsy-dragon` boolean enabled. Configure the `DHI_USERNAME` and
`DHI_TOKEN` repository secrets for an account authorized to pull the pin. The
job fails explicitly if either is missing, signs out after use, and retains the
`drowsy-dragon-evidence` artifact. It has no Azure credentials or deployment step.

## Cleanup and limitations

Use the existing [export and removal workflow](../../README.md#rotate-credentials-and-clean-up).
The dedicated group inventory includes the ACI group, its pull identity, ACR
image and evidence store. Deletion requires the existing ownership, inventory
hash and evidence-export approvals.

Setting `drowsyDragonEnabled` back to `false` prevents new builds/deployments but
**does not delete an existing container** in incremental deployment mode.
Reports flag an observed retained instance as a gap. Export evidence and use
approved lab removal; do not assume disabling the option stops billing.

Local tests and compilation are not live Azure acceptance. Validate DHI access,
the pinned platform manifest, regional ACI support, identity propagation, no
ingress, scanner coverage, receipt collection, Defender ingestion and teardown
on an authorized disposable training subscription before presenting a workshop.
