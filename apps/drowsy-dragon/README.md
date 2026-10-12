# Drowsy Dragon

**The dragon is sleeping. The package scanner is not.**

An opt-in code-to-cloud package-vulnerability demonstration using the exact
digest-pinned DHI .NET 8 SDK recipe below. It prints four Debian package versions
at build time, then sleeps indefinitely. It does **not** compile or serve a .NET
application, expose HTTP, or run an exploit.

```dockerfile
ARG BASE_IMAGE=dhi.io/dotnet:8-sdk@sha256:1ebc91b79beb49566cfb2a6a13bb6cdb42cea37e02b008248ae451e40aa7e792
FROM ${BASE_IMAGE}

RUN dpkg-query -W libc6 libc-bin tar libgcrypt20

CMD ["sleep", "infinity"]
```

The executable [Dockerfile](Dockerfile) and
[approved demo metadata](../../shared/drowsy-dragon.mjs) must agree. Builds fail
if the base pin or commands drift. Images are built for `linux/amd64`.

The [Docker Hub catalog](https://hub.docker.com/hardened-images/catalog/dhi/dotnet)
describes the available DHI .NET SDK images. The digest, not the moving `8-sdk`
tag, selects the exact approved image. A release built with the previous
base digest must be rebuilt and rescanned; its evidence is not valid for this pin.

## What this demonstrates

| Step    | Evidence to keep                                                           | What it does not prove                                                  |
| ------- | -------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Code    | Reviewed Dockerfile, Git revision, base digest and recipe hash             | Imported .NET application source or a native repository-to-runtime edge |
| Build   | Derived image ID and `dpkg-query` inventory                                | That a hardened or digest-pinned image is vulnerability-free            |
| Scan    | Full Trivy JSON, SARIF, timestamps and hashes                              | Defender ingestion, runtime exploitability or a guaranteed CVE list     |
| Cloud   | ACR release digest, ACI image/state and no-ingress readback                | Application HTTP health or exploit detection                            |
| Compare | Package versions, finding IDs, scanner timestamps and before/after digests | Remediation based only on changing finding counts                       |
| Retire  | Approved resource-group inventory and evidence export                      | Removal of subscription-wide Defender charges                           |

Track `libc6`, `libc-bin`, `tar` and `libgcrypt20`. The full image scan is retained,
including findings outside those packages. There are deliberately **no hard-coded
CVE IDs or expected vulnerability counts**: record what the scanner actually
reports for this platform, digest and database version. Missing, failed or
incomplete scans are not a clean result. Even an observed zero is only a snapshot.

## Build and scan locally

Requires the repository's Node/npm dependencies, a running Linux Docker engine
and Trivy with `image --list-all-pkgs` and `convert` support (CI pins 0.74.0).
Latest builds also require Docker Buildx with `imagetools inspect` support.
Authenticate to `dhi.io` with an authorized Docker account; even Community
images require login:

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

## Pinned releases and moving latest

The default `BASE_IMAGE` and approved metadata stay at the author-reviewed digest.
Normal builds and application releases use that pin even when Docker publishes
a newer image. The pipeline never edits the Dockerfile, metadata or approved pin.

For a local comparison against the current upstream `dhi.io/dotnet:8-sdk` image:

```text
npm run image:build:dragon -- --latest
```

The helper resolves the moving upstream tag through the registry, validates its
digest, and passes the resolved digest as `BASE_IMAGE` with `--pull`. It builds
`drowsy-dragon:latest` and records the actual base digest, package inventory and
all-severity scan separately under `output/images/drowsy-dragon/latest/`.
It does not relabel the approved pinned image as latest, or push a local build.

When Drowsy Dragon is enabled, each release build also builds, scans and pushes
this separate upstream-current image to the same app-named ACR repository as
`:latest`. The deployment workflow checks again every six hours at minute 17
UTC, using its registry-only publishing identity. Its manual `refresh-latest`
operation performs the same latest-only update. Scheduled jobs can be delayed
by GitHub; the tag represents the upstream digest resolved by the last
successful run, not an instantaneous Docker Hub webhook.

Latest evidence is retained as `drowsy-dragon-latest-<run-id>` with
`published-image.json` recording the base and derived ACR digests. A failed
resolution, scan or image-integrity check stops before the push; failed registry
readback is not reported as verified publication.
Latest is not added to the approved release manifest, and latest-only refreshes
cannot run automatic application rollout. An upstream update does not invalidate
the unchanged approved pin; promoting that update still requires the author to
review and change the pin, then rebuild and release through the normal gates.

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

Run the approved `setup:github-oidc -- --apply` bootstrap to register required
providers, including `Microsoft.ContainerInstance`, then run `provision` after
enabling the option. Provision checks provider registration and does not start
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
When Blob storage is private to the lab VNet, add `--via-portal` to `deploy`,
`verify` and `report` as described in the root
[private publication guide](../../README.md#publish-and-verify-through-the-private-portal-connection).
The receipt must be stored and verified before deployment; do not bypass this gate.
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

For remediation, review a newer base digest and update the [Dockerfile](Dockerfile),
[approved metadata](../../shared/drowsy-dragon.mjs), digest assertions in the
[tests](../../tests/drowsy-dragon.test.mjs), and this recipe documentation in the
same commit. Run `npm test`, then rebuild, rescan
and deploy through the same gates. Updating only the Dockerfile fails CI before
the image build.
Compare same-scope snapshots and individual findings; a lower count alone is
not proof that a particular CVE was fixed.

## CI evidence

The [validation workflow](../../.github/workflows/dojo.yml) always tests the
integration. Its image job runs on pushes to `dev` and is enabled by default for
manual `dev` runs. Clear the `drowsy-dragon` checkbox to skip a particular manual
run. Pull requests and other branches cannot run this protected job.

The image-only `drowsy-dragon-images` environment is restricted to `dev` and does
not require manual approval. Configure organization secrets `DOCKER_USERNAME`
and `DOCKER_TOKEN` and allow this repository to use both. Use a Docker access
token authorized to pull the pin. The release build consumes the same secret
names in the automatic `code-to-cloud-images` publishing environment. On `dev`
pushes, the release workflow builds, scans and pushes the app-named image to ACR
with its dedicated registry-only writer identity. When
[automatic dev rollout](../../README.md#automatic-dev-rollout) is explicitly
enabled, a dependent job uses the separate `code-to-cloud-training` identity to
update every enabled application, reconcile the ACI scan tag and verify the
deployed digests and receipts. Otherwise application rollout remains manual.

A complete `DHI_USERNAME`/`DHI_TOKEN` pair in the relevant environment overrides
the organization Docker pair. Incomplete pairs fail explicitly rather than
mixing credentials or trying an anonymous pull. A successful workstation pull
does not establish that GitHub runners have registry access.
The job signs out after authenticated use and retains `drowsy-dragon-evidence`
plus the `drowsy-dragon-container` image/Dockerfile artifact. It has no Azure
credentials or deployment step. The separate release workflow owns Azure updates.

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
