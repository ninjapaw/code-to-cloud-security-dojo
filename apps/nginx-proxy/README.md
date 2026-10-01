# NGINX Proxy

The original NinjaPaws NGINX proxy joins WebGoat and Drowsy Dragon as a third,
independent code-to-cloud training image story. It proxies only its own dashboard
and evidence API, **never WebGoat or the admin portal**.

## Original source and target

The [source lock](source-lock.json) records a minimal eight-file import from
`ninjapaw/ninjapaws-cloud-security-dojo` at commit
`7a6d8fbd232000ab2de43f59a05ba5cdbc1e16c9`. The original
[Dockerfile](upstream/Dockerfile), [entrypoint](upstream/entrypoint.sh),
[proxy configuration](upstream/nginx.conf), [dashboard/API](upstream/src/app.js),
dependency manifests, legacy verification script and [MIT license](upstream/LICENSE)
are preserved unchanged. Builds and publication checks verify the snapshot hash.
Do not install dependencies or edit files inside the immutable `upstream` directory.

| Mode | NGINX package pin | Map/regex configuration | Meaning |
| --- | --- | --- | --- |
| `vulnerable` | `1.30.3-1~noble` | Present | Selected affected package/configuration for the target advisory |
| `remediated` | `1.30.4-1~noble` | Removed | Remediation for the target CVE, not a vulnerability-free image |

The target is [CVE-2026-42533](https://my.f5.com/manage/s/article/K000162097),
the map/regex buffer overflow. The
[official NGINX advisory list](https://nginx.org/en/security_advisories.html)
identifies 1.30.4 and 1.31.3 as fixed releases for this CVE. The older imported
dashboard describes its selected version branch, not the full affected range.
Other NGINX, OS or Node/dependency vulnerabilities can remain after this one fix.

Source and NGINX package versions are pinned. The inherited Ubuntu tag and
package feeds are not immutable base-image pins, so rebuilds are not assumed
byte-identical. Each release records the actual derived image digest and scan.

## Build the two images

From the repository root, with Node/npm dependencies, a Linux Docker engine and
Trivy available:

```text
npm run image:check:nginx
npm run image:build:nginx -- --mode vulnerable
npm run image:build:nginx -- --mode remediated
```

`image:check:nginx` is offline and checks source provenance only. The build
commands produce `nginx-proxy:vulnerable` and `nginx-proxy:remediated` locally.
They do not push, deploy, expose a port or run an exploit.

Builds use the imported recipe with allowlisted version/state build arguments.
OCI version/expectation labels override the original reproduction-only labels
so the remediated artifact is not mislabeled as 1.30.3 or guaranteed detection.
Inventory runs `dpkg-query -W nginx` in a temporary read-only, no-network,
capability-dropped container with the entrypoint overridden; it does not start
the legacy workload.

Full-image, all-severity Trivy JSON/SARIF, inventory and local receipts go to the
ignored `output/images/nginx-proxy/<mode>/` directory. The UI focuses on NGINX
findings while retaining the total image finding count. Scanner errors, missing
package coverage, source changes and inventory/version mismatches stop the build.

## Opt in alongside Drowsy Dragon

Use `npm run manage` and choose NGINX Proxy and its mode during configuration.
Both optional demos may be enabled simultaneously:

```json
{
  "drowsyDragonEnabled": true,
  "nginxProxyEnabled": true,
  "nginxProxyMode": "vulnerable"
}
```

These are properties of the existing ignored local configuration, not a
replacement for its tenant/subscription/ownership settings. Defaults remain
disabled; the unchanged default release has WebGoat and the control portal.
With both options enabled, the release has **four images**: WebGoat, the portal,
Drowsy Dragon, and NGINX Proxy.

Follow the root [deployment guide](../../README.md#deployment-and-operation).
Rerun approved `provision` after enabling NGINX so its separate App Service plan
and pull identity exist. Provisioning is already billable before the site starts.
Review and commit source changes before building an environment release.

```text
node scripts/deploy.mjs build --confirm "build:<subscription-id>:<resource-group>"
node scripts/deploy.mjs what-if
node scripts/deploy.mjs deploy --confirm "deploy:<release-hash>:<subscription-id>:<resource-group>" --accept-costs
node scripts/deploy.mjs verify
node scripts/deploy.mjs report
```

All enabled images must finish scanning before any push. Portal HIGH/CRITICAL
findings still block the release; training-image findings are preserved for
explicit review. Configuration or mode changes invalidate old release manifests.

The site has public network access disabled, a private endpoint, its own plan and
ACR-only pull identity. Its `/health` probe goes through NGINX on port 80, not
directly to Node on port 3000. It shares the lab's App Service private DNS zone
and existing VNet link without creating a conflicting second link.
It receives no portal credentials, evidence permissions or Defender-write access.

## Present the image story

1. Show the imported source revision, NGINX package pin and requested mode.
2. Show the actual package inventory and scanner output. Record whether Trivy
   associated **CVE-2026-42533**; a package inventory or target-CVE label alone
   is not a finding. Inspect Defender ACR assessment independently.
3. Approve and deploy the derived ACR digest. The private evidence store retains
   raw inventory, source lock, Dockerfile and Trivy JSON, bound to the deployed
   digest and `dojo.scanHash`/`dojo.mode` tags.
4. In the portal, open **Overview**, **Code-to-cloud story**,
   **Findings & alerts**, **Deployment status** and **Executive reports**.
   NGINX and Drowsy Dragon appear independently, with no inferred clean results.
5. From approved private connectivity, open the original dashboard or read
   `/api/status`. The portal collector uses only the fixed, authoritative
   App Service hostname and `/api/status` path, refuses redirects, bounds the
   response and checks the raw `runtime_verification` fields.
6. Change the local mode to `remediated`, rebuild/rescan and approve a new
   release. Compare binary/package versions, absence of the map configuration,
   individual CVE findings, timestamps and image digests in exported snapshots.

The existing portal HTTP test buttons remain WebGoat-only. No crash payload or
exploit is sent to NGINX. A defined map/regex block is not proof of reachability,
exploitability, a successful exploit, a Defender alert or prevention.

### Legacy evidence limitations

The original dashboard can fall back to configured vulnerability status when
its startup evidence file is unavailable. This integration **does not accept
that fallback as runtime evidence**. It requires actual binary/package/config
fields and otherwise reports unknown. Its `defender_monitoring` flags are
deployment intent; only the control portal's independent Azure readback reports
observed plan state.

The runtime JSON is generated at container startup; collecting it is not a new
binary/configuration probe. Recreate/restart through the approved release after
changes and compare fresh evidence. The preserved `/evidence` expectation label
and legacy `verify.sh` are reproduction-specific to 1.30.3, not remediation
verifiers. Use the integration's package and raw startup checks for both modes.

Local CLI collection without a private route/DNS may time out or return unknown.
Use the VNet-integrated portal or an authorized private network route. Never make
the site public to improve a demonstration or force an alert.

## CI, cleanup and maintenance

The [workflow](../../.github/workflows/dojo.yml) always checks source integrity and
tests this integration. Manually enabling its `nginx-proxy` input builds/scans
both modes and retains separate artifacts. No Azure credentials or writes are
needed, and it is independent of the optional DHI-authenticated job.

Export reports and raw evidence before the existing
[approved lab removal](../../README.md#rotate-credentials-and-clean-up).
The group inventory includes the NGINX site, plan, identity and private endpoint.
Disabling the option does not delete them in incremental deployment mode.
Reports flag retained resources, including a billable plan left after partial
provisioning. Subscription Defender settings remain outside ordinary cleanup.

Refreshing the original source requires a reviewed import, updated source lock
and approved metadata/recipe hashes together. Retain upstream notices and rerun
source, image, runtime and report checks. Import the raw Git blob bytes: archive
or checkout line-ending conversion must not change the pinned snapshot.
Do not copy private deployment
configuration, credentials, history or output directories from the old repository.
