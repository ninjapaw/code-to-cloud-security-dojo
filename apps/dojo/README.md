# Dojo Source and Image Lifecycle

[upstream](upstream/README.md) contains the actual source exported from the pinned
WebGoat repository, including Java lessons, static assets, Maven wrapper, build
configuration and upstream notices. It is not a submodule or a downloaded prebuilt
image. The separate control portal is not part of WebGoat's vulnerable runtime.

[source-lock.json](source-lock.json) records the upstream URL, commit, Git tree,
file count and a deterministic SHA-256 over file paths/content. Commit the snapshot,
lock and shared configuration together. The import preserves upstream bytes and
does not include upstream Git history. Its nested workflows are not root workflows.
The dojo-owned [overlay](overlay/) remains outside that snapshot. It adds only an
engine-level Tomcat redirect from the bare `/` path to the canonical `/WebGoat/`
site; every other request continues through WebGoat unchanged.

## Refresh Upstream

From the repository root:

```text
npm run source:upstream
```

This lists upstream HEAD/tags without changing files. Review a newer release, then
set the full **commit SHA** in `source.revision` in the [shared configuration](../../config/deploy.config.json).
Keep the same source pin in any ignored environment-specific configuration or
`DOJO_CONFIG` override; otherwise CI and local verification will correctly disagree.

```text
npm run source:sync
npm run source:check
```

Sync fetches that exact commit, validates required build/license files and imports
the complete exported snapshot. A second run is a no-op. Local source changes and
unowned directories are never overwritten. A copy-based staged update supports
Windows workspaces that refuse directory renames; an exclusive lock prevents two
syncs, and a verified previous snapshot is backed up during replacement.

After an interrupted sync, inspect any ignored staging/previous-copy directories
before removing them. Remove a stale `.source-sync.lock` only after confirming that
no import process is active. Never discard local changes just to pass verification.
For custom WebGoat changes, make them in an authorized fork, pin its reviewed commit
and reimport; keep dojo-specific build logic outside the upstream snapshot.

## Create an Image

```text
npm run image:build
```

This verifies the local snapshot, compiles it with Java 25/Maven in Docker, and
creates `dojo:local`. The owned generated multi-stage recipe retains the
upstream runtime recipe, adds the reviewed root-routing overlay, and swaps its JAR
copy to the builder stage. A recipe-specific Docker ignore file includes source
(upstream's ignore file allows only prebuilt output). Maven wrapper CRLF is
normalized **inside the Linux build stage only**.

`-- --tag dojo:scan` selects a different local tag. `-- --prepare-only`
generates the recipe/context metadata without Docker. Build receipts under ignored
output record the image ID and imported source lock. Local builds are explicitly
unscanned and never push, deploy or enable paid services.

## Publish and Deploy

The [foundation IaC](../../infra/foundation.bicep) provisions an environment-owned
Basic ACR, disables anonymous/admin authentication and grants app identities AcrPull.
The authorized operator requires ACR push permissions. No registry password is stored.

After source/import/build changes are reviewed and committed, the wizard's `build`
action verifies this snapshot, builds the Dojo workload and portal, scans both, then pushes
them to that ACR under a unique tag. Its release manifest captures upstream commit,
tree and content hash, scan hashes and registry digests. Older release manifests
without snapshot provenance must be rebuilt.

The separate reviewed `deploy` action uses [release IaC](../../infra/main.bicep) to
reference `registry/dojo@sha256:...`, never a mutable `latest` tag. Old images and
manifests remain available for reviewed rollback; rebuilding never automatically
removes prior images. Deprovisioning the approved lab group removes its ACR/images.
Export required evidence or images before that operation.

## Licensing

WebGoat is GPL-2.0-or-later. Preserve [LICENSE.txt](upstream/LICENSE.txt),
[COPYRIGHT.txt](upstream/COPYRIGHT.txt) and all bundled third-party notices. When
distributing an image, meet the applicable license requirements, including making
corresponding source available. Importing it does not relicense WebGoat as dojo code.
