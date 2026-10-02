# Security Policy

## Scope

This is experimental, intentionally vulnerable training software. It is not
production-ready and must not host real data or credentials. The imported WebGoat
workload contains known educational vulnerabilities; the control portal, lifecycle
tooling and deployment boundaries are not intended to be vulnerable.

The optional [Drowsy Dragon](apps/drowsy-dragon/README.md) retains a pinned DHI
.NET SDK image for OS-package assessment. Its name and pin are not proof of
specific vulnerabilities: preserve actual scan evidence. It runs without an IP
address, exposed ports or application credentials and is not an HTTP exploit
target. Its pull-only identity must never receive portal or evidence permissions.

The optional [NGINX Proxy](apps/nginx-proxy/README.md) preserves a reviewed,
licensed source snapshot from the earlier NinjaPaws dojo. Its affected and
target-CVE-remediated modes run in a separate private App Service, never in
front of WebGoat or the admin portal. Do not give it portal credentials or
evidence/Defender-write roles. A package pin, configured dashboard badge or
startup snapshot is not proof of exploitation or a Defender finding.

Use a dedicated Azure training subscription and narrowly scoped identities. The
WebGoat website accepts public HTTPS connections by default for this demo; it
is not a hardened internet service. Deployment configuration can instead select
admin-IP-only or private access for WebGoat and Key Vault. Vault public-access
policy tags are optional, resource-scoped and omitted for private-only vaults;
they never grant permission to read secrets. Use disposable lesson accounts and synthetic
data, never the portal admin credential, and remove the lab after training.
Keep the portal restricted to the approved admin IP, the optional NGINX workload
private, and SCM/FTP publishing blocked. Retain WebGoat's private endpoint,
Internet-denied outbound subnet and pull-only identity. Validate network access,
egress, identity isolation, Key Vault references and credential rotation on a
disposable target before a workshop. Local tests are not a security certification
or proof of live protection.

## Reporting

For an unintended vulnerability in the portal or tooling, use the repository's
private GitHub vulnerability-reporting feature if enabled. If unavailable, request
a private contact channel without publishing exploit details or sensitive data.
Do not post credentials, private keys, tokens, tenant/subscription identifiers,
security exports or exploitable access details in public issues or pull requests.

Include the affected commit, a minimal reproduction with synthetic data, expected
and observed behavior, and impact. Test only your own authorized environment.
There is no promised response SLA or supported production release.

## Credentials and Evidence

- Generate application credentials through the Key Vault workflow. Never use
  upstream sample passwords or key material for real access.
- Keep the portal's `admin-username` and `admin-password` together in Key Vault.
  The session signing key is separate; managed identities and individual WebGoat
  lesson accounts do not receive fabricated shared username/password entries.
- Keep local configuration, environment files, Azure/SSH state, credential files,
  scan exports, release receipts and reports out of Git and container build contexts.
- Review staged files as well as ignore rules. Run `npm run check:public`, a dedicated
  secret/history scanner and dependency checks before publishing.
- The publication guard scans the working tree, not remote history or archive
  contents. Its upstream PEM-formatting exception requires the reviewed path and
  exact hash; new matches require review, not blanket exclusions.
- Treat reports and audit records as sensitive operational data. They may contain
  resource identifiers, findings and request timings. Redact before external sharing.
- If a credential was exposed, revoke or rotate it first, invalidate affected
  sessions, investigate its use, then coordinate removal from Git history and
  published artifacts. Deleting a file alone does not revoke access.

## Intentional Training Content

The pinned WebGoat source and third-party notices are retained unchanged. Its
known vulnerabilities and fixtures are not evidence of a compromised live account.
Do not silently remove lesson code or suppress all upstream findings. Changes to
the source snapshot require an explicit reviewed pin/import and updated provenance.

CI has no Azure deployment credentials. It records intentional workload findings
but gates HIGH/CRITICAL findings in the control-portal image. Deployment and paid
Defender changes require separate operator approval. No detection, prevention,
compliance outcome or risk reduction is guaranteed by this project.

Drowsy Dragon's optional CI scan uses DHI registry secrets only on explicit
manual dispatch. Never forward those credentials into an image or Azure runtime;
Azure pulls from the lab ACR using managed identity. Keep its raw scanner
receipts private, verify digest/hash bindings, and treat missing evidence as
unknown. Disabling the option does not stop a previously deployed instance or
its charges; use the approved resource-group removal workflow.

The NGINX collector accepts only the exact lab App Service hostname and fixed
evidence path, refuses redirects, limits the JSON response to 64 KiB and rejects
missing raw startup measurements. The legacy application's configuration
fallbacks are not accepted as runtime proof. Source and scan tampering, access
failures and missing evidence remain explicit failures or unknown checks.
Its plan may incur charges before its site is deployed; disabling the flag is
not deletion. Export evidence and review the complete owned group inventory.
