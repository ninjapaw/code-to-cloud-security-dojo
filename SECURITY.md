# Security Policy

## Scope

This is experimental, intentionally vulnerable training software. It is not
production-ready and must not host real data or credentials. The imported WebGoat
workload contains known educational vulnerabilities; the control portal, lifecycle
tooling and deployment boundaries are not intended to be vulnerable.

Use a dedicated Azure training subscription and narrowly scoped identities. Keep
the workload private and the portal restricted to the approved admin IP. Validate
network access, egress, identity isolation, Key Vault references and credential
rotation on a disposable target before a workshop. Local tests are not a security
certification or proof of live protection.

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
