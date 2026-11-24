# Security Policy

## Supported scope

Security reports are welcome for vulnerabilities in the code maintained in this repository, especially the Tor Control Protocol client, SAFECOOKIE handling, parser IPC, input/output bounds, and fail-closed status handling.

## Reporting a vulnerability

Please do not publish exploit details or sensitive logs in a public issue. Contact the repository maintainer privately through the contact method listed on the maintainer's GitHub profile. Include the affected version or commit, operating system, reproduction steps, impact, and any relevant sanitized logs.

Do not include Tor cookie contents, credentials, private keys, or other secrets in a report.

## Deployment cautions

- Do not expose a Tor ControlPort to untrusted networks.
- Protect the SAFECOOKIE file with restrictive filesystem permissions.
- TCP ControlPort does not provide kernel peer-credential verification.
- M2 does not route all host traffic through Tor and is not a substitute for a separately verified proxy or routing configuration.
- Live daemon and native platform tests are required before production deployment.
