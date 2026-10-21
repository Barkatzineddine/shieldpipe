# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security tab → Report a vulnerability** on this repository.

Do not open a public issue for security problems. You will get an acknowledgement within
5 working days, and a fix or mitigation plan once the report is confirmed.

## Supported versions

Only the latest image published from `main` is supported. Verify any image before running it:

```bash
cosign verify ghcr.io/barkatzineddine/shieldpipe@<digest> \
  --certificate-identity https://github.com/Barkatzineddine/shieldpipe/.github/workflows/devsecops.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
