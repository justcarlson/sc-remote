# Security

## Supported versions

Security fixes are made on the current `main` branch.

## Report a vulnerability

Use GitHub's private vulnerability reporting for the repository. Do not open a
public issue containing credentials, private endpoints, or fleet data.

## Credential boundary

`sc-remote` intentionally does not manage SSH private keys, passwords, access
tokens, or Git credentials. Configure those with OpenSSH, `ssh-agent`, your Git
credential helper, or a dedicated secret manager.

The synchronized `fleet.json` contains routing metadata. Store it in a private
backend unless every hostname, username, role, and endpoint is safe to publish.
