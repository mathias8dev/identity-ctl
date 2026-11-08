# identity-ctl

`identityctl` is the standalone command-line client for the Identity Management API.
It signs in a human operator through the control tenant's browser/OAuth flow and
performs tenant-scoped user import/export operations using live IdP permissions.

## Install

Download your platform archive from [GitHub Releases](https://github.com/mathias8dev/identity-ctl/releases)
and verify its SHA-256 using the release's `SHA256SUMS`. No Node.js, npm, pnpm,
Bash, curl or jq installation is needed to run the executable.

| Platform | Architectures | Archive |
| --- | --- | --- |
| Linux, glibc 2.28+ | x64, ARM64 | `.tar.gz` |
| macOS 13.5+ | Intel x64, Apple Silicon ARM64 | `.tar.gz` |
| Windows 10+/Windows 11 ARM64 | x64, ARM64 | `.zip` |

Alpine/musl is not supported. macOS executables are ad-hoc signed, not notarized;
Windows executables are unsigned. Archives also contain licenses and `BUILD.json`
with the exact version, source revision, target and embedded runtime version.

The release includes installers that verify the archive before replacing a binary:

```sh
# Download install.sh from the chosen release and inspect it, then:
sh install.sh 0.1.0
identityctl --version
```

Linux/macOS installation defaults to `~/.local/bin`; set `IDENTITYCTL_BIN_DIR` to
choose another directory. On Windows, download the release's `install.ps1`, inspect
it and run `.\install.ps1 -Version 0.1.0`. It installs under
`%LOCALAPPDATA%\Programs\identity-ctl` and updates the user's PATH.

## Authentication

```sh
identityctl login --issuer https://auth.identity.example.com
identityctl status
identityctl logout
```

Select the **control tenant's issuer**, not an application tenant. Identity must
register a public native `identityctl` client, explicit consent, the callback
`http://127.0.0.1/oauth2/callback` with a dynamic loopback port, and these scopes:
`offline_access identity.admin.read identity.admin.manage identity.admin.users.manage identity.admin.users.import identity.admin.users.export`.
The server's administration bootstrap normally creates that client when absent.
The operator must hold the required live directory permissions: client scopes
never bypass server authorization or tenant isolation.

Login uses Authorization Code with S256 PKCE, a cryptographically random state,
and a listener bound only to `127.0.0.1`. The callback must match the exact host,
path, state and issuer and contain one authorization code. Browser authentication,
MFA and consent stay on Identity. The CLI never collects an operator password.

The default session is
`${XDG_CONFIG_HOME:-$HOME/.config}/lookandtry/identityctl/session.json`, compatible
with the former Bash client's schema. On POSIX, its directory must belong to you
and be `0700`, with an owner-only `0600` file. Symlinks are rejected. Windows uses
the account-private home directory; POSIX mode/owner checks do not apply there.
Select a separate `IDENTITYCTL_SESSION_FILE` per environment.

The session is pinned to issuer, API origin and client. Commands serialize session
access with a private `.lock` file, refresh tokens at most 60 seconds before expiry,
and persist the rotated token atomically **before** calling the Management API.
Writes and OAuth exchanges are never automatically retried. A crashed process may
leave a lock: check its recorded PID and stop any owner before manually removing
that `.lock` file. Do not delete a lock held by another live command.

`status` prints metadata, never tokens. `token` intentionally prints only the current
access token for an explicitly selected automation process; avoid displaying it in
a terminal or logs. Logout revokes the refresh token before removing the session.
Remote failure keeps the local session so revocation can be retried.

```sh
export IDENTITYCTL_ISSUER=https://auth.identity.example.com
export IDENTITYCTL_SESSION_FILE="$HOME/.config/lookandtry/identityctl/staging.json"
identityctl login --no-browser
identityctl status
```

The normal API origin equals the issuer. Set `IDENTITYCTL_API_URL` or login's
`--api-url` only for an explicitly trusted distinct administration origin.
Redirects never receive credentials. TLS verification remains enabled and includes
system CAs and `NODE_EXTRA_CA_CERTS`, so enrolled HTTPS `.local` gateways work.
Plain HTTP is accepted only for `localhost`, `127.0.0.1` and `::1` test services.

### Headless hosts

Forward a fixed loopback port from the workstation running the browser:

```sh
ssh -L 54321:127.0.0.1:54321 operator@host
# On the host:
identityctl login --issuer https://auth.identity.example.com --no-browser --callback-port 54321
```

Open the printed URL on the workstation. The callback traverses the tunnel to the
CLI. The default login timeout is 300 seconds; `--timeout` accepts 1–900 seconds.

## User imports and exports

```sh
identityctl users import TENANT_ID canonical-import.json
identityctl users imports TENANT_ID [PAGE]
identityctl users import-results TENANT_ID JOB_ID [PAGE]
identityctl users cancel-import TENANT_ID JOB_ID
identityctl users export TENANT_ID reconciliation-20261108
identityctl users exports TENANT_ID [PAGE]
identityctl users export-records TENANT_ID JOB_ID [PAGE]
identityctl users export-download TENANT_ID JOB_ID > identity-users.ndjson
identityctl users cancel-export TENANT_ID JOB_ID
```

Tenant/job IDs are UUIDs. Lists use server-side pages of 100 records, starting at
page zero; follow every page until `last: true`. Ordinary replies are bounded to
2 MiB. `export-download` streams NDJSON, without buffering the entire export.
Create private output files and check the exit code before consuming a download:
a transport error can leave partial stdout. HTTP calls have a 30-second timeout.

Imports must be regular non-symlink UTF-8 JSON files of 1–512 KiB, containing a
canonical envelope with 1–500 records. Raw product exports are not accepted:

```json
{
  "schemaVersion": 1,
  "source": "customer-directory",
  "mode": "VALIDATE_ONLY",
  "idempotencyKey": "customer-validation-20261108",
  "records": [{"externalId": "customer-42", "email": "user@example.com"}]
}
```

The server validates record fields and owns all identity rules and job state.
Inspect every validation result before submitting `CREATE_ONLY` with its own
intentional idempotency key. Consume the returned `externalId` to issuer/subject
mapping in the source application; matching email never links accounts. The CLI
does not access application databases, move business roles or perform cutover.
Imports may contain password/MFA material: keep them private and out of Git/logs.
Profile exports intentionally exclude credential material.

See [the backend-neutral migration workflow](docs/user-migration.md) for validation, creation, complete result pagination and authoritative account mappings.

## Non-interactive automation

Provide both `IDENTITY_ADMIN_API_URL` and `IDENTITY_ADMIN_ACCESS_TOKEN` through an
approved secret mechanism to use `users` commands without a stored session. The
CLI neither mints nor refreshes that externally supplied token and never puts it
in subprocess arguments. API authority remains the server's responsibility.

## Configuration

| Variable | Meaning |
| --- | --- |
| `IDENTITYCTL_ISSUER` | Control issuer; must match an existing session when supplied |
| `IDENTITYCTL_API_URL` | Trusted Management API origin; defaults to issuer |
| `IDENTITYCTL_CLIENT_ID` | Public native client ID, default `identityctl` |
| `IDENTITYCTL_SESSION_FILE` | Private session file location |
| `IDENTITYCTL_CALLBACK_PORT` | Fixed 1024–65535 loopback port; otherwise assigned by OS |
| `IDENTITYCTL_LOGIN_TIMEOUT` | Login timeout in seconds, default 300 |
| `IDENTITYCTL_NO_BROWSER` | `true` prints the authorization URL without opening it |
| `IDENTITY_ADMIN_API_URL` | Origin for external bearer-token automation |
| `IDENTITY_ADMIN_ACCESS_TOKEN` | External bearer for `users` commands |

CLI login options take precedence over their corresponding environment values.
Errors go to stderr and return a nonzero exit code. OAuth error bodies and input
credentials are never echoed in diagnostics.

## Develop and release

```sh
mise install
pnpm install --frozen-lockfile
pnpm check
pnpm package
pnpm test:packaged
```

TypeScript owns the client; Node 24.16.0 is pinned for compilation into a standalone
executable using Node SEA, esbuild and postject. The six-target matrix builds on
matching native GitHub-hosted OS/architecture runners and runs the same protocol
and session tests against the executable copied outside the checkout.

Manually dispatch **Build and release identityctl** from `main`. `publish: false`
validates native artifacts; `publish: true` publishes `v<package.json version>` only
after all six targets pass. Release validation checks platform, source revision,
runtime version and SHA-256. Publication is resumable for identical draft assets;
it refuses existing differing tags/assets and never overwrites a published release.
Bump the package version for a new immutable release. No npm publication is used.
