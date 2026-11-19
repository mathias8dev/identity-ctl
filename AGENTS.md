# Identity CLI

Use the mathias-engineering skill. This public repository owns the standalone
Identity Management API client. Never copy IdP/backend sources, Git history,
environment files, credentials or stored sessions here.

- Preserve Authorization Code/S256 PKCE, the exact control issuer and loopback
  callback checks. The public native client has no secret. The IdP remains the
  authority for live operator permissions, scopes, tenant isolation and jobs.
- Keep one canonical HTTP/session implementation for all commands. Never access
  application databases or infer account bindings from email.
- Sessions remain pinned to issuer, API origin and client. Serialize rotation,
  write the new session atomically before API use, and retain failed revocation
  state for retry. Do not automatically retry writes or refresh-token exchange.
- Reject symlinks and non-private POSIX sessions. Never log credentials or include
  them in process arguments. Keep system/extra CA trust and TLS verification;
  never forward authorization across redirects.
- Ship standalone executables with the pinned Node runtime, without npm publishing
  or runtime dependencies on a checkout, Node, curl, jq or Bash.
- package.json owns the version. Manual GitHub Actions builds and tests six native
  targets on matching runners. Publish from master only after every artifact passes;
  tags and published release assets are immutable.
- Run pnpm check, pnpm package and pnpm test:packaged. Review the complete public
  file inventory before publication. Never claim platform coverage from a cross
  compilation or local source-only test.
- Use Conventional Commits with a descriptive body. Commit, push and release only
  when authorized; never stage unrelated work.

<!-- mathias-release-flow:start -->
## Shared release conventions

- `develop` is the integration branch; `master` is the production/stable branch.
- Use Conventional Commits. Prepare `release/X.Y.Z` from the chosen develop HEAD
  or a specific commit in develop history. Include existing production fixes.
- The native version file(s) in `.release.json` are authoritative. Review the
  proposed SemVer version and `CHANGELOG.md` in the release MR. Breaking changes
  propose major, features minor, other changes patch; `--bump` is a human override.
- Merge the same approved release branch into master and develop with `--no-ff`.
  Retain it until both merges and successful delivery, then remove it.
- Delivery uses the exact approved version; never recalculate it after review.
  Application tags follow successful production readiness. Package tags authorize
  the existing publication pipeline only after its release checks; immutable
  published versions/tags must never be moved or replaced to retry a failure.
- Release preparation never commits, pushes, tags, publishes or deploys. These
  actions require the corresponding explicit user authorization. Keep CI launch,
  costly stages and production approval explicit.
- See `RELEASING.md` for the repository-owned command and verification steps.
<!-- mathias-release-flow:end -->
