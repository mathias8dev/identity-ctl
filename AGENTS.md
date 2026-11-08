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
  targets on matching runners. Publish from main only after every artifact passes;
  tags and published release assets are immutable.
- Run pnpm check, pnpm package and pnpm test:packaged. Review the complete public
  file inventory before publication. Never claim platform coverage from a cross
  compilation or local source-only test.
- Use Conventional Commits with a descriptive body. Commit, push and release only
  when authorized; never stage unrelated work.
