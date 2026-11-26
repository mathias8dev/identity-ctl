# Changelog

Notable changes are reviewed per release. Versions follow Semantic Versioning.

## [Unreleased]

## [0.2.0] - 2026-11-26

### Added

- Add `identityctl api METHOD /PATH` for all server-authorized Identity HTTP actions with automatic session refresh.
- Support JSON/raw input, custom API headers and private streamed output for one-time credentials.
- Request the existing user-security administration scope on new login; Identity still enforces live permissions.
- Apply the shared develop/master release flow and verify native artifacts on all six platforms.
