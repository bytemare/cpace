# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

For releases prior to this changelog, see [GitHub Releases](https://github.com/bytemare/hash/releases).

## [Unreleased]

## v0.6.2 - 08/04/2026

### Removed
- Removed community files and reuse the central ones from the bytemare/.github repository.

## v0.6.1 - 19/03/2026

### Changed
- Updated dependencies.
- Fixed HMAC key length validation to check against the block size instead of the output size.

### Documentation
- Replaced documentation templates with repository-specific architecture and security model guidance.
- Consolidated security and architecture guidance into `docs/security_model.md` and `docs/architecture_and_guidelines.md`.
- Removed `docs/design_and_security.md` and updated cross-references to canonical docs.
- Fixed broken or stale internal and repository links across docs.
- Added a documentation remediation plan in [docs/documentation_remediation_plan.md](docs/documentation_remediation_plan.md).

## v0.6.0 - 27/01/2026

### Releasing
- SLSA Level 3 provenance generation integrated into release workflow.

### Documentation Updates
- Added governance and releasing documents to docs/
- Upgraded Code of Conduct to Contributor Covenant 3.0.
