# Changelog

All notable changes to `eml-header-analyzer` are documented in this file.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `--json` output mode (tracking in #1).
- ARC-Authentication-Results / ARC-Seal chain parsing (tracking in #2).

## [0.1.0] - unreleased

First working version. No tagged release yet; this entry describes the state of `main`.

### Added

- Parse an `.eml` file and emit a human-readable summary covering From/To/Subject/Date, Message-ID, the Received chain, and Authentication-Results (SPF/DKIM/DMARC).
- `eml-header-analyzer <file>` CLI entry point.
- Public package layout `src/eml_header_analyzer`.
- Pytest suite driven by a synthetic `.eml` fixture.
- GitHub Actions CI against Python 3.10, 3.11, and 3.12.
- `SECURITY.md` with private disclosure instructions.

### Non-goals

- Cryptographic verification of DKIM/ARC signatures. This tool reports what the headers say; it does not re-verify them.
- Any network activity (DNE/Skip remote image fetches, DNS lookups, or anything else during parsing).

[Unreleased]: https://github.com/leenadesq/eml-header-analyzer/commits/main
[0.1.0]: https://github.com/leenadesq/eml-header-analyzer

