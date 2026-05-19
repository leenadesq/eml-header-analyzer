# eml-header-analyzer

A small Python command-line tool that parses an EML message and prints a structured report of its headers: the Received chain, authentication results (SPF, DKIM, DMARC), originating IP, and core envelope fields.

Useful for triaging suspicious mail, building forensic notes, or feeding header data into larger analysis pipelines.

Status: early development. Output format may change between minor versions.

## Why

Most mail clients hide or truncate headers. Most online "header analyzer" web pages require pasting message content into a third-party service, which is not acceptable for sensitive material. This tool runs locally, uses only the Python standard library, and emits both a human-readable report and a JSON document for further processing.

## Install

Requires Python 3.10 or newer.

```
git clone https://github.com/leenadesq/eml-header-analyzer.git
cd eml-header-analyzer
pip install -e .
```

## Usage

```
eml-header-analyzer path/to/message.eml
eml-header-analyzer --json path/to/message.eml
eml-header-analyzer --chain path/to/message.eml
```

The `--chain` option prints only the Received chain in bottom-up order. The `--json` option emits the full report as JSON.

## What it reports

For each EML file the tool extracts the Message-ID, Date, From, To, and Subject; the full Received chain with each hop's `from`, `by`, protocol, and timestamp parsed out where possible; Authentication-Results split into SPF, DKIM, and DMARC verdicts; X-Originating-IP and X-Mailer when present; and a summary block flagging non-monotonic timestamps and missing authentication.

## Roadmap

v0.1 ships the standard-library parser with human and JSON output. v0.2 adds the `--chain` flag with timestamp gap detection. v0.3 adds optional DNS lookup (PTR, ASN) for the originating IP. v0.4 introduces batch mode for a directory of EML files.

## License

MIT. See `LICENSE`.

## Related

This tool is part of a wider set of email forensics references maintained at [leenadesq/email-forensics-notes](https://github.com/leenadesq/email-forensics-notes).
