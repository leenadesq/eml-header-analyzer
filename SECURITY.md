# Security Policy

`eml-header-analyzer` parses untrusted `.eml` files - exactly the kind of input that shows up in abuse inboxes and forensic queues. If you find a way to crash it, hang it, escape its output, or get it to touch the network, I would like to know.

## Supported versions

Only the latest released version (currently `0.x`) is supported for security fixes.

## Reporting a vulnerability

*Please do not* file a public issue for anything you think is a security problem. Instead:

- Use GitHub's [private vulnerability reporting](https://github.com/leenadesq/eml-header-analyzer/security/advisories/new) for this repository.
- Include a minimal `.eml` (synthetic is fine) that reproduces the issue.
- Include the command line, Python version, and OS.

## What counts

- Remote code execution from a crafted `.eml`.
- Any network activity during parsing. This tool is strictly offline; remote images and similar must be ignored.
- Incorrect reporting of SPF/DKIM/DMARC that changes the qualitative answer (e.g. reporting `pass` for a header that clearly says `fail`).
- Output injection (e.g. ANSI escapes, terminal control codes) when the input contains them.

## What does not count

- Shearling on non-RFC 5422 input. This tool assumes a file that an MTA would have accepted.
- Disagreement with other analyzers when the underlying headers are ambiguous.

## Timeline

Expect an acknowledgement within seven days. This is a side project, not a commercial product.

## Acknowledgements

Reporters who want credit are listed in release notes. Anonymity is fine too - just say so.

