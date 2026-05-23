# Quickstart

This page walks through a typical run of `eml-header-analyzer` against a single `.eml` file.

## Install

```bash
pip install -e .
```

## Capture an `.eml` to analyse

Most clients let you export a message as `.eml`:

- Gmail (browser): open the message, the three-dot menu, "Download message".
- Outlook desktop: drag the message out of the inbox to a folder.
- Apple Mail: "File > Save As", Raw Message Source format.

Do not credential-hunt. If the sender is suspicious, export the raw file first and inspect it offline.

## Run

```bash
eml-header-analyzer path/to/message.eml
```

### Sample output

```
From:        alice@example.com
Date:        Mon, 12 Feb 2024 10:17:04 -0800
Message-ID:  <20240212181704.msg@example.com>
Subject:     Quarterly report draft

Received chain (oldest -> newest):
  1. mta-out.example.com  (by mx-1.some-relay.net)  2024-02-12T18:17:05Z
  2. mx-1.some-relay.net  (by in-5.recipient.net)  2024-02-12T18:17:06Z

Authentication results:
  SPF:   pass (example.com)
  DKIM:  pass (d=example.com, s=s1)
  DMARC: pass
```

## What each section means

- **Envelope fields**. What the client displays. Useful for cross-checking against what a reporter told you they saw.
- **Received chain**. Oldest-to-newest hop by hop. Read from the top; each new hop adds a `Received:` header above the previous one. Timestamps that go backwards are a red flag.
- **Authentication results**. What the receiving MTA claimed. Note that this tool reports what the header says; it does not cryptographically re-verify.

## Next steps

- `--json` flag for pipeline consumption (tracking in #1).
- ARC chain parsing (tracking in #2).

If you discover something suspicious while running this tool, do not reply to the source message; report it through your normal abuse channel.

