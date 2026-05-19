"""Parse an EML message and extract a structured header report."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from email import message_from_binary_file, policy
from email.message import EmailMessage
from email.utils import parsedate_to_datetime
from typing import List, Optional


RECEIVED_FROM_RE = re.compile(r"from\s+([^\s;]+)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"by\s+([^\s;]+)", re.IGNORECASE)
RECEIVED_WITH_RE = re.compile(r"with\s+([A-Za-z0-9]+)", re.IGNORECASE)


@dataclass
class Hop:
    raw: str
    from_host: str = ""
    by_host: str = ""
    with_protocol: str = ""
    timestamp: object = None


@dataclass
class HeaderReport:
    message_id: str = ""
    date: str = ""
    from_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    originating_ip: str = ""
    mailer: str = ""
    hops: list = field(default_factory=list)
    warnings: list = field(default_factory=list)


def _split_received(raw):
    hop = Hop(raw=raw)
    m = RECEIVED_FROM_RE.search(raw)
    if m:
        hop.from_host = m.group(1)
    m = RECEIVED_BY_RE.search(raw)
    if m:
        hop.by_host = m.group(1)
    m = RECEIVED_WITH_RE.search(raw)
    if m:
        hop.with_protocol = m.group(1)
    if ";" in raw:
        ts = raw.rsplit(";", 1)[1].strip()
        try:
            dt = parsedate_to_datetime(ts)
            hop.timestamp = dt.isoformat() if dt else ts
        except (TypeError, ValueError):
            hop.timestamp = ts
    return hop


def _parse_auth_results(value):
    spf = dkim = dmarc = ""
    for token in value.split(";"):
        token = token.strip()
        low = token.lower()
        if low.startswith("spf="):
            spf = token
        elif low.startswith("dkim="):
            dkim = token
        elif low.startswith("dmarc="):
            dmarc = token
    return spf, dkim, dmarc


def parse_eml(path):
    with open(path, "rb") as f:
        msg = message_from_binary_file(f, policy=policy.default)
    report = HeaderReport(
        message_id=msg.get("Message-ID", ""),
        date=msg.get("Date", ""),
        from_addr=msg.get("From", ""),
        to_addrs=[a.strip() for a in msg.get("To", "").split(",") if a.strip()],
        subject=msg.get("Subject", ""),
        originating_ip=msg.get("X-Originating-IP", ""),
        mailer=msg.get("X-Mailer", msg.get("User-Agent", "")),
    )
    auth = msg.get("Authentication-Results", "")
    if auth:
        report.spf, report.dkim, report.dmarc = _parse_auth_results(auth)
    for received in msg.get_all("Received", []):
        report.hops.append(_split_received(received))
    _check_warnings(report)
    return report


def _check_warnings(report):
    if not report.spf and not report.dkim and not report.dmarc:
        report.warnings.append("No Authentication-Results header found.")
    timestamps = [h.timestamp for h in report.hops if h.timestamp]
    if len(timestamps) >= 2 and timestamps != sorted(timestamps, reverse=True):
        report.warnings.append(
            "Received timestamps are not monotonically decreasing (top to bottom)."
        )
