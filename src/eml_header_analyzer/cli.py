"""Command-line interface for eml-header-analyzer."""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys

from .parser import parse_eml, HeaderReport


def _report_to_dict(report: HeaderReport) -> dict:
    return dataclasses.asdict(report)


def _print_human(report: HeaderReport) -> None:
    print(f"Message-ID:   {report.message_id}")
    print(f"Date:         {report.date}")
    print(f"From:         {report.from_addr}")
    print(f"To:           {', '.join(report.to_addrs)}")
    print(f"Subject:      {report.subject}")
    if report.originating_ip:
        print(f"X-Origin-IP:  {report.originating_ip}")
    if report.mailer:
        print(f"Mailer:       {report.mailer}")
    print()
    print("Authentication-Results:")
    print(f"  SPF:   {report.spf or '(none)'}")
    print(f"  DKIM:  {report.dkim or '(none)'}")
    print(f"  DMARC: {report.dmarc or '(none)'}")
    print()
    print(f"Received chain ({len(report.hops)} hops, top -> bottom):")
    for i, hop in enumerate(report.hops, 1):
        print(f"  {i:2d}. from={hop.from_host or '?'} by={hop.by_host or '?'} "
              f"with={hop.with_protocol or '?'} at={hop.timestamp or '?'}")
    if report.warnings:
        print()
        print("Warnings:")
        for w in report.warnings:
            print(f"  - {w}")


def _print_chain(report: HeaderReport) -> None:
    for i, hop in enumerate(reversed(report.hops), 1):
        print(f"{i:2d}. from={hop.from_host or '?'} by={hop.by_host or '?'} "
              f"with={hop.with_protocol or '?'} at={hop.timestamp or '?'}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="eml-header-analyzer",
        description="Parse an EML file and report key header fields.",
    )
    parser.add_argument("path", help="Path to the .eml file to analyze")
    out = parser.add_mutually_exclusive_group()
    out.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output")
    out.add_argument("--chain", action="store_true", help="Print only the Received chain, oldest first")
    args = parser.parse_args(argv)

    try:
        report = parse_eml(args.path)
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    except OSError as e:
        print(f"error: could not read file: {e}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(_report_to_dict(report), indent=2, default=str))
    elif args.chain:
        _print_chain(report)
    else:
        _print_human(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
