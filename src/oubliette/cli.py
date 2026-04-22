"""Oubliette CLI -- serve honeypots and export intelligence."""

from __future__ import annotations

import argparse
import json
import logging
import sys

from oubliette.intel.export import export_cef, export_json, export_stix
from oubliette.server import OublietteTrap, create_mcp_server


def main():
    parser = argparse.ArgumentParser(prog="oubliette", description="Oubliette -- AI Agent Deception Platform")
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start the honeypot MCP server")
    serve_p.add_argument("--transport", choices=["stdio", "sse"], default="stdio")
    serve_p.add_argument("--port", type=int, default=8080)
    serve_p.add_argument("--profile", default="default", help="Deception profile name")
    serve_p.add_argument("--active-probes", action="store_true", help="Enable active fingerprinting probes")
    serve_p.add_argument("--storage-dir", default="data", help="Storage directory for SQLite")
    serve_p.add_argument("--log-level", default="INFO")

    export_p = sub.add_parser("export", help="Export collected intelligence")
    export_p.add_argument("--format", choices=["stix", "cef", "json"], required=True)
    export_p.add_argument("--output", default="-", help="Output file (- for stdout)")
    export_p.add_argument("--storage-dir", default="data")

    args = parser.parse_args()

    if args.command == "serve":
        _serve(args)
    elif args.command == "export":
        _export(args)
    else:
        parser.print_help()


def _serve(args):
    logging.basicConfig(level=getattr(logging, args.log_level.upper(), logging.INFO), format="%(levelname)s %(name)s: %(message)s")
    log = logging.getLogger("oubliette")

    trap = OublietteTrap(profile_name=args.profile, storage_dir=args.storage_dir, active_probes=args.active_probes)
    log.info("Oubliette starting -- profile=%s, transport=%s, active_probes=%s", args.profile, args.transport, args.active_probes)
    log.info("Honey tools: %s", ", ".join(trap.profile.get_tool_names()))

    mcp = create_mcp_server(trap)
    if args.transport == "sse":
        mcp.run(transport="sse", port=args.port)
    else:
        mcp.run()


def _export(args):
    from oubliette.intel.events import EventStore
    from oubliette.models import AgentClassification, AgentType, TrapEvent

    store = EventStore(db_path=f"{args.storage_dir}/oubliette.db")
    raw_events = store.get_all(limit=10000)

    if not raw_events:
        print("No events to export.", file=sys.stderr)
        return

    events = []
    for d in raw_events:
        fp = d.get("fingerprint", {})
        events.append(TrapEvent(
            event_id=d["event_id"], timestamp=d["timestamp"],
            session_id=d["session_id"], source_ip=d["source_ip"],
            tool_name=d["tool_name"], arguments=d["arguments"],
            response_sent=d["response_sent"], deception_profile=d["deception_profile"],
            fingerprint=AgentClassification(
                agent_type=AgentType(fp.get("agent_type", "unknown")),
                confidence=fp.get("confidence", 0.0),
            ),
            breadcrumbs_followed=d.get("breadcrumbs_followed", []),
            probes_triggered=d.get("probes_triggered", []),
        ))

    if args.format == "stix":
        output = json.dumps(export_stix(events, []), indent=2)
    elif args.format == "cef":
        output = "\n".join(export_cef(events))
    else:
        output = export_json(events, [])

    if args.output == "-":
        print(output)
    else:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"Exported {len(events)} events to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
