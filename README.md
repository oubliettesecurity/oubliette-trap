# Oubliette

AI Agent Deception Platform -- honeypots, fingerprinting, and intelligence for autonomous AI threats.

Shield defends. Dungeon attacks. **Oubliette traps.**

## What It Does

Oubliette deploys realistic honeypot MCP servers that attract, contain, fingerprint, and extract intelligence from AI agents. Unlike static honeypots, Oubliette generates **interconnected fake environments** where every response references shared state -- making the deception resistant to fingerprinting by sophisticated agents.

- **Deception Layer** -- 15+ honey tools per profile forming coherent fake infrastructure
- **Fingerprinting Engine** -- passive behavioral analysis + active probes classify agents as LLM, script, human, or compromised
- **Intelligence Layer** -- events persisted to SQLite, exportable as STIX 2.1, CEF, or JSON

## Quick Start

```bash
pip install oubliette-trap

# Start honeypot (stdio transport for Claude Code)
oubliette serve

# Network-accessible honeypot
oubliette serve --transport sse --port 8080

# With active fingerprinting probes
oubliette serve --profile default --active-probes

# Export collected intelligence
oubliette export --format stix --output agents.json
oubliette export --format cef --output events.log
```

### With Claude Code

Add to your MCP config:
```json
{
  "mcpServers": {
    "oubliette": {
      "command": "oubliette",
      "args": ["serve"]
    }
  }
}
```

## How It Works

1. Agent discovers the honeypot via MCP server listing
2. Agent calls honey tools (list_services, get_credentials, etc.)
3. Responses form a coherent fake environment with planted breadcrumbs
4. Fingerprinting engine classifies the agent type from behavioral signals
5. Optional active probes (instruction traps, canary tokens) confirm LLM agents
6. All interactions persisted and exportable as threat intelligence

## Built By

[Oubliette Security](https://oubliettesecurity.com) -- AI security, cyber deception, and red teaming for defense applications.

## License

Apache 2.0
