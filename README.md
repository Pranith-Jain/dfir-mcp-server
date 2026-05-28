# DFIR & Threat Intelligence MCP Server

MCP (Model Context Protocol) server exposing 20 DFIR and threat intelligence tools for AI agents. Built on Cloudflare Workers with Durable Objects.

## Tools

| Tool | Description |
|------|-------------|
| `check_ioc` | IP/domain/URL/hash reputation (30+ providers) |
| `lookup_cve` | CVE details + CVSS + EPSS + KEV |
| `search_cve` | Search CVEs by keyword |
| `enrich_actor` | Threat actor profile + TTPs + campaigns |
| `search_malpedia` | Malpedia malware family/actor search |
| `lookup_domain` | DNS, RDAP, CT logs, SPF/DKIM/DMARC |
| `lookup_asn` | ASN registration, netblocks, BGP peers |
| `search_triage` | Recorded Future Triage sandbox search |
| `get_today_briefing` | Today's threat intel briefing |
| `list_briefings` | Recent daily/weekly briefings |
| `get_live_iocs` | Real-time IOC feed (20+ sources) |
| `get_ransomware_activity` | Recent ransomware victims + leak posts |
| `analyze_phishing_email` | Raw email → header/auth/URL risk analysis |
| `unified_search` | Cross-source keyword search |
| `get_detections` | Sigma/YARA/Snort detection rules |
| `get_threat_pulse` | Global threat overview |
| `correlate_iocs` | IOC relationship graph search |
| `check_breach` | Email/domain breach exposure check |
| `get_feed_status` | Feed health + freshness status |
| `lookup_mitre` | MITRE ATT&CK technique lookup |
| `get_relationships` | IOC → actor/malware/campaign graph |

## Quick Start

### 1. Install dependencies

```bash
npm install
```

### 2. Deploy to Cloudflare Workers

```bash
npx wrangler deploy
```

### 3. Connect your MCP client

**Claude Desktop** (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dfir-threatintel": {
      "url": "https://dfir-mcp-server.<your-subdomain>.workers.dev/mcp"
    }
  }
}
```

**Cursor** (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "dfir-threatintel": {
      "url": "https://dfir-mcp-server.<your-subdomain>.workers.dev/mcp"
    }
  }
}
```

## Transports

| Transport | Path | Use |
|-----------|------|-----|
| Streamable HTTP | `/mcp` | Recommended for modern clients |
| SSE | `/sse` | Legacy clients |
| Health | `/` | Server info + tool count |

## Architecture

```
┌─────────────────────────────────────┐
│  Cloudflare Worker                  │
│                                     │
│  DfirMcpServer (Durable Object)     │
│  ├── MCP Protocol Handler           │
│  ├── 20 Tool Definitions            │
│  └── API Proxy → pranithjain.qzz.io │
└─────────────────────────────────────┘
        ▲
        │ Streamable HTTP / SSE
        ▼
┌─────────────┐  ┌─────────────┐
│ Claude Code │  │ Cursor      │
│ Desktop     │  │ IDE         │
└─────────────┘  └─────────────┘
```

The MCP server proxies requests to the [DFIR Toolkit API](https://pranithjain.qzz.io/dfir) — no API keys required for read-only tools.

## Development

```bash
# Local development
npm run dev

# Type check
npm run typecheck

# Deploy
npm run deploy
```

## License

MIT
