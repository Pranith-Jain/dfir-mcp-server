# DFIR & Threat Intelligence MCP Server

MCP (Model Context Protocol) server exposing 98 DFIR and threat intelligence tools for AI agents. Built on Cloudflare Workers with Durable Objects.

## Tools

### IOC & Threat Intelligence
| Tool | Description |
|------|-------------|
| `check_ioc` | IP/domain/URL/hash reputation (30+ providers) |
| `get_live_iocs` | Real-time IOC feed (12+ sources) |
| `get_trending_iocs` | Most active IOCs in last 24h |
| `get_ioc_lifecycle` | IOC first-seen/last-seen/trend/decay |
| `correlate_iocs` | IOC relationship graph search |
| `ioc_watchlist_add` | Add IOC to proactive alert watchlist |
| `ioc_watchlist_list` | List watched IOCs |
| `ioc_watchlist_alerts` | Recent watchlist alerts |
| `ioc_watchlist_stats` | Watchlist dashboard stats |

### CVE Intelligence
| Tool | Description |
|------|-------------|
| `lookup_cve` | CVE details + CVSS + EPSS + KEV |
| `poc_scan` | GitHub exploit/PoC search for CVEs |
| `cve_poc_map` | CVE-to-GitHub-repo mapping cache |
| `cve_health` | CVE data pipeline health check |
| `soc_cve_report` | SOC CVE intelligence report generator |

### Threat Actors & Malware
| Tool | Description |
|------|-------------|
| `enrich_actor` | Threat actor profile + TTPs + campaigns |
| `search_malpedia` | Malpedia malware/actor search |
| `search_malware` | Malware family search |
| `search_triage` | Recorded Future Triage sandbox search |

### Domain & Infrastructure
| Tool | Description |
|------|-------------|
| `lookup_domain` | DNS, RDAP, CT logs, SPF/DKIM/DMARC |
| `lookup_asn` | ASN registration, netblocks, BGP peers |
| `lookup_ip_geo` | IP geolocation + VPN/proxy/tor detection |
| `get_domain_history` | WHOIS history + ownership changes |
| `pivot_domain` | Pivot by registrant attributes |
| `search_registrant` | Find domains by email/org |
| `get_domain_certs` | Certificate Transparency logs |
| `watch_domain_ct` | CT monitoring with alerts |
| `passive_dns_query` | Historical DNS resolutions |
| `passive_dns_reverse` | Reverse passive DNS lookup |
| `passive_dns_overlap` | Infrastructure overlap detection |

### Phishing & Web
| Tool | Description |
|------|-------------|
| `analyze_phishing_email` | Raw email → header/auth/URL risk analysis |
| `analyze_phishing_url` | URL phishing analysis |
| `scan_website` | Security headers + SSL + tech detection |
| `google_dorks` | Google dork query generation |

### Briefings & News
| Tool | Description |
|------|-------------|
| `get_today_briefing` | Today's threat intel briefing |
| `list_briefings` | Recent daily/weekly briefings |
| `get_ransomware_activity` | Recent ransomware victims + leak posts |
| `get_supply_chain_attacks` | Supply-chain compromise incidents |
| `get_cert_in_advisories` | CERT-In vulnerability advisories |
| `get_detections` | Sigma/YARA/Snort detection rules |
| `get_threat_pulse` | Global threat overview |
| `cyber_news` | Cybersecurity RSS news aggregator |

### Report Analysis
| Tool | Description |
|------|-------------|
| `parse_threat_report` | Extract IOCs/actors/TTPs from reports |
| `analyze_report` | Unified report analyzer (IOC + TTP + CVE + OCR) |
| `extract_ttps` | MITRE ATT&CK technique extraction |
| `extract_fivew` | 5W grid (who/what/when/where/why) |
| `extract_iocs_from_image` | OCR image for embedded IOCs |
| `get_cross_report_graph` | Cross-report knowledge graph |

### Detection & MITRE
| Tool | Description |
|------|-------------|
| `lookup_mitre` | MITRE ATT&CK technique lookup |
| `generate_yara_rule` | AI YARA rule generation |
| `validate_yara_rule` | YARA syntax validation |

### Crypto & Breach
| Tool | Description |
|------|-------------|
| `trace_crypto_address` | Cryptocurrency wallet tracing |
| `check_breach` | Email/domain breach exposure check |
| `get_blocklists` | Firewall blocklists (pfSense/iptables/Suricata) |

### Investigation Tools
| Tool | Description |
|------|-------------|
| `notebook_list` | List investigation notebooks |
| `notebook_create` | Create investigation notebook |
| `notebook_get` | Get notebook with entries |
| `notebook_add_entry` | Add note/IOC/finding/timeline |
| `notebook_update` | Update notebook metadata |
| `notebook_delete` | Delete notebook |
| `ws_list` | List AEAD workspaces |
| `ws_create` | Create investigation workspace |
| `ws_get` | Get workspace with subjects/connections |
| `ws_add_subject` | Register entity in workspace |
| `ws_add_connection` | Define entity relationships |
| `ws_add_finding` | Log findings with trust scores |
| `ws_exposure` | Calculate composite exposure score |
| `ws_export_stix` | Export as STIX 2.1 bundle |
| `ws_render_graph` | ASCII graph/timeline/risk heatmap |
| `ws_workflow_advance` | Advance AEAD phase |
| `ws_workflow_summary` | Workspace phase summary |

### Telegram Intelligence
| Tool | Description |
|------|-------------|
| `tg_boolean_search` | Boolean Telegram leak search |
| `tg_timeline` | Telegram message volume timeline |
| `tg_saved_searches_list` | List saved searches |
| `tg_saved_search_create` | Save search query |
| `tg_saved_search_delete` | Delete saved search |

### HudsonRock (Infostealer)
| Tool | Description |
|------|-------------|
| `hr_search_email` | Search by email |
| `hr_search_domain` | Domain compromise search |
| `hr_domain_overview` | Domain compromise stats |
| `hr_assets_discovery` | Compromised URL discovery |
| `hr_third_party_risk` | Supply-chain risk assessment |
| `hr_infection_analysis` | Stealer infection source analysis |
| `hr_search_username` | Search by username |
| `hr_search_ip` | Search by IP/CIDR |
| `hr_account` | API account status check |

### Report Analysis (Advanced)
| Tool | Description |
|------|-------------|
| `extract_ttps` | MITRE ATT&CK technique extraction |
| `extract_fivew` | 5W context extraction |
| `extract_iocs_from_image` | Image OCR for IOCs |
| `analyze_report` | Unified report analyzer |
| `get_cross_report_graph` | Cross-report knowledge graph |

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
│  ├── 98 Tool Definitions            │
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

## Authentication

Some tools require an API key. Provide it via:
- `Authorization: Bearer <key>` header
- `X-API-Key: <key>` header

Get an API key at [pranithjain.qzz.io](https://pranithjain.qzz.io).

## License

MIT
