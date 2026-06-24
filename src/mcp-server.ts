import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import type { Connection, ConnectionContext } from 'agents';
import { z } from 'zod';

type Env = {
  KV_CACHE?: KVNamespace;
  BRIEFINGS_DB?: D1Database;
};

const API_BASE = 'https://pranithjain.qzz.io';

async function apiFetch<T>(path: string, apiKey?: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    accept: 'application/json',
    ...((init?.headers as Record<string, string>) ?? {}),
  };
  if (apiKey) {
    headers['authorization'] = `Bearer ${apiKey}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { ...init, headers });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${body.slice(0, 200)}`);
  }
  return res.json() as Promise<T>;
}

async function apiFetchSse(
  path: string,
  apiKey?: string
): Promise<{ events: Array<{ event: string; data: unknown }> }> {
  const headers: Record<string, string> = { accept: 'text/event-stream' };
  if (apiKey) {
    headers['authorization'] = `Bearer ${apiKey}`;
  }
  const res = await fetch(`${API_BASE}${path}`, { headers });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`API ${res.status}: ${body.slice(0, 200)}`);
  }
  const text = await res.text();
  const events: Array<{ event: string; data: unknown }> = [];
  for (const block of text.split('\n\n')) {
    let event = 'message';
    const dataLines: string[] = [];
    for (const line of block.split('\n')) {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) continue;
    const raw = dataLines.join('\n');
    let data: unknown = raw;
    try {
      data = JSON.parse(raw);
    } catch {
      /* non-JSON data — keep the raw string */
    }
    events.push({ event, data });
  }
  return { events };
}

function jsonResult(data: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(data, null, 2) }] };
}

export class DfirMcpServer extends McpAgent<Env, Record<string, never>, Record<string, never>> {
  server = new McpServer({
    name: 'DFIR-ThreatIntel-MCP',
    version: '2.0.0',
  });

  private apiKey: string | undefined;

  override async onConnect(conn: Connection, ctx: ConnectionContext): Promise<void> {
    const authz = ctx.request.headers.get('authorization') ?? '';
    const bearer = /^Bearer\s+(.+)$/i.exec(authz)?.[1];
    const apiKey = ctx.request.headers.get('x-api-key') ?? undefined;
    this.apiKey = bearer ?? apiKey ?? undefined;

    if (!this.apiKey) {
      throw new Error('API key required — provide via Authorization: Bearer or X-API-Key');
    }

    await super.onConnect(conn, ctx);
  }

  async init() {
    // ── IOC Check ────────────────────────────────────────────────────────
    this.server.tool(
      'check_ioc',
      'Check reputation of an IP address, domain, URL, or file hash (MD5/SHA1/SHA256) across 30+ threat intelligence providers. Returns composite score, admiralty grade, and per-provider verdicts.',
      { indicator: z.string().describe('The IOC to check — IP, domain, URL, or hash') },
      async ({ indicator }) => {
        const data = await apiFetchSse(
          `/api/v1/ioc/check?indicator=${encodeURIComponent(indicator)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── CVE Lookup ───────────────────────────────────────────────────────
    this.server.tool(
      'lookup_cve',
      'Look up a CVE by ID. Returns description, CVSS score, EPSS probability, CISA KEV status, affected products, and references.',
      { cve_id: z.string().describe('CVE identifier, e.g. CVE-2024-3094') },
      async ({ cve_id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/cve/lookup?id=${encodeURIComponent(cve_id)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Threat Actor Enrichment ──────────────────────────────────────────
    this.server.tool(
      'enrich_actor',
      'Get a threat actor profile. Returns aliases, country attribution, MITRE ATT&CK techniques, known campaigns, and associated malware families.',
      { actor: z.string().describe('Threat actor name or slug, e.g. APT28, lazarus-group') },
      async ({ actor }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/actor-enrich?name=${encodeURIComponent(actor)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Malpedia Search ──────────────────────────────────────────────────
    this.server.tool(
      'search_malpedia',
      'Search Malpedia for malware families or threat actors. Returns matching entries with descriptions and references.',
      { q: z.string().describe('Search query — malware family name or actor name') },
      async ({ q }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/malpedia/search?q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Domain Lookup ────────────────────────────────────────────────────
    this.server.tool(
      'lookup_domain',
      'Domain intelligence lookup. Returns DNS records (A, AAAA, MX, NS, TXT, SOA), WHOIS/RDAP registration data, CT log (certificate transparency) entries, SPF/DKIM/DMARC email authentication analysis, and threat intel hits from blocklists and IOC feeds.',
      { domain: z.string().describe('Fully qualified domain name, e.g. example.com') },
      async ({ domain }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/domain/lookup?domain=${encodeURIComponent(domain)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── ASN Lookup ───────────────────────────────────────────────────────
    this.server.tool(
      'lookup_asn',
      'ASN intelligence lookup. Returns AS name, country, network ranges, RIR registration, and BGP peer info.',
      { asn: z.string().describe('AS number, e.g. AS13335 or 13335') },
      async ({ asn }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/asn/lookup?asn=${encodeURIComponent(asn)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Triage Search ────────────────────────────────────────────────────
    this.server.tool(
      'search_triage',
      'Search Recorded Future Triage sandbox for malware samples by family, tag, hash, URL, or domain. Returns analysis results, behavioral reports, and extracted configs.',
      { q: z.string().describe('Triage search query — family:name, tag:ransomware, md5:..., url:...') },
      async ({ q }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/triage/search?q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Today's Briefing ─────────────────────────────────────────────────
    this.server.tool(
      'get_today_briefing',
      "Get today's threat intelligence briefing. A curated digest of the latest CVEs, ransomware activity, data breaches, and emerging threats from the past 24 hours.",
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/briefings/today', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── List Briefings ───────────────────────────────────────────────────
    this.server.tool(
      'list_briefings',
      'List recent threat intelligence briefings (daily and weekly). Returns slug, date, type, and summary for each.',
      { limit: z.number().optional().describe('Max briefings to return (default 10)') },
      async ({ limit }) => {
        const qs = limit ? `?limit=${limit}` : '';
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/briefings/list${qs}`, this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Live IOCs ────────────────────────────────────────────────────────
    this.server.tool(
      'get_live_iocs',
      'Get the most recent live IOCs aggregated from 12+ providers (URLhaus, ThreatFox, AlienVault OTX, SANS ISC, etc). Items are normalized, allowlist-filtered (RFC 5737, vendor docs), and confidence-scored. Supports filtering by IOC kind.',
      {
        kind: z.enum(['ip', 'url', 'domain', 'hash']).optional().describe('Filter to a single IOC kind'),
        limit: z.number().int().min(1).max(500).optional().describe('Max items to return (default 50)'),
      },
      async ({ kind, limit }) => {
        const params = new URLSearchParams();
        if (kind) params.set('kind', kind);
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/live-iocs?${params.toString()}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Ransomware Recent ────────────────────────────────────────────────
    this.server.tool(
      'get_ransomware_activity',
      'Get recent ransomware activity — latest victims, group activity, and leak-site posts from ransomware.live and other trackers.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/ransomware-recent', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Supply Chain Attacks ─────────────────────────────────────────────
    this.server.tool(
      'get_supply_chain_attacks',
      'Software supply-chain compromise incidents (npm/PyPI/container/AI-agent ecosystems) from supplychainattack.org — title, status, severity, ecosystems, attack vectors, blast radius, remediation, package IOCs, and GHSA sources. Filter by ecosystem/status/severity.',
      {
        ecosystem: z.string().optional().describe('Ecosystem filter, e.g. npm/pypi'),
        status: z.string().optional().describe('Incident status: active/contained/resolved'),
        severity: z.string().optional().describe('Severity: critical/high/medium/low'),
        limit: z.number().optional().describe('Max incidents'),
      },
      async ({ ecosystem, status, severity, limit }) => {
        const p = new URLSearchParams();
        if (ecosystem) p.set('ecosystem', ecosystem);
        if (status) p.set('status', status);
        if (severity) p.set('severity', severity);
        if (limit) p.set('limit', String(limit));
        const qs = p.toString();
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/supply-chain-attacks${qs ? `?${qs}` : ''}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── CERT-In Advisories ───────────────────────────────────────────────
    this.server.tool(
      'get_cert_in_advisories',
      'CERT-In (Indian Computer Emergency Response Team) advisories — vendor-reported vulnerabilities affecting Indian enterprises, with severity, CVEs, products affected, and the official CIAD-YYYY-NNNN ID. Filter by CVE, year, severity, or keyword.',
      {
        q: z.string().optional().describe('Free-text search across title, description, products, CVEs'),
        cve: z.string().optional().describe('CVE ID, e.g. CVE-2025-0110'),
        year: z.string().optional().describe('Filter by year, e.g. 2025'),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Severity filter'),
        id: z.string().optional().describe('Specific CERT-In advisory ID, e.g. CIAD-2025-0010'),
        limit: z.number().optional().describe('Max advisories (default: all)'),
      },
      async ({ q, cve, year, severity, id, limit }) => {
        const p = new URLSearchParams();
        if (q) p.set('q', q);
        if (cve) p.set('cve', cve);
        if (year) p.set('year', year);
        if (severity) p.set('severity', severity);
        if (id) p.set('id', id);
        if (limit) p.set('limit', String(limit));
        const qs = p.toString();
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/cert-in${qs ? `?${qs}` : ''}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Phishing Analyze ─────────────────────────────────────────────────
    this.server.tool(
      'analyze_phishing_email',
      'Analyze raw email source for phishing indicators. Parses headers, checks SPF/DKIM/DMARC, extracts URLs, and computes a risk score with flags.',
      { raw_email: z.string().describe('Full raw email source (headers + body)') },
      async ({ raw_email }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/phishing/analyze', this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'text/plain' },
          body: raw_email,
        });
        return jsonResult(data);
      }
    );

    // ── Unified Search ───────────────────────────────────────────────────
    this.server.tool(
      'unified_search',
      'Cross-source search across all threat intelligence feeds. Search by keyword, IOC, actor name, malware family, or CVE to find matching entries across briefings, live feeds, ransomware data, and more.',
      { q: z.string().describe('Search query') },
      async ({ q }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/unified-search?q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Detections ───────────────────────────────────────────────────────
    this.server.tool(
      'get_detections',
      'Get the latest detection rules feed — Sigma, YARA, and Snort rules mapped to threat actors, malware families, and MITRE ATT&CK techniques.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/detections', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Threat Pulse ─────────────────────────────────────────────────────
    this.server.tool(
      'get_threat_pulse',
      'Get a global threat overview — top active threat actors, trending malware families, most exploited CVEs, and geopolitical cyber events from the past week.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/threat-pulse', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── IOC Correlation ──────────────────────────────────────────────────
    this.server.tool(
      'correlate_iocs',
      'Search correlated IOCs. Find relationships between indicators — shared infrastructure, overlapping campaigns, and linked threat actors.',
      { q: z.string().describe('IOC or keyword to correlate') },
      async ({ q }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ioc-correlation?q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Breach Check ─────────────────────────────────────────────────────
    this.server.tool(
      'check_breach',
      'Check if an email address or domain has been exposed in known data breaches. Returns breach names, dates, and exposed data types.',
      {
        target: z.string().describe('Email address or domain to check'),
        type: z.enum(['email', 'domain']).describe('Whether the target is an email or domain'),
      },
      async ({ target, type }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/breach/${type}?${type}=${encodeURIComponent(target)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Feed Status ──────────────────────────────────────────────────────
    this.server.tool(
      'get_feed_status',
      'Get the health and freshness status of all 30+ threat intelligence feed sources. Shows last update time, error rates, and data volume.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/feed-status', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── MITRE Technique ──────────────────────────────────────────────────
    this.server.tool(
      'lookup_mitre',
      'Look up a MITRE ATT&CK technique by ID. Returns technique name, description, tactics, mitigations, and detection guidance.',
      { technique_id: z.string().describe('MITRE ATT&CK technique ID, e.g. T1566.001') },
      async ({ technique_id }) => {
        const enc = encodeURIComponent(technique_id);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/mitre/technique?id=${enc}&technique=${enc}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Relationship Graph ───────────────────────────────────────────────
    this.server.tool(
      'get_relationships',
      'Get the relationship graph for an IOC — shows connections to threat actors, malware families, campaigns, CVEs, and other indicators.',
      { indicator: z.string().describe('The IOC to get relationships for') },
      async ({ indicator }) => {
        const enc = encodeURIComponent(indicator);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/relationship-graph?indicator=${enc}&q=${enc}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── IP Geolocation & Privacy ─────────────────────────────────────────
    this.server.tool(
      'lookup_ip_geo',
      'Get IP geolocation, ASN, company, and privacy detection (VPN/proxy/tor/hosting). Uses IPinfo and Spur.us for anonymization detection.',
      { ip: z.string().describe('IPv4 or IPv6 address') },
      async ({ ip }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ip-geo?ip=${encodeURIComponent(ip)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Generate Blocklists ──────────────────────────────────────────────
    this.server.tool(
      'get_blocklists',
      'Get pre-generated firewall blocklists in pfSense, iptables, and Suricata formats. Derived from aggregated threat intel feeds.',
      {
        format: z
          .enum(['pfsense', 'iptables', 'suricata', 'meta'])
          .optional()
          .describe('Blocklist format (default: meta)'),
      },
      async ({ format }) => {
        const fmt = format ?? 'meta';
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/blocklists/${fmt}`, this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Search Malware ───────────────────────────────────────────────────
    this.server.tool(
      'search_malware',
      'Search for malware families. Returns family info, YARA rules, samples, and references from Malpedia.',
      { q: z.string().describe('Malware family name or keyword') },
      async ({ q }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/malpedia/search?q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Wayback Machine ─────────────────────────────────────────────────
    this.server.tool(
      'wayback_lookup',
      'Check the Wayback Machine (archive.org) for historical snapshots of a URL. Useful for tracking website changes or recovering deleted content.',
      { url: z.string().describe('URL to look up in the Wayback Machine') },
      async ({ url }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/wayback/cdx?url=${encodeURIComponent(url)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Phishing URL Analysis ───────────────────────────────────────────
    this.server.tool(
      'analyze_phishing_url',
      'Analyze a URL for phishing indicators. Checks against PhishTank, OpenPhish, URLhaus, and performs visual similarity analysis.',
      { url: z.string().describe('URL to analyze') },
      async ({ url }) => {
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/phishing/analyze`, this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ url }),
        });
        return jsonResult(data);
      }
    );

    // ── Web Scan ────────────────────────────────────────────────────────
    this.server.tool(
      'scan_website',
      'Scan a website for security issues — checks security headers, SSL certificate, technologies, and potential vulnerabilities.',
      { url: z.string().describe('URL to scan') },
      async ({ url }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/web-scan?url=${encodeURIComponent(url)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Google Dorks ────────────────────────────────────────────────────
    this.server.tool(
      'google_dorks',
      'Generate and execute Google dork queries for a domain. Useful for finding exposed files, login pages, and sensitive information.',
      {
        domain: z.string().describe('Domain to dork'),
        dork_type: z.enum(['files', 'login', 'sensitive', 'all']).optional().describe('Type of dorks to run'),
      },
      async ({ domain, dork_type }) => {
        const dorks: Record<string, string> = {
          files: `site:${domain} (ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:txt OR ext:log OR ext:bak)`,
          login: `site:${domain} (inurl:login OR inurl:admin OR inurl:signin OR intitle:"log in")`,
          sensitive: `site:${domain} (ext:env OR ext:sql OR ext:bak OR ext:config OR intitle:"index of" OR intext:"password")`,
          all: `site:${domain}`,
        };
        const q = dorks[dork_type ?? 'all'] ?? `site:${domain}`;
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/google-dorks?domain=${encodeURIComponent(domain)}&q=${encodeURIComponent(q)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Crypto Trace ────────────────────────────────────────────────────
    this.server.tool(
      'trace_crypto_address',
      'Trace a cryptocurrency wallet address. Returns balance, transaction history, and associated entities from blockchain explorers.',
      {
        address: z.string().describe('Crypto wallet address'),
        chain: z.enum(['bitcoin', 'ethereum', 'monero']).optional().describe('Blockchain (default: auto-detect)'),
      },
      async ({ address, chain }) => {
        const qs = new URLSearchParams({ address });
        if (chain) qs.set('chain', chain);
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/crypto-trace?${qs}`, this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Report Parser ───────────────────────────────────────────────────
    this.server.tool(
      'parse_threat_report',
      'Parse a threat intelligence report or article to extract structured data: IOCs (IPs, domains, URLs, hashes), threat actors, malware families, MITRE ATT&CK techniques, CVEs, targeted sectors, and an executive summary. Use this when analyzing threat reports, blog posts, or incident write-ups.',
      {
        text: z.string().optional().describe('The report text to analyze'),
        url: z.string().optional().describe('URL of the report to fetch and analyze'),
      },
      async ({ text, url }) => {
        if (!text && !url) {
          throw new Error('Either text or url must be provided');
        }
        const data = await apiFetch<Record<string, unknown>>('/api/v1/report/parse', this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ text, url }),
        });
        return jsonResult(data);
      }
    );

    // ── IOC Lifecycle ───────────────────────────────────────────────────
    this.server.tool(
      'get_ioc_lifecycle',
      'Get the lifecycle data for an IOC — when it first appeared, last seen, activity trend, and decay rate. Use this to understand if an indicator is still active or dormant.',
      { indicator: z.string().describe('The IOC to get lifecycle data for') },
      async ({ indicator }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ioc-lifecycle?indicator=${encodeURIComponent(indicator)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Trending IOCs ───────────────────────────────────────────────────
    this.server.tool(
      'get_trending_iocs',
      'Get the most active IOCs in the last 24 hours. Returns indicators with highest observation counts and scores, useful for identifying emerging threats.',
      {
        limit: z.number().optional().describe('Max results (default 50, max 200)'),
        type: z.enum(['ipv4', 'domain', 'url', 'hash']).optional().describe('Filter by indicator type'),
      },
      async ({ limit, type }) => {
        const params = new URLSearchParams();
        if (limit) params.set('limit', String(limit));
        if (type) params.set('type', type);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ioc-lifecycle/trending?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── YARA Rule Generator ─────────────────────────────────────────────
    this.server.tool(
      'generate_yara_rule',
      'Generate a YARA detection rule using AI. Provide a description of what to detect, and optionally known strings, malware family name, and target file type. Returns a syntactically valid YARA rule with metadata.',
      {
        description: z.string().describe('What the rule should detect (e.g., "Cobalt Strike beacon DLL")'),
        strings: z.array(z.string()).optional().describe('Known malicious strings to match'),
        family: z.string().optional().describe('Malware family name'),
        filetype: z.string().optional().describe('Target file type (PE, ELF, document, etc.)'),
        complexity: z.enum(['basic', 'standard', 'advanced']).optional().describe('Rule complexity level'),
      },
      async ({ description, strings, family, filetype, complexity }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/yara/generate', this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ description, strings, family, filetype, complexity }),
        });
        return jsonResult(data);
      }
    );

    // ── YARA Rule Validator ─────────────────────────────────────────────
    this.server.tool(
      'validate_yara_rule',
      'Validate a YARA rule syntax. Checks for balanced braces, required sections, and proper string definitions.',
      {
        rule: z.string().describe('The YARA rule text to validate'),
      },
      async ({ rule }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/yara/validate', this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ rule }),
        });
        return jsonResult(data);
      }
    );

    // ── CT Domain Monitor ───────────────────────────────────────────────
    this.server.tool(
      'watch_domain_ct',
      'Add a domain to Certificate Transparency monitoring. Alerts on new subdomains, suspicious patterns, wildcard certs, and more. Uses crt.sh for unlimited free CT log queries.',
      {
        domain: z.string().describe('Domain to monitor (e.g., example.com)'),
        alert_types: z
          .array(z.enum(['new_subdomain', 'suspicious_name', 'wildcard', 'ca_change', 'short_validity', 'ip_cert']))
          .optional()
          .describe('Types of alerts to generate'),
      },
      async ({ domain, alert_types }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/ct-monitor/watch', this.apiKey, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ domain, alert_types }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'get_domain_certs',
      'Get recent certificates for a domain from Certificate Transparency logs. Shows new subdomains, certificate details, and any alerts.',
      {
        domain: z.string().describe('Domain to query'),
        days: z.number().optional().describe('Look back period in days (default 30)'),
        limit: z.number().optional().describe('Max results (default 100)'),
      },
      async ({ domain, days, limit }) => {
        const params = new URLSearchParams({ domain });
        if (days) params.set('days', String(days));
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ct-monitor/certs?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── WHOIS History ────────────────────────────────────────────────
    this.server.tool(
      'get_domain_history',
      'Get the WHOIS history for a domain. Returns all historical registration snapshots, ownership changes, registrar changes, and nameserver changes over time. Essential for tracking domain ownership transfers and identifying infrastructure reuse by threat actors.',
      { domain: z.string().describe('Domain to get history for, e.g. evil-example.com') },
      async ({ domain }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/domain/history?domain=${encodeURIComponent(domain)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'pivot_domain',
      'Pivot across domains by shared registrant attributes. Find other domains owned by the same entity by matching registrant email, organization, nameservers, or registrar. Critical for mapping attacker infrastructure — if a malicious domain shares its registrant email with 50 other domains, those are likely all owned by the same threat actor.',
      {
        domain: z.string().describe('Domain to pivot from'),
        type: z
          .enum(['email', 'org', 'nameserver', 'registrar', 'all'])
          .optional()
          .describe(
            'Pivot type (default: all) — email pivots by registrant email, org by organization, nameserver by shared NS, registrar by same registrar'
          ),
      },
      async ({ domain, type }) => {
        const params = new URLSearchParams({ domain });
        if (type) params.set('type', type);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/domain/history/pivot?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'search_registrant',
      'Search for all domains registered by a specific email address or organization name. Returns domains, registration dates, and snapshot counts. Useful for finding all infrastructure operated by a known threat actor.',
      {
        email: z.string().optional().describe('Registrant email to search for'),
        org: z.string().optional().describe('Registrant organization name to search for (partial match)'),
      },
      async ({ email, org }) => {
        const params = new URLSearchParams();
        if (email) params.set('email', email);
        if (org) params.set('org', org);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/domain/history/search?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── CVE Intelligence ──────────────────────────────────────────────
    this.server.tool(
      'poc_scan',
      'Search GitHub for public exploit/PoC repositories for a CVE. Returns repo URLs, star counts, language, age, and whether the repo has actual code. Bypasses GitHub 1000-result limit via monthly pagination.',
      { cve_id: z.string().describe('CVE identifier, e.g. CVE-2024-3094') },
      async ({ cve_id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/cve-poc-scan?id=${encodeURIComponent(cve_id)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'cve_poc_map',
      'Get the cached CVE-to-GitHub-repo mapping. Pass ?id=CVE-XXXX-XXXXX for a single CVE, or ?year=YYYY for a year-scoped index of all mapped CVEs. Results are KV-cached for 24h.',
      {
        cve_id: z.string().optional().describe('CVE ID (optional if year is provided)'),
        year: z.number().optional().describe('Year for index lookup (optional if cve_id is provided)'),
      },
      async ({ cve_id, year }) => {
        const params = new URLSearchParams();
        if (cve_id) params.set('id', cve_id);
        if (year) params.set('year', String(year));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/cve-poc-map?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'cyber_news',
      'Aggregate cybersecurity news from 11 RSS feeds across 5 tiers (Advisory, Exploit, Research, Vendor, Community). Supports tier filtering and keyword search. Sources: CISA, Rapid7, Packet Storm, BleepingComputer, Hacker News, GitHub Security, ZDI, Reddit netsec/exploitdev/bugbounty.',
      {
        tier: z
          .number()
          .optional()
          .describe('Filter by tier: 1=Advisory, 2=Exploit, 3=Research, 4=Vendor, 5=Community'),
        query: z.string().optional().describe('Keyword filter (searches title + description)'),
        limit: z.number().optional().describe('Max articles to return (default 100)'),
      },
      async ({ tier, query, limit }) => {
        const params = new URLSearchParams({ limit: String(limit ?? 100) });
        if (tier) params.set('tier', String(tier));
        if (query) params.set('q', query);
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/cyber-news?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'cve_health',
      'Check the health of CVE data pipelines. Validates NVD API, EPSS API, CISA KEV, GitHub API rate limit, KV intel cache (EPSS coverage, KEV count, field completeness), and Exploit-DB mirror availability. Returns overall status (healthy/degraded/unhealthy) with per-check details.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/cve-health', this.apiKey);
        return jsonResult(data);
      }
    );

    this.server.tool(
      'soc_cve_report',
      'Generate a SOC CVE intelligence report. Takes a list of up to 50 CVE IDs and bundles CVE lookup + PoC scan + health check into a downloadable CSV or Markdown report. Returns executive summary, CVSS/EPSS/KEV details, PoC repos, and pipeline health.',
      {
        cves: z.array(z.string()).describe('List of CVE IDs to include in the report (max 50)'),
        format: z.enum(['csv', 'markdown']).optional().describe('Output format: csv or markdown (default markdown)'),
      },
      async ({ cves, format }) => {
        const data = await apiFetch<Record<string, unknown>>(
          '/api/v1/soc-cve-report/json',
          this.apiKey,
          {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ cves, format: format ?? 'markdown' }),
          }
        );
        return jsonResult(data);
      }
    );

    // ── Telegram Intelligence Search ──────────────────────────────────
    this.server.tool(
      'tg_boolean_search',
      'Search Telegram leak messages with boolean AND/OR/NOT operators and field qualifiers. Fields: text, channel.title, channel.username, severity, leak_type. Supports wildcards (prefix*) and exact phrases ("quoted").',
      {
        q: z.string().describe('Boolean query (e.g. ransomware AND channel.title:TeamPCP NOT tutorial)'),
        mode: z.enum(['boolean', 'general']).optional().describe('Search mode (default: boolean)'),
        channel: z.string().optional().describe('Filter by channel handle'),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional().describe('Filter by severity'),
        from: z.string().optional().describe('Date from (ISO date)'),
        to: z.string().optional().describe('Date to (ISO date)'),
        sort: z.enum(['newest', 'oldest']).optional().describe('Sort order (default: newest)'),
        limit: z.number().optional().describe('Max results (default 50)'),
      },
      async (args) => {
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(args)) {
          if (v !== undefined && v !== null) params.set(k, String(v));
        }
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/tg-search?${params}`, this.apiKey);
        return jsonResult(data);
      }
    );

    this.server.tool(
      'tg_timeline',
      'Get Telegram message volume timeline data (messages per day) with severity breakdown. Useful for visualizing activity spikes.',
      {
        q: z.string().optional().describe('Boolean query to filter timeline'),
        channel: z.string().optional().describe('Filter by channel handle'),
        days: z.number().optional().describe('Number of days to look back (default 30, max 365)'),
      },
      async (args) => {
        const params = new URLSearchParams();
        for (const [k, v] of Object.entries(args)) {
          if (v !== undefined && v !== null) params.set(k, String(v));
        }
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/tg-timeline?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool('tg_saved_searches_list', 'List saved Telegram boolean search queries.', {}, async () => {
      const data = await apiFetch<Record<string, unknown>>('/api/v1/tg-saved-searches', this.apiKey);
      return jsonResult(data);
    });

    this.server.tool(
      'tg_saved_search_create',
      'Save a Telegram boolean search query for one-click reuse.',
      {
        name: z.string().describe('Saved search name (e.g. "Daily Stealer Monitor")'),
        query: z.string().describe('Boolean query to save'),
        mode: z.enum(['boolean', 'general']).optional().describe('Search mode'),
        sort_order: z.enum(['newest', 'oldest']).optional().describe('Sort order'),
      },
      async ({ name, query, mode, sort_order }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/tg-saved-searches', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ name, query, mode, sort_order }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'tg_saved_search_delete',
      'Delete a saved Telegram search query.',
      {
        id: z.string().describe('Saved search ID'),
      },
      async ({ id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/tg-saved-searches/${encodeURIComponent(id)}`,
          this.apiKey,
          { method: 'DELETE' }
        );
        return jsonResult(data);
      }
    );

    // ── Passive DNS Correlation Engine ──────────────────────────────────
    this.server.tool(
      'passive_dns_query',
      'Query passive DNS for a domain or IP. Returns historical DNS resolutions, infrastructure migrations, and fast-flux detection. Sources: VirusTotal, URLscan, crt.sh, CIRCL.',
      {
        query: z.string().describe('Domain or IP address to query'),
        force: z.boolean().optional().describe('Force fresh query (bypass D1 cache)'),
      },
      async ({ query, force }) => {
        const params = new URLSearchParams({ query });
        if (force) params.set('force', '1');
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/passive-dns?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'passive_dns_reverse',
      'Reverse passive DNS lookup: find all domains that historically resolved to a given IP. Reads from accumulated D1 cache.',
      { ip: z.string().describe('IP address to reverse-lookup') },
      async ({ ip }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/passive-dns/reverse?ip=${encodeURIComponent(ip)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'passive_dns_overlap',
      'Find IPs shared between multiple domains (infrastructure overlap detection). Useful for mapping shared malicious hosting.',
      { domains: z.string().describe('Comma-separated list of domains (min 2)') },
      async ({ domains }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/passive-dns/overlap?domains=${encodeURIComponent(domains)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── IOC Watchlist ───────────────────────────────────────────────────
    this.server.tool(
      'ioc_watchlist_add',
      'Add an IOC to the watchlist for proactive alerting. Supported types: ip, domain, url, hash, cve, email. Alerts fire when the IOC appears in feeds.',
      {
        indicator: z.string().describe('The IOC value to watch'),
        indicator_type: z.enum(['ip', 'domain', 'url', 'hash', 'cve', 'email']).describe('IOC type'),
        label: z.string().optional().describe('Human-readable label'),
        webhook_url: z.string().optional().describe('Webhook URL (Discord, Slack, Telegram, custom)'),
        min_confidence: z.number().optional().describe('Minimum confidence to trigger (0-100, default 50)'),
        tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).optional().describe('TLP marking'),
      },
      async (args) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/ioc-watchlist', this.apiKey, {
          method: 'POST',
          body: JSON.stringify(args),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ioc_watchlist_list',
      'List all watched IOCs. Optionally filter by type.',
      {
        type: z.enum(['ip', 'domain', 'url', 'hash', 'cve', 'email']).optional().describe('Filter by IOC type'),
        limit: z.number().optional().describe('Max results (default 100)'),
      },
      async ({ type, limit }) => {
        const params = new URLSearchParams();
        if (type) params.set('type', type);
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ioc-watchlist?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ioc_watchlist_alerts',
      'List recent alerts from the IOC watchlist.',
      {
        indicator: z.string().optional().describe('Filter by indicator'),
        since: z.string().optional().describe('ISO 8601 lower bound'),
        limit: z.number().optional().describe('Max results (default 50)'),
      },
      async ({ indicator, since, limit }) => {
        const params = new URLSearchParams();
        if (indicator) params.set('indicator', indicator);
        if (since) params.set('since', since);
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/ioc-watchlist/alerts?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ioc_watchlist_stats',
      'Get watchlist dashboard stats: total watches, alerts by type, webhook delivery rate.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/ioc-watchlist/stats', this.apiKey);
        return jsonResult(data);
      }
    );

    // ── Investigation Notebooks ────────────────────────────────────────
    this.server.tool(
      'notebook_list',
      'List investigation notebooks. Each notebook is a persistent investigation session with notes, IOCs, findings, and timeline entries stored in D1.',
      {
        status: z.enum(['open', 'investigating', 'resolved', 'archived']).optional().describe('Filter by status'),
        limit: z.number().optional().describe('Max results (default 50)'),
      },
      async ({ status, limit }) => {
        const params = new URLSearchParams();
        if (status) params.set('status', status);
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(`/api/v1/notebooks?${params}`, this.apiKey);
        return jsonResult(data);
      }
    );

    this.server.tool(
      'notebook_create',
      'Create a new investigation notebook.',
      {
        title: z.string().describe('Notebook title (e.g. "Phishing Campaign — example.com")'),
        description: z.string().optional().describe('Brief summary'),
        severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('Severity (default: info)'),
      },
      async ({ title, description, severity }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/notebooks', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ title, description, severity }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'notebook_get',
      'Get a notebook with all its entries.',
      {
        id: z.string().describe('Notebook ID'),
      },
      async ({ id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/notebooks/${encodeURIComponent(id)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'notebook_add_entry',
      'Add a note, IOC, finding, timeline event, or artifact to a notebook.',
      {
        notebook_id: z.string().describe('Notebook ID'),
        entry_type: z
          .enum(['note', 'ioc', 'finding', 'timeline', 'artifact'])
          .optional()
          .describe('Entry type (default: note)'),
        content: z.string().describe('Entry content'),
      },
      async ({ notebook_id, entry_type, content }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/notebooks/${encodeURIComponent(notebook_id)}/entries`,
          this.apiKey,
          { method: 'POST', body: JSON.stringify({ entry_type, content }) }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'notebook_update',
      'Update a notebook title, description, status, or severity.',
      {
        id: z.string().describe('Notebook ID'),
        title: z.string().optional().describe('New title'),
        description: z.string().optional().describe('New description'),
        status: z.enum(['open', 'investigating', 'resolved', 'archived']).optional().describe('New status'),
        severity: z.enum(['info', 'low', 'medium', 'high', 'critical']).optional().describe('New severity'),
      },
      async ({ id, title, description, status, severity }) => {
        const body: Record<string, unknown> = {};
        if (title !== undefined) body.title = title;
        if (description !== undefined) body.description = description;
        if (status !== undefined) body.status = status;
        if (severity !== undefined) body.severity = severity;
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/notebooks/${encodeURIComponent(id)}`,
          this.apiKey,
          { method: 'PUT', body: JSON.stringify(body) }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'notebook_delete',
      'Delete a notebook and all its entries.',
      {
        id: z.string().describe('Notebook ID'),
      },
      async ({ id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/notebooks/${encodeURIComponent(id)}`,
          this.apiKey,
          { method: 'DELETE' }
        );
        return jsonResult(data);
      }
    );

    // ── CTI Workspace Tools (AEAD Lifecycle) ──────────────────────────
    this.server.tool(
      'ws_list',
      'List investigation workspaces. Each workspace is a full AEAD-lifecycle case with subjects, connections, findings, and timeline.',
      {
        status: z.enum(['open', 'active', 'archived']).optional().describe('Filter by status'),
        limit: z.number().optional().describe('Max results (default 50)'),
      },
      async ({ status, limit }) => {
        const params = new URLSearchParams();
        if (status) params.set('status', status);
        if (limit) params.set('limit', String(limit));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces?${params}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_create',
      'Create a new investigation workspace for AEAD lifecycle tracking.',
      {
        title: z.string().describe('Workspace title (e.g. "Phishing — example.com")'),
        description: z.string().optional().describe('Brief summary'),
        target: z.string().optional().describe('Primary target (domain, IP, email, etc.)'),
        target_type: z
          .enum(['person', 'domain', 'org', 'username', 'email', 'ip', 'other'])
          .optional()
          .describe('Target type (default: domain)'),
        tags: z.array(z.string()).optional().describe('Tags for classification'),
      },
      async ({ title, description, target, target_type, tags }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/workspaces', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ title, description, target, target_type, tags }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_get',
      'Get a workspace with all subjects, connections, findings, and timeline.',
      {
        id: z.string().describe('Workspace ID'),
      },
      async ({ id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(id)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_add_subject',
      'Register a subject (entity) in a workspace investigation.',
      {
        workspace_id: z.string().describe('Workspace ID'),
        subject_type: z
          .enum([
            'person',
            'domain',
            'org',
            'username',
            'email',
            'ip',
            'phone',
            'location',
            'asset',
            'device',
            'crypto',
            'custom',
          ])
          .describe('Entity type'),
        label: z.string().describe('Human-readable label'),
        value: z.string().optional().describe('Raw value (IP, email, domain, etc.)'),
        confidence: z.number().optional().describe('Confidence 0-100'),
        trust_score: z.number().optional().describe('Trust score 1-5'),
      },
      async ({ workspace_id, subject_type, label, value, confidence, trust_score }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/subjects`,
          this.apiKey,
          { method: 'POST', body: JSON.stringify({ subject_type, label, value, confidence, trust_score }) }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_add_connection',
      'Define a relationship between two subjects in a workspace.',
      {
        workspace_id: z.string().describe('Workspace ID'),
        from_subject_id: z.string().describe('Source subject ID'),
        to_subject_id: z.string().describe('Target subject ID'),
        relationship: z
          .string()
          .describe('Relationship type (owns, uses, works_at, linked_to, alias, communicated_with)'),
        strength: z.enum(['confirmed', 'probable', 'possible']).optional().describe('Connection strength'),
      },
      async ({ workspace_id, from_subject_id, to_subject_id, relationship, strength }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/connections`,
          this.apiKey,
          { method: 'POST', body: JSON.stringify({ from_subject_id, to_subject_id, relationship, strength }) }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_add_finding',
      'Log a finding with source, trust score, and confidence in a workspace.',
      {
        workspace_id: z.string().describe('Workspace ID'),
        subject_id: z.string().optional().describe('Related subject ID'),
        finding_type: z
          .enum(['infrastructure', 'identity', 'exposure', 'credential', 'behavioral', 'legal', 'ioc'])
          .optional()
          .describe('Finding type'),
        weight: z.enum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']).optional().describe('Severity weight'),
        description: z.string().describe('Finding description'),
        source_url: z.string().optional().describe('Source URL'),
        confidence: z.number().optional().describe('Confidence 0-100'),
      },
      async ({ workspace_id, subject_id, finding_type, weight, description, source_url, confidence }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/findings`,
          this.apiKey,
          {
            method: 'POST',
            body: JSON.stringify({ subject_id, finding_type, weight, description, source_url, confidence }),
          }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_exposure',
      'Calculate composite exposure score (0-100) for a target based on IOC reputation, breach exposure, infrastructure, attack surface, and threat intel.',
      {
        target: z.string().describe('Target to score (domain, IP, email)'),
        target_type: z.string().optional().describe('Target type'),
        ioc_reputation: z
          .object({})
          .passthrough()
          .optional()
          .describe('IOC reputation signals (abuseScore, vtPositives, etc.)'),
        breach_exposure: z.object({}).passthrough().optional().describe('Breach exposure signals'),
        infrastructure: z.object({}).passthrough().optional().describe('Infrastructure exposure signals'),
        attack_surface: z.object({}).passthrough().optional().describe('Attack surface signals'),
        threat_intel: z.object({}).passthrough().optional().describe('Threat intelligence signals'),
      },
      async (args) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/cti/exposure', this.apiKey, {
          method: 'POST',
          body: JSON.stringify(args),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_export_stix',
      'Export workspace indicators as STIX 2.1 bundle or flat IOC list.',
      {
        workspace_id: z.string().describe('Workspace ID'),
        format: z.enum(['stix', 'flat']).optional().describe('Output format (default: stix)'),
        default_tlp: z.enum(['WHITE', 'GREEN', 'AMBER', 'RED']).optional().describe('Default TLP marking'),
      },
      async ({ workspace_id, format, default_tlp }) => {
        const url = `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/export?format=${format ?? 'stix'}`;
        const data = await apiFetch<Record<string, unknown>>(url, this.apiKey);
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_render_graph',
      'Render an ASCII box-drawing relationship graph, timeline, or risk heatmap from workspace data.',
      {
        type: z.enum(['entities', 'timeline', 'risk']).describe('Graph type'),
        nodes: z.array(z.object({}).passthrough()).optional().describe('Graph nodes (for entities type)'),
        edges: z.array(z.object({}).passthrough()).optional().describe('Graph edges (for entities type)'),
        events: z.array(z.object({}).passthrough()).optional().describe('Timeline events'),
        dimensions: z.array(z.object({}).passthrough()).optional().describe('Risk dimensions'),
        title: z.string().optional().describe('Graph title'),
      },
      async (args) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/cti/render/graph', this.apiKey, {
          method: 'POST',
          body: JSON.stringify(args),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_workflow_advance',
      'Advance a workspace to the next AEAD phase (Acquire→Enrich→Assess→Deliver→Complete).',
      {
        workspace_id: z.string().describe('Workspace ID'),
      },
      async ({ workspace_id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/workflow/advance`,
          this.apiKey,
          { method: 'POST' }
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'ws_workflow_summary',
      'Get workspace summary: phase progress, findings breakdown, recommended commands.',
      {
        workspace_id: z.string().describe('Workspace ID'),
      },
      async ({ workspace_id }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/workspaces/${encodeURIComponent(workspace_id)}/workflow/summary`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── Report Analysis ────────────────────────────────────────────────
    this.server.tool(
      'extract_ttps',
      'Extract MITRE ATT&CK techniques from a free-text threat report. Returns technique IDs, tactic labels, confidence (high/medium/low), and the supporting evidence string.',
      {
        text: z.string().min(30).max(50_000).describe('Report text (30 chars – 50KB)'),
        use_llm: z
          .boolean()
          .optional()
          .describe('Run the LLM branch too (default true). Set false for cheap keyword-only extraction.'),
      },
      async ({ text, use_llm }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/ttp-extract', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ text, useLlm: use_llm ?? true }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'extract_fivew',
      'Extract the classic 5W grid (who/what/when/where/why) from a free-text report. Single LLM call; returns structured JSON with a per-grid confidence score.',
      {
        text: z.string().min(100).max(50_000).describe('Report text (100 chars – 50KB)'),
      },
      async ({ text }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/fivew', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ text }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'extract_iocs_from_image',
      'Fetch an image and run Workers AI vision over it to extract IOCs that are only visible in screenshots (IPs, domains, URLs, hashes, CVEs, emails). Returns the OCR text + the per-IOC confidence band.',
      {
        url: z.string().url().describe('HTTP(S) URL of the image to analyze (max 5MB)'),
      },
      async ({ url }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/image-ioc', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({ url }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'analyze_report',
      'Unified per-report analyzer. Runs summary + IOC extraction (with allowlist + confidence) + MITRE ATT&CK TTP mapping + 5W context + CVE extraction + image-OCR + STIX 2.1 bundle in a single round-trip. Accepts text, URL, or both; optionally takes image URLs to OCR.',
      {
        text: z.string().max(80_000).optional().describe('Report text (optional if url provided)'),
        url: z.string().url().optional().describe('Report URL to fetch (optional if text provided)'),
        image_urls: z.array(z.string().url()).max(8).optional().describe('Image URLs to OCR for embedded IOCs (max 8)'),
        title: z.string().optional().describe('Display title for the report'),
      },
      async ({ text, url, image_urls, title }) => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/report-analyzer', this.apiKey, {
          method: 'POST',
          body: JSON.stringify({
            text,
            url,
            imageUrls: image_urls,
            title,
          }),
        });
        return jsonResult(data);
      }
    );

    this.server.tool(
      'get_cross_report_graph',
      'Cross-report knowledge-graph snapshot. Returns the top N most-referenced nodes (IOCs, actors, malware, CVEs, techniques, campaigns) across every ingested source, with the edges that connect them. Filter by node type and time window.',
      {
        types: z
          .array(z.enum(['ip', 'domain', 'hash', 'url', 'actor', 'malware', 'campaign', 'cve', 'technique']))
          .optional()
          .describe('Node types to include (default: all)'),
        days: z
          .number()
          .int()
          .min(0)
          .max(3650)
          .optional()
          .describe('Only consider nodes seen in the last N days (default 90; 0 = all)'),
        limit: z.number().int().min(10).max(1000).optional().describe('Max nodes to return (default 200, max 1000)'),
        min_conn: z
          .number()
          .int()
          .min(0)
          .max(50)
          .optional()
          .describe('Minimum edge count to include a node (default 0)'),
      },
      async ({ types, days, limit, min_conn }) => {
        const params = new URLSearchParams();
        if (types && types.length > 0) params.set('types', types.join(','));
        if (days !== undefined) params.set('days', String(days));
        if (limit !== undefined) params.set('limit', String(limit));
        if (min_conn !== undefined && min_conn > 0) params.set('minConn', String(min_conn));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/graph/cross-report?${params.toString()}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    // ── HudsonRock Cavalier (infostealer intelligence) ───────────────────
    this.server.tool(
      'hr_search_email',
      'Search for compromised credentials by email address via Hudson Rock Cavalier API. Returns infostealer infections, stealer families, compromised URLs, and credential types (employee/user/third-party).',
      { email: z.string().describe('Email address to search') },
      async ({ email }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/breach/hudsonrock?email=${encodeURIComponent(email)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_search_domain',
      'Search for domain-wide infostealer compromises via Hudson Rock Cavalier API. Returns compromised employees, users, and third-party exposures with stealer families and infection dates.',
      {
        domain: z.string().describe('Domain name, e.g. example.com'),
        types: z
          .array(z.enum(['employees', 'users', 'third_parties']))
          .optional()
          .describe('Filter by credential type'),
        keywords: z.array(z.string()).optional().describe('Filter URLs by keyword (e.g. sso, vpn, admin)'),
      },
      async ({ domain, types, keywords }) => {
        const p = new URLSearchParams({ domain });
        if (types) p.set('types', types.join(','));
        if (keywords) p.set('keywords', keywords.join(','));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/breach/hudsonrock/domain?${p}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_domain_overview',
      'Get domain compromise overview statistics from Hudson Rock — compromised employee/user counts, last compromise dates, and upload timelines. Useful for risk posture assessment.',
      { domain: z.string().describe('Domain name, e.g. example.com') },
      async ({ domain }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/domain-overview?domain=${encodeURIComponent(domain)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_assets_discovery',
      'Discover all compromised URLs for a domain (attack surface mapping). Returns URLs where credentials were stolen, occurrence counts, and compromise types.',
      {
        domain: z.string().describe('Domain name, e.g. example.com'),
        types: z.array(z.enum(['employees', 'users'])).optional(),
        keywords: z.array(z.string()).optional().describe('Filter by URL keyword'),
      },
      async ({ domain, types, keywords }) => {
        const p = new URLSearchParams({ domain });
        if (types) p.set('types', types.join(','));
        if (keywords) p.set('keywords', keywords.join(','));
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/discovery?${p}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_third_party_risk',
      'Assess third-party / supply-chain risk for a domain. Returns employee URLs, third-party service URLs, and user URLs where credentials were compromised — indicating supply chain exposure.',
      { domain: z.string().describe('Domain name to assess') },
      async ({ domain }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/assessment?domain=${encodeURIComponent(domain)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_infection_analysis',
      'AI-powered infection source analysis for a specific stealer log. Returns the likely infection URL, confidence score, timeline of suspicious activity, and analyst summary. Works best with Lumma stealers.',
      { stealer: z.string().describe('Stealer ID from a previous search result') },
      async ({ stealer }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/infection-analysis?stealer=${encodeURIComponent(stealer)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_search_username',
      'Search for compromised credentials by username via Hudson Rock Cavalier API.',
      { username: z.string().describe('Username to search') },
      async ({ username }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/username?username=${encodeURIComponent(username)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_search_ip',
      'Search for compromises by IP address or CIDR range via Hudson Rock Cavalier API. Useful for IR when you have a suspicious IP.',
      { ip: z.string().describe('IP address or CIDR range') },
      async ({ ip }) => {
        const data = await apiFetch<Record<string, unknown>>(
          `/api/v1/hudsonrock/ip?ip=${encodeURIComponent(ip)}`,
          this.apiKey
        );
        return jsonResult(data);
      }
    );

    this.server.tool(
      'hr_account',
      'Check Hudson Rock Cavalier API account status, permissions, and quota. Use to verify the API key is valid.',
      {},
      async () => {
        const data = await apiFetch<Record<string, unknown>>('/api/v1/hudsonrock/account', this.apiKey);
        return jsonResult(data);
      }
    );
  }
}
