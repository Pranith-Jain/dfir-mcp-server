import { DfirMcpServer } from './mcp-server';

export { DfirMcpServer };

interface Env {
  DFIR_MCP: DurableObjectNamespace;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Streamable HTTP transport (recommended for MCP clients)
    if (url.pathname.startsWith('/mcp')) {
      return DfirMcpServer.serve('/mcp', { binding: 'DFIR_MCP' }).fetch(request, env, ctx);
    }

    // SSE transport (legacy clients)
    if (url.pathname.startsWith('/sse')) {
      return DfirMcpServer.serveSSE('/sse', { binding: 'DFIR_MCP' }).fetch(request, env, ctx);
    }

    // Health / info endpoint
    if (url.pathname === '/' || url.pathname === '/health') {
      return Response.json({
        name: 'DFIR-ThreatIntel MCP Server',
        version: '1.0.0',
        tools: 20,
        transport: {
          streamable_http: '/mcp',
          sse: '/sse',
        },
        docs: 'https://github.com/Pranith-Jain/dfir-mcp-server',
      });
    }

    return new Response('Not Found', { status: 404 });
  },
};
