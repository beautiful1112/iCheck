import {mcpTools} from "@/lib/studio-library";
import type {Capability} from "@/lib/studio-builder";

export function StudioMCPTools({version}: {version: Capability["versions"][number] | undefined}) {
  const tools = mcpTools(version);
  return <section aria-label="Tools inside this MCP server" className="space-y-2 rounded-lg bg-slate-50 p-3">
    <h3 className="text-sm font-medium">{tools ? `1 MCP server · ${tools.length} ${tools.length === 1 ? "tool" : "tools"}` : "Tool definitions unavailable"}</h3>
    {tools && <ul className="space-y-3 border-l-2 border-violet-200 pl-3">{tools.map(tool => <li key={tool.name}>
      <p className="break-words font-mono text-xs font-medium">{tool.name}</p>
      <p className="text-xs text-slate-500">{tool.operation === "backup" ? "Save a protected configuration backup" : "Read device information"}</p>
      <p className="break-words font-mono text-xs text-slate-500">{tool.commands.join(" · ")}</p>
    </li>)}</ul>}
  </section>;
}
