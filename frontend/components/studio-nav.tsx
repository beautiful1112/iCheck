import Link from "next/link";

export function StudioNav({current}: {current: "library" | "conversations" | "builder" | "mcp"}) {
  return <nav aria-label="Capability Studio" className="flex flex-wrap items-center gap-x-5 gap-y-3 border-b border-slate-200 pb-4 text-sm">
    <Link href="/" className="mr-auto text-slate-500">← AI Operator</Link>
    {([{id: "library", href: "/studio", label: "Library"}, {id: "conversations", href: "/studio/conversations", label: "Conversations"},
      {id: "builder", href: "/studio/builder", label: "Create capability"}] as const).map(item => item.id === "builder" ? <a key={item.id} href={item.href} className="text-slate-600 hover:text-violet-700">{item.label}</a> : <Link key={item.id} href={item.href}
        aria-current={current === item.id ? "page" : undefined} className={current === item.id ? "font-semibold text-violet-700" : "text-slate-600 hover:text-violet-700"}>{item.label}</Link>)}
  </nav>;
}
