import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { unnamedSelects, scanApplication } from "../scripts/check-accessible-selects.mjs";

test("select names accept ARIA, implicit labels and matching explicit labels", () => {
  assert.deepEqual(unnamedSelects(`<>
    <select aria-label="Tenant" />
    <NativeSelect aria-labelledby="stage-title" />
    <label>Scope<NativeSelect /></label>
    <label htmlFor="provider">Provider</label><select id="provider" />
    <FieldLabel htmlFor="mcp-profile">Profile</FieldLabel><select id="mcp-profile" />
    <label htmlFor={fieldId}>Dynamic</label><select id={fieldId} />
  </>`), []);
});

test("an ID, placeholder, unrelated label or empty ARIA name does not name a select", () => {
  assert.equal(unnamedSelects(`<>
    <select id="alone" />
    <NativeSelect placeholder="Choose" />
    <label htmlFor="other">Other</label><select id="unmatched" />
    <select aria-label=" " /><select aria-label={""} />
    <select aria-label={null} /><select aria-label={undefined} />
    <select aria-label={false} />
  </>`).length, 8);
});

test("conditional and mapped selectors are covered without executing the app", () => {
  const findings = unnamedSelects(`const Page = () => <>
    {enabled && <select />}
    {sources.map(source => <NativeSelect key={source.id} />)}
  </>`, "conditional.tsx");
  assert.deepEqual(findings.map((item) => item.tag), ["select", "NativeSelect"]);
  assert.ok(findings.every((item) => item.filename === "conditional.tsx" && item.line > 1));
});

test("all application selectors have a source-level naming association", () => {
  assert.deepEqual(scanApplication(fileURLToPath(new URL("../app", import.meta.url))), []);
});

function luminance(hex) {
  const values = hex.slice(1).match(/../g).map((part) => parseInt(part, 16) / 255);
  const linear = values.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return linear[0] * 0.2126 + linear[1] * 0.7152 + linear[2] * 0.0722;
}

function contrast(a, b) {
  const [high, low] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (high + 0.05) / (low + 0.05);
}

test("muted tokens retain normal-text contrast on the supported light and dark surfaces", () => {
  const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  const light = css.match(/:root\s*\{[\s\S]*?--muted-foreground:\s*(#[0-9a-f]{6})/)[1];
  const dark = css.match(/\[data-text-surface="dark"\]\s*\{\s*--muted-foreground:\s*(#[0-9a-f]{6})/)[1];
  for (const background of ["#ffffff", "#f3f4f7", "#eef0f5", "#ebedef", "#e9e8fb", "#e2e8f0"]) {
    assert.ok(contrast(light, background) >= 4.5, `${light} on ${background}`);
  }
  for (const background of ["#172133", "#1d283b", "#182134", "#202940", "#303c54", "#36405b"]) {
    assert.ok(contrast(dark, background) >= 4.5, `${dark} on ${background}`);
  }
});

test("desktop, mobile and AI input surfaces opt into the dark text token", () => {
  const home = readFileSync(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.equal((home.match(/data-text-surface="dark"/g) || []).length, 3);
  assert.match(home, /aria-label="Investigation objective or operator context"/);
});

test("the topology canvas uses dark text while its inspector remains a light surface", () => {
  const topology = readFileSync(new URL("../app/topology/page.tsx", import.meta.url), "utf8");
  assert.match(topology, /data-text-surface="dark" className="[^"\n]*bg-\[#172133\]/);
  assert.equal((topology.match(/data-text-surface="dark"/g) || []).length, 1);
});

test("catalog navigation can wrap without clipping its heading or related actions", () => {
  const catalog = readFileSync(new URL("../app/studio/catalog/page.tsx", import.meta.url), "utf8");
  assert.match(catalog, /<header className="[^"\n]*min-h-16[^"\n]*flex-wrap/);
  assert.match(catalog, /<div className="flex flex-wrap items-center gap-2">/);
});

test("the Studio library create action has normal-text contrast", () => {
  const studio = readFileSync(new URL("../components/studio-library.tsx", import.meta.url), "utf8");
  assert.match(studio, /bg-violet-600[^\n]*text-white hover:bg-violet-700/);
  assert.ok(contrast("#ffffff", "#7c3aed") >= 4.5);
  assert.ok(contrast("#ffffff", "#6d28d9") >= 4.5);
});

test("interactive topology exposes full names, selected state and keyboard selection", () => {
  const topology = readFileSync(new URL("../app/topology/page.tsx", import.meta.url), "utf8");
  assert.match(topology, /<svg[^>]*role="group"/);
  assert.doesNotMatch(topology, /<svg[^>]*role="img"/);
  assert.match(topology, /role="button" aria-label=\{`\$\{node\.label\}/);
  assert.match(topology, /aria-pressed=\{active\}/);
  assert.match(topology, /focus-visible:outline-2/);
  assert.match(topology, /event\.key === "Enter" \|\| event\.key === " "[\s\S]*?event\.preventDefault\(\)/);
  assert.match(topology, /fill="var\(--muted-foreground\)"/);
});

test("the selected-node description list groups term/value pairs at one level", () => {
  const topology = readFileSync(new URL("../app/topology/page.tsx", import.meta.url), "utf8");
  const description = topology.match(/<dl className="mt-4 grid grid-cols-2 gap-3 text-xs">([\s\S]*?)<\/dl>/)[1];
  assert.doesNotMatch(description, /<div[^>]*>\s*<div/);
  assert.equal((description.match(/<dt /g) || []).length, 7);
  assert.equal((description.match(/<dd /g) || []).length, 7);
});

test("the retired Services route sends existing bookmarks to Assets", () => {
  const services = readFileSync(new URL("../app/services/page.tsx", import.meta.url), "utf8");
  assert.match(services, /redirect\("\/assets\/devices"\)/);
  assert.doesNotMatch(services, /apiFetch|<button|<Button/);
});

test("AI runtime settings do not present implemented LangGraph paths as a future milestone", () => {
  const settings = readFileSync(new URL("../app/settings/ai/page.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(settings, /M2 foundation|next implementation slice/);
  assert.match(settings, /Provider health does not establish model quality/);
});

test("populated AI success messages and bounded-route badges use readable green", () => {
  const settings = readFileSync(new URL("../app/settings/ai/page.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(settings, /text-\[#1b874b\]/);
  assert.equal((settings.match(/text-\[#166534\]/g) || []).length, 2);
  // Tint #2eb85c at 10% over the page and white card surfaces.
  for (const background of ["#dff1e7", "#eaf8ef"]) {
    assert.ok(contrast("#166534", background) >= 4.5);
  }
});

test("opening a new authoring form cannot publish the previously selected draft", () => {
  const studio = readFileSync(new URL("../app/studio/builder/page.tsx", import.meta.url), "utf8");
  assert.match(studio, /if \(!approved \|\| !canPublish\(selected, principal\)\) return/);
  assert.match(studio, /!selected && !nativeId && <section/);
});

test("the Studio conversation is a named region in normal document flow", () => {
  const studio = readFileSync(new URL("../app/studio/builder/page.tsx", import.meta.url), "utf8");
  assert.match(studio, /<section aria-label="Authoring conversation" className="space-y-3"/);
});

test("device enrollment success and verified/active statuses retain normal-text contrast", () => {
  const devices = readFileSync(new URL("../components/assets-workspace.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(devices, /text-\[#1b874b\]/);
  assert.equal((devices.match(/text-\[#166534\]/g) || []).length, 3);
  assert.ok(contrast("#166534", "#dfeee8") >= 4.5);
});

test("device verification evidence is named and keyboard-scrollable", () => {
  const devices = readFileSync(new URL("../components/assets-workspace.tsx", import.meta.url), "utf8");
  assert.match(devices, /<pre role="region" aria-label=\{`Verification evidence for \$\{device\.name\} \(\$\{connection\.protocol\}\)`\} tabIndex=\{0\} className="[^"\n]*focus-visible:outline-2/);
});

test("all wireless RSSI strengths retain normal-text contrast", () => {
  const endpoints = readFileSync(new URL("../app/assets/endpoints/page.tsx", import.meta.url), "utf8");
  const tone = endpoints.match(/function signalTone\([\s\S]*?\n\}/)[0];
  assert.doesNotMatch(tone, /text-(emerald|amber|red)-600/);
  for (const color of ["#166534", "#92400e", "#991b1b"]) {
    assert.ok(tone.includes(`text-[${color}]`));
    assert.ok(contrast(color, "#ffffff") >= 4.5, `${color} on white`);
  }
});

test("conditional source provenance and acceptance/retirement material have named keyboard regions", () => {
  const qualification = readFileSync(new URL("../app/assets/condition-sources/workspace.tsx", import.meta.url), "utf8");
  const replacement = readFileSync(new URL("../app/assets/condition-sources/replacement-workspace.tsx", import.meta.url), "utf8");
  for (const source of [qualification, replacement]) {
    const panels = source.match(/<pre[^>]+>/g) || [];
    assert.equal(panels.length, 2);
    for (const panel of panels) {
      assert.match(panel, /role="region" aria-label=\{`[^`]+`\} tabIndex=\{0\}/);
      assert.match(panel, /focus-visible:outline-2 focus-visible:outline-offset-2/);
    }
  }
  for (const label of ["Source provenance for", "Proposed source acceptance"]) assert.ok(qualification.includes(label));
  for (const label of ["Source replacement proposal", "Source retirement receipt"]) assert.ok(replacement.includes(label));
});

test("source mapping refresh retains confirmed receipts and periodically expires browser authority", () => {
  const source = readFileSync(new URL("../app/assets/condition-sources/replacement-workspace.tsx", import.meta.url), "utf8");
  assert.ok(source.includes("window.setInterval(() => setNow(Date.now()), 5000)"));
  assert.ok(source.includes("window.clearInterval(timer)"));
  assert.ok(source.includes("setDetail(data); setRequestId(data.request.id); remember(data)"));
  assert.ok(source.includes("setDetail(updated); remember(updated)"));
  assert.ok(source.includes("Cutover is confirmed by the retained receipt"));
  assert.ok(source.includes("executorIndependent:Boolean(identity?.principal_id&&detail.review?.reviewer_principal_id"));
});

test("rich collector editors and uploads have separate stable accessible names", () => {
  const source = readFileSync(new URL("../app/studio/builder/page.tsx", import.meta.url), "utf8");
  assert.match(source, /<label[^>]*>Sanitized response, definition or command output<Textarea/);
  assert.match(source, /aria-label="Upload source document"/);
  assert.match(source, /<label[^>]*>Vendor MIB bundle and dependencies<input/);
});

test("Studio uses native details for advanced contract review outside the library", () => {
  const source = readFileSync(new URL("../app/studio/builder/page.tsx", import.meta.url), "utf8");
  assert.match(source, /<details><summary className="cursor-pointer text-sm">Advanced definition, validation, permissions and history/);
});

test("enabled MCP activation has normal-text contrast in default and hover states", () => {
  const source = readFileSync(new URL("../app/settings/mcp/page.tsx", import.meta.url), "utf8");
  assert.match(source, /className="w-full bg-\[#047857\] text-white hover:bg-\[#065f46\]"/);
  assert.ok(contrast("#ffffff", "#047857") >= 4.5);
  assert.ok(contrast("#ffffff", "#065f46") >= 4.5);
});

test("MCP activation and recovery revalidate freshness beyond discovery refresh", () => {
  const source = readFileSync(new URL("../app/settings/mcp/page.tsx", import.meta.url), "utf8");
  assert.match(source, /setInterval\(\(\) => setClockNow\(Date\.now\(\)\), 5000\)/);
  assert.match(source, /window\.clearInterval\(timer\)/);
  assert.match(source, /!selectedAttestationFresh/);
  assert.match(source, /mcpAttestationIsFresh\(attestations\.find/);
  assert.match(source, /mcpAttestationIsFresh\(fresh, activation\.server_id, activation\.artifact_version_id\)/);
});
