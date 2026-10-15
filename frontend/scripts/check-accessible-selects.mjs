import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

function attributeValue(opening, name, source) {
  const attr = opening.attributes.properties.find(
    (item) => ts.isJsxAttribute(item) && item.name.getText(source) === name,
  );
  if (!attr?.initializer) return null;
  if (ts.isStringLiteral(attr.initializer)) {
    return attr.initializer.text.trim() ? `literal:${attr.initializer.text}` : null;
  }
  const expression = attr.initializer.expression;
  if (!expression) return null;
  if (ts.isStringLiteral(expression)) {
    return expression.text.trim() ? `literal:${expression.text}` : null;
  }
  const text = expression.getText(source);
  return ["null", "undefined", "false"].includes(text) ? null : `expression:${text}`;
}

// A narrow source guard, not a replacement for rendered accessibility checks.
// NativeSelect wraps a native select and must receive its own accessible name.
export function unnamedSelects(text, filename = "page.tsx") {
  const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const labels = new Set();
  const controls = [];
  function visit(node) {
    if (ts.isJsxOpeningElement(node) || ts.isJsxSelfClosingElement(node)) {
      const name = node.tagName.getText(source);
      if (["label", "FieldLabel"].includes(name)) {
        const target = attributeValue(node, "htmlFor", source);
        if (target) labels.add(target);
      }
      if (["select", "NativeSelect"].includes(name)) controls.push(node);
    }
    ts.forEachChild(node, visit);
  }
  visit(source);
  return controls.filter((node) => {
    if (attributeValue(node, "aria-label", source) || attributeValue(node, "aria-labelledby", source)) return false;
    const id = attributeValue(node, "id", source);
    if (id && labels.has(id)) return false;
    for (let parent = node.parent; parent; parent = parent.parent) {
      if (ts.isJsxElement(parent) && parent.openingElement.tagName.getText(source) === "label") return false;
    }
    return true;
  }).map((node) => ({
    filename,
    line: source.getLineAndCharacterOfPosition(node.getStart(source)).line + 1,
    tag: node.tagName.getText(source),
  }));
}

export function scanApplication(directory) {
  const failures = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const filename = path.join(directory, entry.name);
    if (entry.isDirectory()) failures.push(...scanApplication(filename));
    else if (filename.endsWith(".tsx")) failures.push(...unnamedSelects(readFileSync(filename, "utf8"), filename));
  }
  return failures;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const failures = scanApplication(fileURLToPath(new URL("../app", import.meta.url)));
  for (const item of failures) console.error(`${item.filename}:${item.line}: ${item.tag} needs an accessible name`);
  if (failures.length) process.exitCode = 1;
  else console.log("Accessible select source guard passed (rendered GUI checks still required)");
}
