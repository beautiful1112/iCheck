import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import ts from "typescript";

function tsxFiles(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return tsxFiles(path);
    return entry.isFile() && path.endsWith(".tsx") ? [path] : [];
  });
}

const problems = [];
for (const file of [...tsxFiles("app"), ...tsxFiles("components")]) {
  const source = ts.createSourceFile(
    file,
    readFileSync(file, "utf8"),
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TSX,
  );

  function visit(node) {
    if (ts.isJsxElement(node) && ["Link", "a"].includes(node.openingElement.tagName.getText(source))) {
      function inspectChild(child) {
        const tag = ts.isJsxElement(child)
          ? child.openingElement.tagName.getText(source)
          : ts.isJsxSelfClosingElement(child)
            ? child.tagName.getText(source)
            : null;
        if (tag === "Button" || tag === "button") {
          const line = source.getLineAndCharacterOfPosition(child.getStart(source)).line + 1;
          problems.push(`${file}:${line}: link contains a button; use Button asChild around the Link`);
        }
        ts.forEachChild(child, inspectChild);
      }
      node.children.forEach(inspectChild);
    }
    ts.forEachChild(node, visit);
  }

  visit(source);
}

if (problems.length) {
  process.stderr.write(`${problems.join("\n")}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write("No links contain buttons.\n");
}
