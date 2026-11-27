import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";
import { parse } from "@babel/parser";
const english = JSON.parse(
  fs.readFileSync(path.resolve("src/locales/en.json"), "utf8"),
) as Record<string, string>;
const messages = JSON.parse(
  fs.readFileSync(path.resolve("src/messages.json"), "utf8"),
) as Record<string, string>;

function files(directory: string, extension: RegExp): string[] {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((item) => {
    const filename = path.join(directory, item.name);
    return item.isDirectory()
      ? files(filename, extension)
      : extension.test(filename)
        ? [filename]
        : [];
  });
}

test("every source-language message and backend error has an English translation", () => {
  const catalog: Record<string, string> = english;
  const required = new Set<string>(Object.values(messages));
  for (const filename of files("src", /\.tsx?$/)) {
    const source = parse(fs.readFileSync(filename, "utf8"), {
      sourceType: "module",
      plugins: ["typescript", "jsx"],
    });
    function visit(value: unknown) {
      if (!value || typeof value !== "object") return;
      if (Array.isArray(value)) return value.forEach(visit);
      const node = value as {
        type?: string;
        value?: string;
        callee?: { type: string; name: string };
        arguments?: { type: string; value: string }[];
      };
      if (
        node.type === "CallExpression" &&
        node.callee?.type === "Identifier" &&
        node.callee.name === "t" &&
        node.arguments?.[0]?.type === "StringLiteral"
      ) {
        required.add(node.arguments[0].value);
      }
      if (
        node.type === "StringLiteral" &&
        node.value &&
        /[\u3400-\u9fff]/.test(node.value) &&
        !(filename.endsWith("language-switcher.tsx") && node.value === "中文")
      ) {
        required.add(node.value);
      }
      if (
        node.type === "JSXText" &&
        node.value &&
        /[\u3400-\u9fff]/.test(node.value)
      ) {
        expect(filename).toBe(
          path.join("src", "components", "filing-link.tsx"),
        );
      }
      Object.values(value).forEach(visit);
    }
    visit(source);
  }
  for (const key of required) {
    expect(catalog[key], key).toBeDefined();
    expect(catalog[key], key).not.toMatch(/[\u3400-\u9fff]/);
    expect(
      [...catalog[key].matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort(),
      key,
    ).toEqual([...key.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort());
  }
});

test("browser error codes emitted by the backend have localized messages", () => {
  const backend = path.resolve("..", "services", "user-center", "src");
  for (const directory of ["web", "service"]) {
    for (const filename of files(path.join(backend, directory), /\.rs$/)) {
      if (/_tests?\.rs$/.test(filename)) continue;
      const source = fs.readFileSync(filename, "utf8");
      for (const [, code] of source.matchAll(
        /\b(?:Invalid|json_error|json_ok_with_error)\(\s*"([a-z][a-z_0-9]+)"/g,
      )) {
        expect(
          messages[code],
          `${path.basename(filename)}: ${code}`,
        ).toBeDefined();
      }
    }
  }
});
