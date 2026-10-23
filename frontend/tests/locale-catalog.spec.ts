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

test("every source-language message and backend error has an English translation", () => {
  const catalog: Record<string, string> = english;
  const required = new Set<string>(Object.values(messages));
  function read(directory: string) {
    for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
      const filename = path.join(directory, item.name);
      if (item.isDirectory()) read(filename);
      else if (/\.tsx?$/.test(filename)) {
        const source = parse(fs.readFileSync(filename, "utf8"), {
          sourceType: "module",
          plugins: ["typescript", "jsx"],
        });
        function visit(value: unknown) {
          if (!value || typeof value !== "object") return;
          if (Array.isArray(value)) {
            value.forEach(visit);
            return;
          }
          const node = value as {
            type?: string;
            callee?: { type: string; name: string };
            arguments?: { type: string; value: string }[];
          };
          if (
            node.type === "CallExpression" &&
            node.callee?.type === "Identifier" &&
            node.callee.name === "t" &&
            node.arguments?.[0]?.type === "StringLiteral"
          )
            required.add(node.arguments[0].value);
          Object.values(value).forEach(visit);
        }
        visit(source);
      }
    }
  }
  read(path.resolve("src"));
  for (const key of required) {
    expect(catalog[key], key).toBeDefined();
    expect(catalog[key], key).not.toMatch(/[\u3400-\u9fff]/);
    expect(
      [...catalog[key].matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort(),
      key,
    ).toEqual([...key.matchAll(/\{\{(\w+)\}\}/g)].map((m) => m[1]).sort());
  }
});
