import { readFileSync } from "fs";
import { join } from "path";
import { Router, Request, Response } from "express";

const API_DOCS_MARKDOWN = readFileSync(join(__dirname, "api-docs.md"), "utf8");

function renderMarkdownToHtml(md: string): string {
  const lines = md.split("\n");
  const out: string[] = [];
  let inCodeBlock = false;
  let inTable = false;
  let tableHeaderDone = false;
  let inList = false;
  let paraLines: string[] = [];

  const inline = (s: string) =>
    s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(
        /\[([^\]]+)\]\(([^)]+)\)/g,
        '<a href="$2" target="_blank" rel="noopener noreferrer">$1</a>',
      );

  const flushPara = () => {
    if (paraLines.length > 0) {
      out.push(`<p>${paraLines.map(inline).join(" ")}</p>`);
      paraLines = [];
    }
  };

  const flushBlock = () => {
    flushPara();
    if (inList) {
      out.push("</ul>");
      inList = false;
    }
    if (inTable) {
      out.push("</tbody></table>");
      inTable = false;
      tableHeaderDone = false;
    }
  };

  for (const line of lines) {
    if (line.startsWith("```")) {
      flushBlock();
      inCodeBlock = !inCodeBlock;
      out.push(inCodeBlock ? "<pre><code>" : "</code></pre>");
      continue;
    }

    if (inCodeBlock) {
      out.push(line.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"));
      continue;
    }

    if (line.startsWith("### ")) {
      flushBlock();
      out.push(`<h3>${inline(line.slice(4))}</h3>`);
      continue;
    }
    if (line.startsWith("## ")) {
      flushBlock();
      out.push(`<h2>${inline(line.slice(3))}</h2>`);
      continue;
    }
    if (line.startsWith("# ")) {
      flushBlock();
      out.push(`<h1>${inline(line.slice(2))}</h1>`);
      continue;
    }

    if (line.trim() === "---") {
      flushBlock();
      out.push("<hr>");
      continue;
    }

    if (line.startsWith("|")) {
      flushPara();
      if (inList) {
        out.push("</ul>");
        inList = false;
      }
      if (!inTable) {
        out.push("<table><thead>");
        inTable = true;
        tableHeaderDone = false;
      }
      if (line.replace(/\|/g, "").trim().replace(/-/g, "").trim() === "") {
        out.push("</thead><tbody>");
        tableHeaderDone = true;
        continue;
      }
      const cells = line
        .split("|")
        .slice(1, -1)
        .map((c) => c.trim());
      const tag = tableHeaderDone ? "td" : "th";
      out.push("<tr>" + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join("") + "</tr>");
      continue;
    }

    if (inTable) {
      out.push("</tbody></table>");
      inTable = false;
      tableHeaderDone = false;
    }

    if (line.startsWith("- ")) {
      flushPara();
      if (!inList) {
        out.push("<ul>");
        inList = true;
      }
      out.push(`<li>${inline(line.slice(2))}</li>`);
      continue;
    }

    if (inList) {
      out.push("</ul>");
      inList = false;
    }

    if (line.trim() === "") {
      flushPara();
      continue;
    }

    paraLines.push(line);
  }

  flushBlock();

  return out.join("\n");
}

function renderApiDocsHtml(markdown: string): string {
  const body = renderMarkdownToHtml(markdown);
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Walrus API Docs</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: #f5f5f5; color: #222; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; font-size: 14px; line-height: 1.6; }
    .nav { background: #fff; border-bottom: 1px solid #e5e7eb; padding: 12px 24px; display: flex; gap: 24px; align-items: center; }
    .nav a { color: #6b7280; text-decoration: none; font-size: 0.9rem; }
    .nav a:hover { color: #111; }
    .nav .brand { font-weight: 800; font-size: 1.05rem; color: #111; }
    .content { max-width: 860px; margin: 0 auto; padding: 32px 24px; }
    h1 { font-size: 22px; margin-bottom: 20px; }
    h2 { font-size: 16px; margin: 32px 0 12px; border-bottom: 1px solid #e5e7eb; padding-bottom: 6px; color: #111; }
    h3 { font-size: 13px; margin: 24px 0 8px; color: #1d4ed8; font-family: "SFMono-Regular", Consolas, monospace; }
    p { margin: 8px 0; }
    hr { border: none; border-top: 1px solid #e5e7eb; margin: 24px 0; }
    pre { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px 16px; overflow-x: auto; margin: 10px 0; }
    code { font-family: "SFMono-Regular", Consolas, monospace; font-size: 13px; }
    p code, li code { background: #f3f4f6; padding: 1px 5px; border-radius: 4px; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden; margin: 10px 0; font-size: 13px; }
    th { background: #f9fafb; font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; color: #6b7280; padding: 9px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; }
    td { padding: 8px 12px; border-bottom: 1px solid #f3f4f6; }
    ul { margin: 8px 0 8px 20px; }
    li { margin: 3px 0; }
    a { color: #1d4ed8; text-decoration: none; }
    p a, li a { background: #aa80ff; border: 1px solid #2a0080; color: #fff; padding: 1px 8px; border-radius: 4px; font-size: 12px; font-weight: 500; white-space: nowrap; }
    p a:hover, li a:hover { color: #444; background: #dbeafe; border-color: #93c5fd; }
  </style>
</head>
<body>
  <nav class="nav">
    <span class="brand">Walrus</span>
    <a href="/api" style="color:#111;font-weight:700">API Docs</a>
    <a href="/admin/v1/">Admin UI</a>
    <a href="/health">Health</a>
  </nav>
  <div class="content">
    ${body}
  </div>
</body>
</html>`;
}

export function createApiDocsRouter(): Router {
  const router = Router();
  router.get("/", (req: Request, res: Response) => {
    if (req.headers.accept?.includes("text/html")) {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderApiDocsHtml(API_DOCS_MARKDOWN));
    } else {
      res.setHeader("Content-Type", "text/markdown; charset=utf-8");
      res.send(API_DOCS_MARKDOWN);
    }
  });
  return router;
}
