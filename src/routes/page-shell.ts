export type AdminNavItem = "packages" | "jobs" | "validate" | "vulns";

export const BASE_PAGE_STYLES = `
  *, *::before, *::after { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f5f5f5; color: #222; }
  a { color: #1d4ed8; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .nav { display: flex; align-items: center; gap: 24px; flex-wrap: wrap; background: #fff; border-bottom: 1px solid #e5e7eb; padding: 12px 24px; margin-bottom: 24px; }
  .nav .brand { font-weight: 800; font-size: 1.05rem; color: #111; }
  .nav a { font-size: 0.9rem; color: #6b7280; text-decoration: none; }
  .nav a:hover { color: #111; }
  .nav a.active { color: #111; font-weight: 700; }
  .nav-spacer { flex: 1 1 24px; }
  .nav form { display: inline; margin: 0; }
  .nav-link { appearance: none; border: 0; padding: 0; background: transparent; color: #6b7280; cursor: pointer; font: inherit; font-size: 0.9rem; }
  .nav-link:hover { color: #111; text-decoration: underline; }
  .wrap { width: 100%; max-width: 1100px; margin: 0 auto; padding: 24px; }
  h1 { margin: 0 0 16px; font-size: 1.4rem; }
  h2 { margin: 0 0 8px; font-size: 1rem; }
  p { line-height: 1.55; }
  .panel { max-width: 520px; margin: 48px auto; padding: 28px; background: #fff; border: 1px solid #e5e7eb; border-radius: 10px; box-shadow: 0 8px 28px rgb(15 23 42 / 0.06); }
  .meta { color: #6b7280; font-size: 0.85rem; }
  .field { display: grid; gap: 6px; margin-top: 16px; }
  .field label { font-size: 0.82rem; font-weight: 700; color: #374151; }
  input, textarea { width: 100%; border: 1px solid #d1d5db; border-radius: 6px; padding: 9px 10px; color: #222; background: #fff; font: inherit; }
  input:focus, textarea:focus { border-color: #1d4ed8; outline: 3px solid #dbeafe; }
  textarea { resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.8rem; }
  .actions { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin-top: 20px; }
  .btn { display: inline-block; border: 0; border-radius: 6px; padding: 8px 14px; cursor: pointer; font: inherit; font-size: 0.85rem; font-weight: 700; text-decoration: none; }
  .btn:hover { text-decoration: none; }
  .btn-primary { background: #1d4ed8; color: #fff; }
  .btn-primary:hover { background: #1e40af; }
  .btn-secondary { background: #e5e7eb; color: #374151; }
  .btn-secondary:hover { background: #d1d5db; }
  .alert { margin: 0 0 16px; padding: 10px 12px; border-radius: 6px; font-size: 0.85rem; }
  .alert-error { background: #fee2e2; color: #991b1b; }
  .alert-success { background: #dcfce7; color: #166534; }
  .hero { padding: 56px 0 36px; }
  .hero h1 { font-size: clamp(2.2rem, 7vw, 4rem); letter-spacing: -0.04em; margin-bottom: 8px; }
  .version { display: inline-block; margin-bottom: 20px; padding: 3px 9px; border-radius: 999px; background: #e5e7eb; color: #4b5563; font: 600 0.78rem ui-monospace, SFMono-Regular, Menlo, monospace; }
  .hero-copy { max-width: 680px; color: #4b5563; font-size: 1.05rem; }
  .link-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 14px; margin-top: 28px; }
  .link-card { display: block; padding: 18px; border: 1px solid #e5e7eb; border-radius: 8px; background: #fff; color: #222; }
  .link-card:hover { border-color: #93c5fd; text-decoration: none; }
  .link-card strong { display: block; margin-bottom: 5px; }
  .link-card span { color: #6b7280; font-size: 0.85rem; line-height: 1.4; }
  @media (max-width: 640px) {
    .nav { gap: 14px; padding: 12px 16px; }
    .wrap { padding: 16px; }
    .panel { margin: 20px auto; padding: 22px; }
    .hero { padding-top: 32px; }
  }
`;

export function renderAdminNav(active?: AdminNavItem): string {
  return `<nav class="nav" aria-label="Admin navigation">
    <a class="brand" href="/">Walrus</a>
    <a href="/admin/v1/"${active === "packages" ? ' class="active"' : ""}>Packages</a>
    <a href="/admin/v1/jobs"${active === "jobs" ? ' class="active"' : ""}>Jobs</a>
    <a href="/admin/v1/validate"${active === "validate" ? ' class="active"' : ""}>Validate TOML</a>
    <a href="/admin/v1/vulns"${active === "vulns" ? ' class="active"' : ""}>Vulnerabilities</a>
    <a href="/api">API Docs</a>
    <a href="/app/status">Status</a>
    <span class="nav-spacer"></span>
    <form method="post" action="/admin/v1/tokens"><button class="nav-link" type="submit">API token</button></form>
    <form method="post" action="/admin/v1/logout"><button class="nav-link" type="submit">Log out</button></form>
  </nav>`;
}

export function renderPublicNav(): string {
  return `<nav class="nav" aria-label="Site navigation">
    <a class="brand" href="/">Walrus</a>
    <span class="nav-spacer"></span>
    <a href="/api">API Docs</a>
    <a href="/app/status">Status</a>
    <a href="/admin/v1/login?return_to=%2Fadmin%2Fv1%2F">Admin login</a>
  </nav>`;
}

export function renderPage(options: {
  title: string;
  nav: string;
  body: string;
  extraStyles?: string;
}): string {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(options.title)}</title>
  <style>${BASE_PAGE_STYLES}${options.extraStyles ?? ""}</style>
</head>
<body>
  ${options.nav}
  <main class="wrap">${options.body}</main>
</body>
</html>`;
}

export function renderLandingPage(version: string): string {
  const safeVersion = escapeHtml(version);
  return renderPage({
    title: "Walrus",
    nav: renderPublicNav(),
    body: `<section class="hero">
      <span class="version">v${safeVersion}</span>
      <h1>Walrus</h1>
      <p class="hero-copy">A policy-aware package ingress service for discovering, verifying, retaining, and serving trusted software artifacts.</p>
      <div class="actions">
        <a class="btn btn-primary" href="/admin/v1/login?return_to=%2Fadmin%2Fv1%2F">Log in as admin</a>
        <a class="btn btn-secondary" href="/api">Browse API documentation</a>
      </div>
      <div class="link-grid">
        <a class="link-card" href="/health"><strong>Deployment health</strong><span>Minimal availability contract for the deployment platform.</span></a>
        <a class="link-card" href="/app/status"><strong>Application status</strong><span>Operational details, dependency state, and degradations.</span></a>
        <a class="link-card" href="/openapi.json"><strong>OpenAPI specification</strong><span>Machine-readable public API contract.</span></a>
      </div>
    </section>`,
  });
}

export function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
