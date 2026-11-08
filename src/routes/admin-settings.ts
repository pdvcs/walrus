import { Router } from "express";
import { renderSharedHtml, escHtml } from "./admin.js";
import { withBase } from "../common/base-path.js";
import {
  SETTING_NAME_MAX_LENGTH,
  SETTING_NAME_PATTERN,
  SETTING_VALUE_MAX_LENGTH,
  type SettingRow,
} from "../db/queries/settings.js";

export interface AdminSettingsRouteDeps {
  listSettings: () => Promise<SettingRow[]>;
  upsertSetting: (input: {
    name: string;
    value: string;
    updated_by: string;
  }) => Promise<{ setting: SettingRow; created: boolean }>;
  deleteSetting: (name: string) => Promise<boolean>;
  /** Audit trail. Receives the setting name but never its value, which may be sensitive. */
  logAdminAction: (
    actionType: string,
    details: Record<string, unknown>,
    subject?: string,
  ) => Promise<void>;
}

/**
 * Admin settings: operator-managed name/text pairs (/admin/v1/settings). The page is
 * server-rendered; add/edit/delete go through the JSON endpoints below via fetch, so scripts
 * and the UI share one validated write path.
 */
export function createAdminSettingsRouter(deps: AdminSettingsRouteDeps, basePath: string): Router {
  const router = Router();

  router.get("/settings", async (_req, res, next) => {
    try {
      const settings = await deps.listSettings();
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.send(renderSettingsPage(settings, basePath));
    } catch (err) {
      next(err);
    }
  });

  router.get("/settings.json", async (_req, res, next) => {
    try {
      res.json({ settings: await deps.listSettings() });
    } catch (err) {
      next(err);
    }
  });

  router.put("/settings/:name", async (req, res, next) => {
    try {
      const name = req.params.name;
      const nameError = validateName(name);
      if (nameError) return void res.status(400).json({ error: nameError });

      const raw = ((req.body ?? {}) as Record<string, unknown>).value;
      if (typeof raw !== "string") {
        return void res.status(400).json({ error: "value must be a string" });
      }
      // Pasted keys routinely carry a trailing newline or leading space; neither is meaningful
      // and both break exact-match comparisons in whatever consumes the setting.
      const value = raw.trim();
      if (value.length === 0) {
        return void res.status(400).json({ error: "value must be a non-empty string" });
      }
      if (value.length > SETTING_VALUE_MAX_LENGTH) {
        return void res
          .status(400)
          .json({ error: `value must be at most ${SETTING_VALUE_MAX_LENGTH} characters` });
      }

      const subject = req.auth?.subject;
      if (!subject) return void res.status(401).json({ error: "Authentication required" });

      const { setting, created } = await deps.upsertSetting({
        name,
        value,
        updated_by: subject,
      });
      await deps.logAdminAction(created ? "setting-created" : "setting-updated", { name }, subject);
      res.status(created ? 201 : 200).json({ setting, created });
    } catch (err) {
      next(err);
    }
  });

  router.delete("/settings/:name", async (req, res, next) => {
    try {
      const name = req.params.name;
      const nameError = validateName(name);
      if (nameError) return void res.status(400).json({ error: nameError });
      const deleted = await deps.deleteSetting(name);
      if (!deleted) return void res.status(404).json({ error: "Setting not found" });
      await deps.logAdminAction("setting-deleted", { name }, req.auth?.subject);
      res.json({ name, deleted: true });
    } catch (err) {
      next(err);
    }
  });

  return router;
}

function validateName(name: string): string | null {
  if (name.length > SETTING_NAME_MAX_LENGTH) {
    return `name must be at most ${SETTING_NAME_MAX_LENGTH} characters`;
  }
  if (!SETTING_NAME_PATTERN.test(name)) {
    return "name must start with a lowercase letter and contain only lowercase letters, digits and underscores";
  }
  return null;
}

export function renderSettingsPage(settings: SettingRow[], basePath: string): string {
  const esc = escHtml;
  const fmt = (d: Date): string => new Date(d).toISOString().replace("T", " ").slice(0, 19) + "Z";

  const rows = settings
    .map(
      (s) => `<tr data-name="${esc(s.name)}">
        <td><code>${esc(s.name)}</code></td>
        <td><div class="setting-value">${esc(s.value)}</div></td>
        <td class="meta">${esc(s.updated_by)}<br>${esc(fmt(s.updated_at))}</td>
        <td style="white-space:nowrap">
          <button class="btn btn-sm btn-secondary" data-action="edit">Edit</button>
          <button class="btn btn-sm btn-danger" data-action="delete">Delete</button>
        </td>
      </tr>`,
    )
    .join("");

  const table =
    settings.length === 0
      ? `<p class="empty">No settings yet. Add one below.</p>`
      : `<table><thead><tr><th>Name</th><th>Value</th><th>Last updated</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;

  const body = `
    <style>
      .setting-value { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; max-height: 7.5em; overflow: auto; }
      .setting-form { background: #fff; border: 1px solid #e5e7eb; border-radius: 8px; padding: 16px 20px; margin-top: 24px; }
      .setting-form label { display: block; font-size: 0.85rem; font-weight: 600; color: #374151; margin: 12px 0 4px; }
      .setting-form label:first-of-type { margin-top: 0; }
      .setting-form input[readonly] { background: #f3f4f6; color: #6b7280; }
      #setting-status { font-size: 0.82rem; color: #6b7280; }
      #setting-status.error { color: #b91c1c; }
    </style>
    <h1>Settings</h1>
    <p class="meta" style="margin-bottom:8px">Named text values the application reads at runtime, for example <code>registry_public_key</code>. Values are shown in full to every admin, so do not store secrets here.</p>
    ${table}
    <form class="setting-form" id="setting-form">
      <h2 id="form-title" style="margin-bottom:12px">Add a setting</h2>
      <label for="setting-name">Name</label>
      <input id="setting-name" name="name" required maxlength="${SETTING_NAME_MAX_LENGTH}" pattern="[a-z][a-z0-9_]*" placeholder="registry_public_key" autocomplete="off" spellcheck="false">
      <p class="meta" style="margin-top:4px">Lowercase letters, digits and underscores; must start with a letter.</p>
      <label for="setting-value">Value</label>
      <textarea id="setting-value" name="value" required rows="6" maxlength="${SETTING_VALUE_MAX_LENGTH}" spellcheck="false"></textarea>
      <p class="meta" style="margin-top:4px">Leading and trailing whitespace is removed. Saving an existing name replaces its value.</p>
      <div style="display:flex;gap:10px;align-items:center;margin-top:14px">
        <button type="submit" class="btn btn-primary" id="setting-save">Save setting</button>
        <button type="button" class="btn btn-secondary" id="setting-cancel" hidden>Cancel edit</button>
        <span id="setting-status" role="status"></span>
      </div>
    </form>`;

  const rawTail = `
<script>
(() => {
  const base = ${JSON.stringify(withBase(basePath, "/admin/v1/settings"))};
  const form = document.getElementById("setting-form");
  const nameEl = document.getElementById("setting-name");
  const valueEl = document.getElementById("setting-value");
  const statusEl = document.getElementById("setting-status");
  const cancelEl = document.getElementById("setting-cancel");
  const titleEl = document.getElementById("form-title");

  function say(msg, isError) {
    statusEl.textContent = msg;
    statusEl.className = isError ? "error" : "";
  }

  function resetForm() {
    form.reset();
    nameEl.readOnly = false;
    cancelEl.hidden = true;
    titleEl.textContent = "Add a setting";
  }

  async function call(method, name, payload) {
    const r = await fetch(base + "/" + encodeURIComponent(name), {
      method,
      headers: { "Content-Type": "application/json" },
      body: payload ? JSON.stringify(payload) : undefined,
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || "Request failed (" + r.status + ")");
    return data;
  }

  document.querySelectorAll("tr[data-name]").forEach((row) => {
    const name = row.dataset.name;
    row.querySelector('[data-action="edit"]').addEventListener("click", () => {
      nameEl.value = name;
      nameEl.readOnly = true;
      valueEl.value = row.querySelector(".setting-value").textContent;
      cancelEl.hidden = false;
      titleEl.textContent = "Edit " + name;
      say("", false);
      valueEl.focus();
      form.scrollIntoView({ behavior: "smooth", block: "nearest" });
    });
    row.querySelector('[data-action="delete"]').addEventListener("click", async () => {
      if (!confirm("Delete setting '" + name + "'? Anything that reads it will stop finding it.")) return;
      try {
        await call("DELETE", name);
        location.reload();
      } catch (err) {
        say(err.message, true);
      }
    });
  });

  cancelEl.addEventListener("click", () => { resetForm(); say("", false); });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const btn = document.getElementById("setting-save");
    btn.disabled = true;
    say("Saving…", false);
    try {
      await call("PUT", nameEl.value.trim(), { value: valueEl.value });
      location.reload();
    } catch (err) {
      say(err.message, true);
      btn.disabled = false;
    }
  });
})();
</script>`;

  return renderSharedHtml("Settings", "settings", body, basePath, "", rawTail);
}
