/**
 * Global test guard. Integration tests create/delete rows and run destructive
 * global cleanups, so they MUST run against a dedicated throwaway database whose
 * name ends in `_test` (e.g. walrus_test). This guard hard-fails the whole run
 * otherwise — the safety net that prevents a `npm test` from ever wiping the dev
 * or production `walrus` database again.
 *
 * The DB is chosen by vitest.config.ts (`TEST_DATABASE_URL` → `DATABASE_URL`);
 * this only validates it.
 */
const url = process.env.DATABASE_URL ?? "";

function databaseName(connectionString: string): string {
  try {
    return new URL(connectionString).pathname.replace(/^\//, "");
  } catch {
    // Fall back to the trailing path segment for non-URL forms.
    const m = /\/([^/?]+)(\?|$)/.exec(connectionString);
    return m ? m[1] : "";
  }
}

const dbName = databaseName(url);

if (!/_test$/.test(dbName)) {
  throw new Error(
    `Refusing to run the test suite against database "${dbName || url || "(unset)"}".\n` +
      `Tests perform destructive writes/deletes and must target a dedicated database whose ` +
      `name ends in "_test" (e.g. walrus_test).\n` +
      `Create it once:  createdb walrus_test\n` +
      `Then run tests normally, or point TEST_DATABASE_URL at your own *_test database.`,
  );
}
