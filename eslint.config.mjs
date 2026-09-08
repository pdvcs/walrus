import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist/**", "node_modules/**", "src/static/**"] },
  ...tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        project: "./tsconfig.eslint.json",
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // Overly strict for a backend service — relax these
      "@typescript-eslint/no-explicit-any": "warn",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_" }],

      // WAL-120. pino runs its error serializer on the `err` key and no other. An Error
      // under any other key is serialized as a plain object, and Error's `message` and
      // `stack` are non-enumerable -- so `log.error({ error }, "...")` emits `"error": {}`
      // and the exception is gone. It reads as if it logged something.
      //
      // The downstream cost is larger than the log line: Cloud Error Reporting groups by
      // stack trace, so a record with no stack enters no group and appears in no count.
      // Four auth-path sites did this, including both audit-failure logs.
      //
      // Matched on the method name rather than the receiver so `this.log.error(...)` is
      // covered too. The rule is not "never name a variable `error`" -- it is "pino only
      // serializes `err`".
      //
      // Restricted to an *identifier* value (`{ error }` or `{ error: e }`), which is the shape
      // that carries a live Error. A key built from one -- `String(err)`, `err.message`,
      // `result.error` -- is already a string and loses nothing, so flagging it would be noise:
      // the first draft of this rule matched 11 sites, and 7 of them were exactly that.
      // Syntax cannot tell an Error from a string, so this approximates it by shape; the
      // remaining invariant is that a log key named `error` always holds an Error.
      "no-restricted-syntax": [
        "error",
        {
          selector:
            'CallExpression[callee.property.name=/^(trace|debug|info|warn|error|fatal)$/] > ObjectExpression > Property[key.name="error"][value.type="Identifier"]',
          message:
            "pino serializes only the `err` key: an Error logged under `error` becomes {}, losing message and stack (and its Error Reporting group). Use { err } (WAL-120).",
        },
      ],
    },
  },
  {
    // Test files exercise the app through untyped JSON (supertest `res.body`,
    // `JSON.parse` of fixtures, ad-hoc `pool.query`). The type-checked "unsafe"
    // family is noise here — src/ stays strict.
    files: ["tests/**/*.ts"],
    rules: {
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-return": "off",
      "@typescript-eslint/require-await": "off",
      "@typescript-eslint/restrict-template-expressions": "off",
    },
  },
);
