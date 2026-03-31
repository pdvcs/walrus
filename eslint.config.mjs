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
    },
  },
);
