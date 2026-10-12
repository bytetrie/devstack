// ESLint configuration, scaffolded by devstack. `pnpm lint` checks the whole project (CI should run
// it as a blocking check), `pnpm lint:changed` only what changed since the last commit, and
// `pnpm check` adds the type check. Warnings fail too (--max-warnings 0).
//
// This project has no separate static-analysis tool (Semgrep, Opengrep), so the unsafe patterns
// are caught here, and the rules are strict on purpose. Turning one off, here or with an
// `eslint-disable` comment, needs the reason written next to it (`-- why`); AGENTS.md has the rules.
import js from "@eslint/js";
import comments from "@eslint-community/eslint-plugin-eslint-comments/configs";
import { defineConfig, globalIgnores } from "eslint/config";
import nounsanitized from "eslint-plugin-no-unsanitized";
import security from "eslint-plugin-security";
import globals from "globals";
import tseslint from "typescript-eslint";

// The one module that may import child_process. Every process launch goes through it: execFile or
// spawn with an argument array, never `shell: true`, never a command string built from input.
const CHILD_PROCESS_WRAPPER = "src/lib/child-process.ts";
const viaWrapper = `start processes through ${CHILD_PROCESS_WRAPPER} only`;

// Code built from strings at run time: eval, setTimeout("...") and the Function constructor.
const noDynamicCode = {
  "no-eval": "error",
  "no-implied-eval": "error",
  "no-new-func": "error",
};

const childProcessOnlyInWrapper = {
  "no-restricted-imports": ["error", {
    paths: [
      { name: "child_process", message: viaWrapper },
      { name: "node:child_process", message: viaWrapper },
    ],
  }],
  "no-restricted-syntax": ["error", {
    selector: "ImportExpression[source.value=/^(node:)?child_process$/]",
    message: viaWrapper,
  }],
};

export default defineConfig(
  globalIgnores(["dist/", "coverage/"]),
  {
    linterOptions: {
      reportUnusedDisableDirectives: "error",
      reportUnusedInlineConfigs: "error",
    },
  },

  // Every `eslint-disable` needs a reason after `--`, and may not switch off everything at once.
  comments.recommended,
  {
    rules: {
      "@eslint-community/eslint-comments/require-description": ["error", { ignore: ["eslint-enable"] }],
    },
  },

  // Server and scripts (TypeScript, Node): type-aware.
  {
    files: ["**/*.ts"],
    extends: [js.configs.recommended, tseslint.configs.strictTypeChecked, security.configs.recommended],
    languageOptions: {
      globals: globals.node,
      parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname },
    },
    rules: {
      "no-eval": "error",
      "no-new-func": "error",
      "@typescript-eslint/no-implied-eval": "error", // the preset's type-aware no-implied-eval
      ...childProcessOnlyInWrapper,
      // Already errors in strict-type-checked; listed so that loosening the preset can't drop them.
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unsafe-argument": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-declaration-merging": "error",
      "@typescript-eslint/no-unsafe-enum-assignment": "error",
      "@typescript-eslint/no-unsafe-enum-comparison": "error",
      "@typescript-eslint/no-unsafe-function-type": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",
      "@typescript-eslint/no-unsafe-unary-minus": "error",
      // Not in the preset. A cast that narrows a type (`JSON.parse(body) as User`) is a claim
      // nothing checks: validate the data instead, or disable this line with the reason it is safe.
      "@typescript-eslint/no-unsafe-type-assertion": "error",
      // `{ ... } as T` hides missing fields; annotate instead (`const x: T = { ... }`).
      "@typescript-eslint/consistent-type-assertions": ["error", {
        assertionStyle: "as",
        objectLiteralTypeAssertions: "never",
        arrayLiteralTypeAssertions: "never",
      }],
    },
  },
  {
    files: [CHILD_PROCESS_WRAPPER],
    rules: {
      "no-restricted-imports": "off",
      "no-restricted-syntax": "off",
      // This module is where process launches are written and reviewed; the rule flags all of them.
      "security/detect-child-process": "off",
    },
  },

  // Browser code: no HTML built from strings (innerHTML, outerHTML, insertAdjacentHTML,
  // document.write) unless it goes through a sanitizer.
  {
    files: ["static/**/*.js"],
    extends: [js.configs.recommended, nounsanitized.configs.recommended],
    languageOptions: { globals: globals.browser },
    rules: noDynamicCode,
  },

  // Other JavaScript (this file, tool configs, scripts): Node.
  {
    files: ["**/*.js", "**/*.mjs"],
    ignores: ["static/**"],
    extends: [js.configs.recommended, security.configs.recommended],
    languageOptions: { globals: globals.node },
    rules: { ...noDynamicCode, ...childProcessOnlyInWrapper },
  },
);
