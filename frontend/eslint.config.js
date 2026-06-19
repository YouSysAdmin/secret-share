import js from "@eslint/js";
import svelte from "eslint-plugin-svelte";
import globals from "globals";

const runes = {
  $state: "readonly",
  $derived: "readonly",
  $effect: "readonly",
  $props: "readonly",
  $bindable: "readonly",
  $inspect: "readonly",
  $host: "readonly",
};

export default [
  js.configs.recommended,
  ...svelte.configs["flat/recommended"],
  {
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: "module",
      globals: { ...globals.browser, ...runes },
    },
  },
  {
    files: ["**/*.config.js"],
    languageOptions: { globals: { ...globals.node } },
  },
  { ignores: ["dist/", ".svelte-kit/", "node_modules/"] },
];
