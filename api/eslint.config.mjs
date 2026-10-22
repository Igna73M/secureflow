import security from "eslint-plugin-security";

export default [
    {
        ignores: ["node_modules/**", "coverage/**", "eslint.config.mjs"],
    },
    {
        files: ["**/*.js", "**/*.cjs", "**/*.mjs"],
        languageOptions: {
            ecmaVersion: "latest",
            sourceType: "commonjs",
        },
        plugins: {
            security,
        },
        rules: {
            "security/detect-eval-with-expression": "error",
            "security/detect-non-literal-require": "error",
            "security/detect-child-process": "error",
            "security/detect-unsafe-regex": "error",
        },
    },
];
