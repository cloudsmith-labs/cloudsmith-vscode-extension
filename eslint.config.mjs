import globals from "globals";

export default [{
    ignores: [".quality/**", ".stryker-tmp/**", ".vscode-test/**", "node_modules/**"],
}, {
    files: ["**/*.{js,mjs}"],
    languageOptions: {
        ecmaVersion: 2022,
    },

    rules: {
        "constructor-super": "error",
        "getter-return": "error",
        "no-async-promise-executor": "error",
        "no-const-assign": "error",
        "no-constant-binary-expression": "error",
        "no-dupe-else-if": "error",
        "no-eval": "error",
        "no-global-assign": "error",
        "no-implied-eval": "error",
        "no-implicit-coercion": ["error", { allow: ["!!"] }],
        "no-new-func": "error",
        "no-this-before-super": "error",
        "no-undef": "error",
        "no-unreachable": "error",
        "no-unsafe-finally": "error",
        "no-unsafe-optional-chaining": "error",
        "no-unused-vars": "error",
        "use-isnan": "error",
        "valid-typeof": "error",
    },
}, {
    files: ["**/*.js"],
    languageOptions: {
        globals: {
            ...globals.commonjs,
            ...globals.node,
        },
        sourceType: "commonjs",
    },
}, {
    files: ["extension.js", "commands/**/*.js", "domain/**/*.js", "models/**/*.js", "util/**/*.js", "views/**/*.js", "scripts/**/*.js"],
    rules: {
        "no-promise-executor-return": "error",
    },
}, {
    files: ["test/**/*.js", "ui-test/**/*.js"],
    languageOptions: {
        globals: {
            ...globals.mocha,
        },
    },
}, {
    files: ["**/*.mjs"],
    languageOptions: {
        globals: {
            ...globals.node,
        },
        ecmaVersion: 2022,
        sourceType: "module",
    },
}];
