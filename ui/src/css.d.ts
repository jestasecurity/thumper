// Ambient declaration for side-effect CSS imports (e.g. `@fontsource/inter/400.css`
// and `./styles/app.css` in main.tsx). TypeScript 6 rejects untyped side-effect
// imports (TS2882) without this; harmless under TS 5. See #144 / #148.
declare module "*.css";
