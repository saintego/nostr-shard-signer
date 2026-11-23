# Agent Instructions

Guidance for AI coding agents (and humans) working in this repo. Claude Code reads it through
CLAUDE.md. Adapted from nostr-post's AGENTS.md, so the two projects look and read alike; where
the signer differs (it holds keys, runs in an iframe on other sites' pages, and is React), the
rule says why.

## Technical standards

Apply them to new and changed code. Existing exceptions are tracked in issues: don't copy them.

### Files

- Keep source files under 500 lines. When a change would push a file over, split it into focused
  modules first. `bunker/src/App.tsx` and `bunker/src/styles.css` are over: don't grow them; move
  what you touch out of them.

### File names

- Files are camelCase (`passkeyPopup.ts`, `derive.vectors.json`); React components are
  PascalCase, named after the component (`ConfirmView.tsx`).
- Tool config files keep their tool's name (`vite.config.ts`, `playwright.config.js`).

### Exports

- No barrel files (`export * from …`). Import the module you need.

### Style

- Logic is pure functions in framework-free modules (`bunker/src/lib/`), components only render
  and wire events. A function that mixes logic with JSX is split.
- New logic modules return a `Result` for expected failures instead of throwing (soft rule; the
  existing code throws, and so do the libraries it wraps).
- No classes holding mutable state. Exception: an object a library must copy between windows
  (`postMessage`), where only plain fields survive, e.g. storage helpers handed to Web3Auth. Say
  so in a comment.
- Prefer `const` over `let` (soft rule). Use `let` when a value really changes; don't contort code
  to avoid it.

### Types

- TypeScript strict mode. No `any`: wrap untyped library internals (Web3Auth's) in small typed
  helpers, and keep the cast there. Write code that would pass `noUncheckedIndexedAccess`.

### Tooling

- npm workspaces (not pnpm: the workflows and the npm package build on npm).
- Biome for linting and formatting: `npm run lint`, `npm run lint:fix`, `npm run format`.
  `npm run lint:hooks` (React hook dependencies) runs in CI and must pass: a deliberate
  exception gets a `biome-ignore` comment with the reason, not an `eslint-disable`.
- Tests: `npm test` (build, types, Playwright). Locally, see the README for the browser setup.

## Security first

The signer holds users' keys on other people's sites. Before a change, ask what a hostile page
that embeds the signer could do with it.

- The page never chooses what the signer shows: no page-supplied text, styles or markup in the
  signer's UI (see Styling and User-facing text).
- Sensitive steps go to the signer's popup (#62, #73 D22). Popups open with `'_blank'`, never by
  name (#77), and trust only their opener.
- Keys, the root and Web3Auth tokens never leave the signer's origin except where the spec says
  so (#73).
- Spec and decisions: #73. Checks against real browsers: #75 and the check kit (`checks.html`).

## Styling

One visual language with nostr-post: its design tokens and primitives (`@nostr-post/ui`), vendored
in `bunker/src/vendor/nostr-post-ui/` by `scripts/vendor-nostr-post-ui.sh` until it's on npm.
Material 3 is the reference for new UI (roles, states, spacing), not a dependency.

- **Share, don't restyle**: for a button, field, chip, badge, card, list item, dialog, menu or
  message, use the primitive's classes (`np-button np-filled`, `np-input`, `np-message np-error`,
  …; see the vendored README). A missing variant goes to `@nostr-post/ui` first, then is vendored
  again. Keep a component's own class next to the primitive's when code or tests use it.
- **Tokens only**: colors, font sizes, radii, spacing and shadows come from `--np-*` tokens; no
  hex/rgb values or px font sizes in styles, and no colors in React style objects.
- **Dark theme from the tokens**: a `dark` class on the root swaps token values. Check every new or
  restyled view in both.
- **Pages can't restyle the signer** (unlike nostr-post's components): no `::part`, no style
  overrides, no page CSS. A page may pass only a validated theme: light, dark or auto, a primary
  color, a radius and a font size. Never the error, warning or danger colors, which tell the user
  what is risky.
- Styles live in their own module next to the component, not in one global sheet; move a
  component's rules out of `styles.css` when you touch it.
- The widget's size goes to the page as `RESIZE`: a style change that changes a view's height
  changes what the page sees (#73 D22, fixed heights for views with private data).

## User-facing text

- Prepare for translation: a component's text lives in a messages object with English defaults
  (`*Messages.ts` next to the component), read through the locale registry, not inline in JSX.
  Move existing inline text over when you touch it.
- **Translations are bundled in the signer**, one messages set per language. A page may pass only
  a language code (`locale`); the signer uses it if it has that language, otherwise the browser's,
  otherwise English. Pages can never supply or override the signer's text: a page that could
  reword a prompt could turn "Don't allow" into "Allow" or drop a warning.
- Write for people who don't know Nostr: short sentences, no jargon in prompts; say what will
  happen and who can see it.

## Keep docs in sync

- A change to public API (bridge options, messages to the page, `window.nostr` behaviour) updates
  README.md, llms.txt, llms-full.txt, the npm README and `nostr-bridge.d.ts` in the same commit.
- When a change alters behaviour a doc describes, fix that doc. Docs describe what exists; planned
  work goes to GitHub Issues.

## Issues

GitHub Issues are the single list of open work.

- Before starting a change, read the open issues it touches (and #73's sub-issues for v1).
- If an open issue would need a different data model, API or file layout than the simplest
  version of your change, say so before building and let the user choose.
- A bug or request reported in chat gets an issue before the fix. The PR that fixes it closes it.
- New work found on the way (a bug you didn't fix, a follow-up, a TODO) gets an issue; a TODO
  comment names it (`TODO(#123)`). Ask before opening issues outside the change at hand.
- Don't delete issues.

## Branches, commits and PRs

- Work on a branch and open a PR; the user validates on the PR and merges. Commits and pushes to
  the work branch are fine; never push to `main` or merge.
- v1 lands in one PR (#96) into the integration branch (`shared-mode`), one commit per issue.
- Changes needed in other repos (evolustr, nostr-post) are proposed to the user first.
