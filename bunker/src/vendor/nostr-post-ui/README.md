# @nostr-post/ui

The visual language of nostr-post: Material 3 style design tokens and shared UI primitives,
used by every component (`@nostr-post/web`, the domain packages, the field plugins' `/web`
entries) and by apps. Pages customize it on three levels: tokens, `::part()`, and full style
overrides.

No UI library dependency: the main entry has no dependencies at all, `/web` needs only Lit.

| Entry | Contents |
|---|---|
| `@nostr-post/ui` | Tokens as data and as CSS, the primitives as CSS, class and part names, the style overrides registry, color scheme choice. No Lit, React or DOM. |
| `@nostr-post/ui/web` | Lit styles for shadow DOM (`npStyles`), `NpElement` (the components' base class), `installTokens`, `followColorScheme`. |
| `@nostr-post/ui/web/dialog` | `<np-dialog>`: a modal dialog with a title, Close and its content. |
| `@nostr-post/ui/web/lightbox` | `<np-lightbox>`: photos and videos large, one at a time, with previous and next. |
| `@nostr-post/ui/tokens.css` | The tokens, for any page. |
| `@nostr-post/ui/ui.css` | Tokens and primitives, for apps and plain HTML. |

Other UI targets (a React entry, React Native, another UI library) can build on the main entry:
the tokens are data (`resolveTokens`), not only CSS.

## Tokens

All tokens are CSS custom properties named `--np-*`. They sit in the cascade layer `np.tokens`,
so a page's own (unlayered) CSS always wins, wherever it is loaded. The components install them
into the document when they connect; apps may load `tokens.css` or `ui.css` themselves.

```css
/* Brand: a few tokens restyle every component */
:root {
  --np-color-primary: #0b57d0;
  --np-font-size: 15px;
  --np-radius: 12px;
}

/* The dark theme has its own values */
.dark {
  --np-color-primary: #a8c7fa;
}
```

### Color roles

`--np-color-<role>`, light values on `:root`, dark values under `.dark` (a `dark` class on any
ancestor, as before):

- **Accents**: `primary`, `secondary`, `tertiary`, `error`, `success`, `warning`, `info`, each
  with `on-<accent>` (text on it). `<accent>-container` and `on-<accent>-container` are derived
  from the accent (`color-mix`), so setting `--np-color-primary` also changes its container.
- **Surfaces**: `surface`, `surface-container-lowest`, `-low`, `surface-container`, `-high`,
  `-highest`, `on-surface`, `on-surface-variant`, `inverse-surface`, `inverse-on-surface`.
- **Lines**: `outline`, `outline-variant`.
- **Others**: `rating` (stars), `scrim`, `on-scrim` (text on images), `shadow`.

### Type, shape, spacing, motion

| Input | Default | Derived |
|---|---|---|
| `--np-font-size` | `14px` | `--np-text-xs`, `-sm`, `-md`, `-lg`, `-xl`, `-2xl` (11, 12, 14, 16, 18, 24px) |
| `--np-font-family`, `--np-font-family-mono`, `--np-line-height` | system fonts, `1.5` | |
| `--np-radius` | `8px` | `--np-radius-xs`, `-sm`, `-md`, `-lg` (4, 8, 12, 16px), `--np-radius-full` |
| `--np-space` | `4px` | `--np-space-1` … `-6`, `-8` (multiples) |
| | | `--np-elevation-1`, `-2`, `-3`, `--np-focus-ring`, `--np-motion-duration`, `--np-motion-easing` |

Derived tokens are computed where they are declared: on `:root`, on `.dark`, and on any element
with the class `np-theme`. To theme only a part of the page, set the inputs on a container with
`class="np-theme"`.

### Tokens as data

```ts
import { resolveTokens, overridesCss, tokensCss, uiCss } from '@nostr-post/ui';

const dark = resolveTokens('dark', { color: { primary: '#a8c7fa' }, fontSize: 16 });
dark.color['primary-container']; // a hex value, mixed like the CSS does
dark.text.lg; // 18 (px)

overridesCss({ color: { primary: '#0b57d0' }, radius: 12 });
// ':root {\n  --np-color-primary: #0b57d0;\n  --np-radius: 12px;\n}\n'
```

`colorTokens`, `typeScale`, `radiusScale`, `spaceScale`, `elevationTokens` and `motionTokens`
are the raw data; `tokensCss()` and `uiCss()` the generated stylesheets.

## Primitives

The shared building blocks, styled only through `np-` classes (never bare elements), in the
cascade layer `np.primitives`. Modifiers are extra classes.

| Primitive | Classes |
|---|---|
| Button | `np-button` (outlined) + `np-filled`, `np-tonal`, `np-outlined`, `np-text`, `np-danger`, `np-small`; `np-icon-button` |
| Text field | `np-field` (wrapper), `np-label` (+ `np-required`), `np-input` (input, textarea, select; `aria-invalid` or `np-invalid`), `np-hint`, `np-field-error`, `np-checkbox` |
| Chip, badge | `np-chip` (+ `np-selected` or `aria-pressed`), `np-badge` + `np-primary`, `np-success`, `np-warning`, `np-error`, `np-info`, `np-tertiary` |
| Containers | `np-card` (+ `np-outlined`, `np-elevated`), `np-list`, `np-list-item`, `np-divider` |
| Dialog, menu | `np-dialog` (on `<dialog>`), `np-dialog-header`, `np-dialog-title`, `np-dialog-body`, `np-dialog-actions`; `np-menu`, `np-menu-item` |
| Choice | `np-segmented` + `np-segment`, `np-tabs` + `np-tab` (selected: `aria-pressed`, `aria-selected` or `np-selected`) |
| Messages | `np-message` + `np-error`, `np-success`, `np-warning`, `np-info`; `np-empty`, `np-loading`, `np-progress` |
| Others | `np-app` (page background and text), `np-headline`, `np-title`, `np-avatar`, `np-toolbar`, `np-spacer` |

The class names are also data: `npClass` and `npModifier`.

```html
<link rel="stylesheet" href="https://unpkg.com/@nostr-post/ui/dist/ui.css" />
<button class="np-button np-filled">Publish</button>
<div class="np-message np-error">Couldn't reach the relays</div>
```

## Parts

Components expose their key elements as parts with the same names everywhere, so one
`::part()` rule styles them all (`npPart`):

`container`, `card`, `header`, `title`, `content`, `footer`, `actions`, `button`, `primary` (the
main action, next to `button`), `input`, `label`, `hint`, `error`, `chip`, `badge`, `dialog`,
`menu`, `avatar`, `media`.

```css
nostr-post-view::part(card) {
  border-left: 4px solid var(--np-color-primary);
}
nostr-post-composer::part(primary) {
  text-transform: uppercase;
}
```

A component inside another forwards the parts (`exportparts=${npExportParts}`), so a rule on
`nostr-calendar-event` reaches the post view inside it.

## Style overrides

The "go crazy" level: add CSS to a component, or replace all its styles, by tag name or `'*'`
for every component. It also applies to components already on the page.

```ts
import { clearStyles, registerStyles, unstyled } from '@nostr-post/ui';

// Added after the component's own styles
const remove = registerStyles('nostr-post-composer', '.np-button { letter-spacing: 0.05em; }');

// Replace everything: start from the component's bare HTML
registerStyles('*', myDesignSystemCss, { mode: 'replace' });
unstyled('nostr-post-feed'); // no styles at all

remove(); // undo one entry
clearStyles(); // undo all
```

## Color scheme

```ts
import { type ColorScheme, parseColorScheme } from '@nostr-post/ui';
import { followColorScheme } from '@nostr-post/ui/web';

const stop = followColorScheme(parseColorScheme(localStorage.getItem('theme'))); // 'system' follows the OS
```

`followColorScheme(scheme, target = document.documentElement)` puts the `dark` class on the target
and, for `'system'`, keeps following `prefers-color-scheme`. `isDarkScheme` is the pure decision.

## `/web`: building a component

```ts
import { NpElement, npStyles } from '@nostr-post/ui/web';
import { css, html } from 'lit';
import { customElement } from 'lit/decorators.js';

@customElement('my-field-input')
export class MyFieldInput extends NpElement {
  static override styles = [...npStyles, css`.row { display: flex; gap: var(--np-space-2); }`];

  override render() {
    return html`<div class="row">
      <input class="np-input" part="input" />
      <button class="np-button np-filled" part="button primary">Add</button>
    </div>`;
  }
}
```

- `npStyles`: host defaults (font, color, box sizing) and the primitives, first in `styles`.
- `NpElement`: a `LitElement` that installs the tokens and applies `registerStyles` overrides.
- `installTokens(document)`: put the tokens into a document early (components do it when they
  connect).

## Shared components

Generic Lit components that more than one place needs (see AGENTS.md). Each takes plain data,
has its text in a messages object with English defaults (`messages` property) and its own
subpath, so importing `/web` doesn't load them.

### `<np-dialog>` (`@nostr-post/ui/web/dialog`)

```ts
import '@nostr-post/ui/web/dialog';

html`<np-dialog heading="Raw data" .messages=${{ close: 'Zavřít' }} @close=${onClose}>
  ${content}
</np-dialog>`;
```

- `heading`: the title; the children are its content.
- Opens with the `open` property or attribute (render it with `open` to show it while it's in
  the template) or `showModal()`; closes on Close, Escape and `close()`. `backdrop-close` also
  closes it on a click outside (a press that began inside, e.g. selecting text, doesn't count).
- Fires `close` when it closes.
- Parts: `dialog`, `header`, `button`. Size it with `np-dialog::part(dialog) { width: … }`.
- Messages (`DialogMessages`): `close`.

### `<np-lightbox>` (`@nostr-post/ui/web/lightbox`)

```ts
import '@nostr-post/ui/web/lightbox';
import type { LightboxSlide, NpLightbox } from '@nostr-post/ui/web/lightbox';

const slides: LightboxSlide[] = [{ url, media: 'image', alt }, { url: video, media: 'video', poster }];
html`<np-lightbox .slides=${slides}></np-lightbox>`;
lightbox.open(1);
```

- `.slides`: `{ url, media: 'image' | 'video', alt?, poster?, caption? }` (`caption`: text or a
  template under the photo, e.g. who posted it).
- `open(index)`, `close()`. Previous and next with buttons, arrow keys and swiping, wrapping
  around (`slideIndex(index, step, count)` in the main entry); "3 / 12"; full screen.
- Parts: `dialog`, `button`.
- Messages (`LightboxMessages`): `label`, `previous`, `next`, `position(current, count)`,
  `fullScreen`, `close`.
