# Design system

The interface uses Tailwind utilities with CSS-variable color tokens. Light and dark themes are supported by `frontend/src/styles/tokens.css`; keep both themes in sync when changing a token.

## Color tokens

| Tailwind token | CSS variable | Purpose |
|---|---|---|
| `background` | `--color-bg-app` | Application canvas |
| `surface`, `surface-1` | `--color-bg-surface` | Cards, dialogs, and panels |
| `surface-2` | `--color-bg-surface-elevated` | Raised surfaces |
| `surface-hover` | `--color-bg-surface-hover` | Hovered surfaces |
| `border-subtle`, `border`, `border-strong` | `--color-border-*` | Surface separation |
| `text-primary`, `text-secondary`, `text-muted` | `--color-text-*` | Text hierarchy |
| `accent`, `accent-hover` | `--color-brand-accent*` | Brand and primary actions |
| `critical`, `high`, `medium`, `low`, `info`, `warning`, `success` | `--color-*` | Finding severity and status |

## Existing primitives

Use the shared components in `frontend/src/components/ui/` for buttons, inputs, alerts, badges, cards, drawers, empty states, modals, progress, selects, skeletons, tables, tabs, and toasts. Use `useToast()` for user-visible operation failures. Modals provide a focus trap, restore focus on close, and generate unique accessible ids.

Fonts are bundled locally: Inter is the interface font and JetBrains Mono is for code, identifiers, and terminal-like content. Do not load product UI fonts from a remote service.

## Migration rules

- Prefer semantic color tokens for new UI. Existing raw Tailwind palettes remain until each page can be migrated and reviewed; do not replace `theme.extend.colors` or ban raw classes globally before that migration is complete.
- Keep light and dark token values paired. Theme selection supports `light`, `dark`, and `system`.
- Prefer shared UI primitives over page-local controls. Add a primitive when it removes repeated behavior or markup across multiple features.
- Keep spacing and layout readable with Tailwind's standard scale. Avoid new one-off hex colors and inline styles when a token or utility fits.
