# MetaVault OSS - brand iconography

**v0.3 - clean-room rebuild.** The mark is authored as parametric geometry in
`scripts/build_brand.py`. Nothing is traced from a bitmap. The same contour list
produces the SVGs (exact fillet arcs) and every PNG/ICO (supersampled winding
rasteriser).

Look at `preview.html` for the contact sheet.

## The mark

- **Vault body**: a rounded frame on two feet. The open interior is the window into the vault.
- **Hinges**: two accent capsules that cut through the frame with a clear gap, so
  they still read in mono and at small sizes.
- **AI chip**: a square chip with 3 pins per side and a pin-1 marker. A geometric
  **AI** monogram is knocked out of its center. The letters are drawn from geometry,
  so the mark doesn't depend on a font.

### Optical size tiers

One drawing can't be detailed at 512 px and also crisp at 16 px. The build
picks a tier from the rendered mark size:

| tier  | mark size | drawn on        | detail                                   |
| ----- | --------- | --------------- | ---------------------------------------- |
| full  | >= 96 px  | 512u grid       | AI monogram, pin-1 marker, fine pins     |
| mid   | 40-95 px  | 512u grid       | heavier frame, bigger chip, bolder AI    |
| small | 28-39 px  | 32-px grid      | chip + die window, 2 pins per side       |
| tiny  | 20-27 px  | 24-px grid      | chip + die window, 2 pins per side       |
| micro | < 20 px   | 16-px grid      | solid chip + 1-px pins, no hinge gap     |

The small tiers are authored in whole pixels on their own grid, so their edges
land on pixel boundaries.

## Files

| file | what it is |
| ---- | ---------- |
| `mark.svg` | master mark, ink on transparent (512u viewBox) |
| `mark-inverse.svg` | master mark with snow ink, for dark surfaces |
| `icons/favicon-{16..256}.png` | transparent favicon rung |
| `icons/favicon.ico` | 16+24+32+48 bundle |
| `icons/favicon.svg` | paper rounded-square favicon (primary) |
| `icons/icon-192.png`, `icon-512.png` | PWA icons (opaque paper) |
| `icons/maskable-512.png` | PWA maskable (content inside the 80% safe circle) |
| `icons/apple-touch-icon.png` | iOS home tile, 180, opaque |
| `icons/mark-white.png`, `mark-black.png` | mono silhouettes |
| `app/icon-{1024..32}.png` | Electron set on a paper squircle |
| `app/app-icon.ico` | Windows bundle (16..256) |
| `app/mac.iconset/*` | macOS bundle source (`iconutil -c icns app/mac.iconset`) |
| `app/tray{,@2x}.png` | white tray silhouettes (dark taskbar) |
| `app/tray-light{,@2x}.png` | ink tray silhouettes (light taskbar) |
| `logo-horizontal.svg/.png`, `logo-horizontal-dark.png` | mark + wordmark lockups |
| `wordmark.svg/.png` | standalone wordmark (Inter wght 640, outlined, GPOS-kerned) |
| `src/tiers.png` | optical-tier QA strip |

```html
<link rel="icon" href="/brand/icons/favicon.svg" type="image/svg+xml">
<link rel="icon" href="/brand/icons/favicon-32.png" sizes="32x32">
<link rel="apple-touch-icon" href="/brand/icons/apple-touch-icon.png">
<link rel="manifest" href="/brand/site.webmanifest">
<meta name="theme-color" content="#0f0d17">
```

Electron: point `build.icon` (electron-builder) at `brand/app/app-icon.ico`
(Windows) / `brand/app/mac.iconset` (mac). Copy `tray*.png` over
`packages/app/src/renderer/tray.png`.

## Colors

| token  | hex       | use |
| ------ | --------- | --- |
| ink    | `#0c0c0e` | mark on light surfaces, wordmark |
| accent | `#8250fc` | hinges |
| paper  | `#fbfbfd` | tiles (favicon, PWA, app icon) |
| snow   | `#f4f4f6` | mark ink on dark surfaces |
| night  | `#0f0d17` | app canvas / theme color |

## Editing

Change the numbers in `TIERS` (mark) or the lockup ratios in `build()`, then run:

```
python scripts/build_brand.py
```

Requirements: Python 3.10+, Pillow, numpy, fontTools. The original teal-vault set
(`site/brand/**`) is untouched.
