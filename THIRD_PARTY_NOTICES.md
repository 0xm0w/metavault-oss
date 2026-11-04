# Third-party notices

MetaVault OSS is licensed under the Apache License 2.0 (see `LICENSE`).
It depends on and redistributes third-party software under their own licenses.
This file lists what is bundled directly in this repository and how to find the
rest. It is an inventory, not legal advice.

## Bundled in this repository

| Component | Where | License | Text |
| --- | --- | --- | --- |
| Inter variable font (v4.001), Copyright 2016 The Inter Project Authors, https://github.com/rsms/inter | `brand/src/inter-var.ttf`, `site/brand/src/inter-var.ttf` (used to outline the logo wordmark and build brand assets) | SIL Open Font License 1.1 | [`LICENSES/Inter-OFL-1.1.txt`](LICENSES/Inter-OFL-1.1.txt), copied from https://github.com/rsms/inter/blob/master/LICENSE.txt |

The marketing site (`site/`) also requests Inter from Google Fonts at view time.
That is a runtime request to Google, not a bundled file.

## npm dependencies

Runtime and development dependencies are pinned in `package-lock.json`, which
records each package's declared license. At the time of writing the lockfile
declares permissive licenses (MIT, ISC, BSD-2/3-Clause, Apache-2.0, BlueOak-1.0.0,
0BSD) plus MPL-2.0 (file-level copyleft, used unmodified) and a few
multi-licensed packages (for example `BSD-3-Clause OR GPL-2.0`, `MIT OR CC0-1.0`,
`WTFPL OR MIT`) where a permissive option applies. Re-check with your own license
tooling before redistributing.

## Windows installer

The Windows installer packages the app with Electron (MIT; it also carries
Chromium's third-party licenses). Installer builds should include the license
files that Electron and electron-builder place in the application directory
(`LICENSE`, `LICENSES.chromium.html`). Check a release asset to confirm before
publishing a new build.
