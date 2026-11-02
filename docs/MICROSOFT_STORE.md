# Publishing MetaVault OSS to the Microsoft Store

The Store build produces an unsigned `.appx` (MSIX) package that the
Store re-signs. This gives users a **Windows-verified** install path
(SmartScreen-free, automatic updates via the Store).

## Build the package

```powershell
cd packages/app
npm run build
npm run pack:win:store
```

Output: `packages/app/release/MetaVault-OSS-0.1.0-win-x64.appx`.

The `appx` block in `package.json` (`build.appx`) sets the Store identity
fields. Before a real submission you must replace the placeholder values
with the ones Partner Center assigns to your reserved app:

- `identityName` / `applicationId` — from Partner Center → App identity
- `publisher` — your publisher ID (e.g. `CN=...`) from Partner Center
- `publisherDisplayName` — your display name

## Submit to the Microsoft Store

1. Create a free **Microsoft Partner Center** account and enroll in the
   Windows app developer program (one-time fee).
2. Reserve an app name ("MetaVault OSS") in Partner Center. This assigns
   the `identityName` and `publisher` you must put in `build.appx`.
3. Update `package.json` `build.appx` with those values and rebuild.
4. In Partner Center, create a new submission and upload the `.appx`.
5. Fill in store listing (description, screenshots, privacy policy URL,
   age rating) and submit for certification. Review typically takes 1–3
   days.
6. Once published, the Store listing URL becomes the canonical
   "Download for Windows" link. Update the site buttons in
   `site/index.html`, `site/docs/index.html`, and `site/hackathon/index.html`
   to point at the Store listing instead of the GitHub release.

## Notes

- The package is intentionally unsigned locally; the Store signs it.
  Do not attempt to self-sign for Store submission.
- Store builds do not include the daemon binaries' PATH tweaks from
  `scripts/installer.nsh` (that script is NSIS-only). If you need
  CLI-on-PATH behaviour for Store users, document a manual PATH step.
- Keep the NSIS installer (`npm run pack:win`) as the fallback for
  users who cannot reach the Store or want the open-source build.
