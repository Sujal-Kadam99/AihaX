# Secure Windows Updates

## Policy

Automatic updates are supported only by packaged Windows releases. The app
requires a generic update feed over HTTPS and a configured Authenticode
publisher allowlist. Without both values, the updater stays disabled. Development
builds and unsigned local installers never check for or install updates.

`electron-updater` verifies the downloaded artifact hash from the update
metadata and validates the Windows signature against the publisher in
`app-update.yml` before allowing installation. Downloads and installation both
require user confirmation. Downgrades and prereleases are disabled.

## Release prerequisites

Store these values in the release environment or CI secret store. Do not commit
the certificate or password:

- `AIHAX_UPDATE_URL`: HTTPS directory where `latest.yml` and its installer files
  will be published.
- `AIHAX_UPDATE_PUBLISHER`: the full signer certificate subject expected by
  Windows Authenticode verification.
- `CSC_LINK`: path or secure URL for the Windows code-signing certificate.
- `CSC_KEY_PASSWORD`: certificate password, when the certificate requires one.

From `electron/`, run `npm run build:release`. The command stops before building
if the update feed, expected publisher, or signing certificate is missing or
invalid. It builds the frontend and creates the signed Windows installer and
update metadata in `electron/dist/`.

Publish `latest.yml`, the installer, and its blockmap to the exact directory
configured by `AIHAX_UPDATE_URL`. Do not publish the metadata until all listed
artifacts are available at their recorded URLs. A publisher change requires a
trusted transition plan; clients reject installers signed by an unrecognized
publisher.

## Local build behavior

`npm run build` creates an unsigned development installer without update-feed
metadata. The packaged app therefore fails the updater readiness gate and will
not install updates. This allows local packaging checks without representing
the result as a release build.
