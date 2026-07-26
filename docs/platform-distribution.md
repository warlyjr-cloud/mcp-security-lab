# Platform distribution

## Current channels

- npm package and `mcpsl` command on supported Node.js versions;
- composite GitHub Action;
- `linux/amd64` GHCR image with SBOM and provenance.

These channels preserve one JavaScript implementation across Linux, Windows, and macOS.

## Native trust

There is currently no standalone `.exe`, macOS application bundle, installer, kernel
extension, or privileged service. Therefore Windows Authenticode signing and Apple
notarization are not applicable to version 0.3. Claiming either would be misleading.

If native binaries are introduced, release gates must include:

- reproducible compilation from a protected tag;
- platform-specific malware scanning;
- Authenticode signing through short-lived or hardware-backed credentials;
- Apple Developer ID signing, hardened runtime, and notarization;
- signed update metadata and rollback protection;
- separate provenance for each architecture.

Until then, package provenance, GitHub attestations, checksums, and immutable container
digests are the appropriate trust mechanisms.
