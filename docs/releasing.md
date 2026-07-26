# Release process

## One-time setup

1. Create the `mcp-security-lab` package on npm if it does not already exist.
2. Configure npm trusted publishing for:
   - GitHub owner: `warlyjr-cloud`
   - repository: `mcp-security-lab`
   - workflow: `release.yml`
   - allowed action: publish
3. Create a protected GitHub environment named `npm` with required maintainer approval.
4. Protect release tags and the `main` branch.
5. Disable traditional npm publish tokens after trusted publishing is verified.

The first npm publication may require a manually authenticated bootstrap because trusted
publisher configuration requires an existing package.

## Release checklist

1. Update `package.json`, `src/version.ts`, and `CHANGELOG.md`.
2. Run:

   ```powershell
   npm.cmd ci --ignore-scripts
   npm.cmd run quality
   npm.cmd run release:verify -- v0.3.0
   npm.cmd pack --dry-run
   ```

3. Merge through a reviewed pull request with all required checks.
4. Create a signed, protected tag matching the package version.
5. Publish a GitHub Release from that tag.
6. Approve the `npm` environment deployment.
7. Verify npm provenance, the attached CycloneDX SBOM and SHA-256 file, the GitHub
   attestation, and the GHCR image digest.

The workflow publishes with npm OIDC and does not use a long-lived `NPM_TOKEN`.

## Failure and rollback

Never overwrite an existing version. If publication is incorrect, deprecate the affected
npm version with a clear message, publish a corrected patch version, and document the event
in the changelog. Container tags must point to immutable release digests; consumers should
pin the digest rather than relying on a moving major tag.
