# Sandbox guarantees

## Docker adapter

The adapter runs `docker version` with a bounded timeout before reporting
`sandbox.verified=true`. The generated command uses:

- `--network none` by default;
- `--read-only`;
- `--cap-drop ALL`;
- `--security-opt no-new-privileges`;
- bounded PIDs, memory, and CPU;
- a `noexec,nosuid` 64 MiB temporary filesystem;
- a read-only `/workspace` mount;
- no Docker socket or parent environment inheritance.

Behavioral exercises also mount a random canary directory read-only. The canary value is
synthetic and is never reused.

Use an image pinned by full `sha256` digest. A mutable tag produces `SANDBOX002`.

## Direct adapter

`sandbox.adapter=none` is not a sandbox. It exists for reviewed local development and
compatibility. Dynamic execution records `SANDBOX001`, `verified=false`, and
`network=host`.

## Host considerations

Docker Desktop on Windows and macOS adds a VM boundary, but local file-sharing and daemon
configuration still matter. Linux shares the host kernel. In every platform:

- use a disposable host for unknown code;
- do not mount home folders, SSH directories, cloud credentials, or the Docker socket;
- keep the daemon patched;
- prefer rootless Docker where available;
- enforce host egress controls for tests that require network access.

## Future adapters

Windows Sandbox, macOS sandbox profiles, and hardened Linux namespaces require separate
implementations and verification. They are not currently claimed. See
[platform distribution](platform-distribution.md).
