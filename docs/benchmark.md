# Benchmark methodology

The public benchmark measures deterministic rule classification, not model quality or
malware detection.

Each case declares:

- a synthetic configuration;
- whether the target must execute;
- explicit confirmation that the fixture is synthetic;
- the exact set of expected finding IDs.

The runner calculates true positives, false positives, false negatives, precision, and
recall. Duplicate findings within one case are collapsed to rule IDs for scoring.

```text
precision = true positives / (true positives + false positives)
recall    = true positives / (true positives + false negatives)
```

The `1.0` manifest requires both metrics to equal `1.0`. The corpus currently contains a
secure metadata server, an insecure metadata server, and a shell-launch configuration.

## Reproducibility

```powershell
npm.cmd run benchmark
```

Executable cases require `--consent-synthetic-execution`. Fixtures do not access the
network, personal files, credentials, or external services.

## Corpus acceptance

A new fixture must:

- be minimal and synthetic;
- terminate within the default timeout;
- avoid random values unless deterministically seeded;
- make expected findings reviewable;
- include both a security signal and a nearby negative case when practical.

Benchmark success proves only that the current rules match the reviewed corpus. It does not
estimate prevalence or real-world exploitability.
