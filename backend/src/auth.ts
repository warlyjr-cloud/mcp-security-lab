import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Fixed-length digest comparison: hashing both sides to a constant-length
 * digest before comparing means neither the match result nor a length
 * mismatch is observable via timing, unlike a naive `a === b` or an
 * early-exit per-character compare.
 */
export function timingSafeStringEqual(a: string, b: string): boolean {
    const digestA = createHash('sha256').update(a).digest();
    const digestB = createHash('sha256').update(b).digest();
    return timingSafeEqual(digestA, digestB);
}

export interface BasicAuthCredentials {
    user: string;
    password: string;
}

/** Parse an `Authorization: Basic <base64>` header. Returns null for anything else. */
export function parseBasicAuthHeader(header: string | undefined): BasicAuthCredentials | null {
    if (!header) {
        return null;
    }
    const [scheme, encoded] = header.split(' ');
    if (scheme !== 'Basic' || !encoded) {
        return null;
    }
    const decoded = Buffer.from(encoded, 'base64').toString('utf8');
    const separatorIndex = decoded.indexOf(':');
    if (separatorIndex === -1) {
        return null;
    }
    return { user: decoded.slice(0, separatorIndex), password: decoded.slice(separatorIndex + 1) };
}

export function credentialsMatch(
    provided: BasicAuthCredentials,
    expected: BasicAuthCredentials,
): boolean {
    return (
        timingSafeStringEqual(provided.user, expected.user) &&
        timingSafeStringEqual(provided.password, expected.password)
    );
}

/**
 * Tracks failed Basic Auth attempts against this single-process backend and
 * imposes a lockout window once a threshold is crossed. This does not
 * distinguish attackers by source -- the backend binds to loopback, so a
 * malicious local process and the legitimate frontend are indistinguishable
 * by IP -- it exists only to slow down automated guessing of a weak,
 * operator-set MCP_CONSULT_PASSWORD. It offers no protection when the
 * password is left at its randomly generated default, which is not
 * practically guessable in the first place.
 */
export class AuthAttemptLimiter {
    private failures = 0;
    private lockedUntil = 0;

    constructor(
        private readonly maxFailures = 5,
        private readonly lockoutMs = 60_000,
        private readonly now: () => number = Date.now,
    ) {}

    /** Milliseconds remaining in an active lockout, or 0 when not locked out. */
    lockoutRemainingMs(): number {
        return Math.max(0, this.lockedUntil - this.now());
    }

    recordSuccess(): void {
        this.failures = 0;
        this.lockedUntil = 0;
    }

    recordFailure(): void {
        this.failures += 1;
        if (this.failures >= this.maxFailures) {
            this.lockedUntil = this.now() + this.lockoutMs;
        }
    }
}
