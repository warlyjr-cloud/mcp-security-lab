import assert from 'node:assert/strict';
import test from 'node:test';

import {
    AuthAttemptLimiter,
    credentialsMatch,
    parseBasicAuthHeader,
    timingSafeStringEqual,
} from '../src/auth';

function basicHeader(user: string, password: string): string {
    return `Basic ${Buffer.from(`${user}:${password}`).toString('base64')}`;
}

test('timingSafeStringEqual matches equal strings and rejects different ones', () => {
    assert.equal(timingSafeStringEqual('hunter2', 'hunter2'), true);
    assert.equal(timingSafeStringEqual('hunter2', 'hunter3'), false);
    assert.equal(timingSafeStringEqual('short', 'a-much-longer-string'), false);
    assert.equal(timingSafeStringEqual('', ''), true);
});

test('parseBasicAuthHeader parses a well-formed header', () => {
    assert.deepEqual(parseBasicAuthHeader(basicHeader('mcp-consult', 'secret')), {
        user: 'mcp-consult',
        password: 'secret',
    });
});

test('parseBasicAuthHeader tolerates a password containing a colon', () => {
    assert.deepEqual(parseBasicAuthHeader(basicHeader('user', 'pass:with:colons')), {
        user: 'user',
        password: 'pass:with:colons',
    });
});

test('parseBasicAuthHeader returns null for missing, malformed, or non-Basic headers', () => {
    assert.equal(parseBasicAuthHeader(undefined), null);
    assert.equal(parseBasicAuthHeader(''), null);
    assert.equal(parseBasicAuthHeader('Bearer sometoken'), null);
    assert.equal(parseBasicAuthHeader('Basic'), null);
    // Valid base64 but no ':' separator once decoded.
    assert.equal(parseBasicAuthHeader(`Basic ${Buffer.from('nocolonhere').toString('base64')}`), null);
});

test('credentialsMatch requires both user and password to match', () => {
    const expected = { user: 'mcp-consult', password: 'secret' };
    assert.equal(credentialsMatch({ user: 'mcp-consult', password: 'secret' }, expected), true);
    assert.equal(credentialsMatch({ user: 'wrong', password: 'secret' }, expected), false);
    assert.equal(credentialsMatch({ user: 'mcp-consult', password: 'wrong' }, expected), false);
});

test('AuthAttemptLimiter allows requests through until the failure threshold is crossed', () => {
    let now = 0;
    const limiter = new AuthAttemptLimiter(3, 10_000, () => now);

    assert.equal(limiter.lockoutRemainingMs(), 0);
    limiter.recordFailure();
    assert.equal(limiter.lockoutRemainingMs(), 0);
    limiter.recordFailure();
    assert.equal(limiter.lockoutRemainingMs(), 0);
    limiter.recordFailure(); // 3rd failure crosses the threshold
    assert.ok(limiter.lockoutRemainingMs() > 0);
});

test('AuthAttemptLimiter lockout expires after the configured window', () => {
    let now = 0;
    const limiter = new AuthAttemptLimiter(1, 10_000, () => now);

    limiter.recordFailure();
    assert.equal(limiter.lockoutRemainingMs(), 10_000);

    now = 5_000;
    assert.equal(limiter.lockoutRemainingMs(), 5_000);

    now = 10_000;
    assert.equal(limiter.lockoutRemainingMs(), 0);
});

test('AuthAttemptLimiter resets the failure count on success', () => {
    let now = 0;
    const limiter = new AuthAttemptLimiter(2, 10_000, () => now);

    limiter.recordFailure();
    limiter.recordSuccess();
    limiter.recordFailure();
    // Only one failure since the reset -- still below the threshold of 2.
    assert.equal(limiter.lockoutRemainingMs(), 0);
});

test('AuthAttemptLimiter clears an active lockout on the next success', () => {
    let now = 0;
    const limiter = new AuthAttemptLimiter(1, 10_000, () => now);

    limiter.recordFailure();
    assert.ok(limiter.lockoutRemainingMs() > 0);

    limiter.recordSuccess();
    assert.equal(limiter.lockoutRemainingMs(), 0);
});
