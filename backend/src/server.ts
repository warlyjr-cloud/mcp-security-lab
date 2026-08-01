import express, { NextFunction, Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Anthropic from '@anthropic-ai/sdk';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

dotenv.config();

// Resolve the installed verifier CLI entry so the web UI runs the REAL scanner
// (not a simulation). `require` is available under the CommonJS backend.
const VERIFIER_CLI = require.resolve('mcp-security-lab/dist/src/cli.js');

const app = express();
const port = process.env.PORT || 3000;

// This backend is a LOCAL developer demo. Restrict CORS to localhost origins and
// cap the request body so the API is not a general-purpose remote surface.
const LOCALHOST_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;
app.use(
    cors({
        origin: (origin, callback) => {
            // Allow same-origin / tools with no Origin header, and localhost only.
            if (!origin || LOCALHOST_ORIGIN.test(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Origin not allowed'));
            }
        },
    }),
);
app.use(express.json({ limit: '64kb' }));

const apiKey = process.env.ANTHROPIC_API_KEY;
if (!apiKey) {
    console.error('ANTHROPIC_API_KEY environment variable is missing.');
}

const anthropic = new Anthropic({ apiKey: apiKey || 'MISSING_API_KEY' });

// This backend binds to loopback and restricts CORS to localhost, but that only
// keeps *remote* web pages out -- any other local process or user on a shared
// host can still reach this port and spend the operator's Anthropic quota on
// /api/consult. Require HTTP Basic Auth for that endpoint. If no password is
// configured, generate one at startup rather than shipping a hardcoded default
// credential; the demo stays usable out of the box, but the credential is only
// ever known to whoever reads this process's own console output.
const BASIC_AUTH_USER = process.env.MCP_CONSULT_USER || 'mcp-consult';
const BASIC_AUTH_PASSWORD = process.env.MCP_CONSULT_PASSWORD || randomBytes(18).toString('base64url');
if (!process.env.MCP_CONSULT_PASSWORD) {
    console.log(
        '[MCP Security Lab] MCP_CONSULT_PASSWORD is not set; generated a one-time password for /api/consult:\n' +
            `  user:     ${BASIC_AUTH_USER}\n` +
            `  password: ${BASIC_AUTH_PASSWORD}\n` +
            'Set MCP_CONSULT_USER / MCP_CONSULT_PASSWORD (and the matching VITE_CONSULT_USER / ' +
            'VITE_CONSULT_PASSWORD in frontend/.env) to pin stable credentials across restarts.',
    );
}

/** Fixed-length digest comparison so neither timing nor a length mismatch leaks anything. */
function timingSafeStringEqual(a: string, b: string): boolean {
    const digestA = createHash('sha256').update(a).digest();
    const digestB = createHash('sha256').update(b).digest();
    return timingSafeEqual(digestA, digestB);
}

function requireBasicAuth(req: Request, res: Response, next: NextFunction): void {
    const header = req.headers.authorization || '';
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
        const decoded = Buffer.from(encoded, 'base64').toString('utf8');
        const separatorIndex = decoded.indexOf(':');
        if (separatorIndex !== -1) {
            const user = decoded.slice(0, separatorIndex);
            const password = decoded.slice(separatorIndex + 1);
            if (
                timingSafeStringEqual(user, BASIC_AUTH_USER) &&
                timingSafeStringEqual(password, BASIC_AUTH_PASSWORD)
            ) {
                next();
                return;
            }
        }
    }
    res.set('WWW-Authenticate', 'Basic realm="MCP Security Lab Consultant"');
    res.status(401).json({ error: 'Basic authentication required for /api/consult.' });
}

app.post('/api/consult', requireBasicAuth, async (req: Request, res: Response): Promise<void> => {
    if (!apiKey) {
        res.status(503).json({ error: 'ANTHROPIC_API_KEY is not configured on the server.' });
        return;
    }

    try {
        const { prompt, moduleContext } = req.body;

        if (!prompt) {
            res.status(400).json({ error: 'Prompt is required' });
            return;
        }

        const systemInstruction = `You are the AI Security Consultant for the MCP Security Lab suite.
You communicate in a professional, concise, hacker/cybersecurity expert persona.
Keep answers highly technical, structured, and use markdown.
Context: ${moduleContext || 'General Cybersecurity Consultation'}`;

        const response = await anthropic.messages.create({
            model: 'claude-opus-4-8',
            max_tokens: 1024,
            system: systemInstruction,
            messages: [{ role: 'user', content: prompt }],
        });

        const content = response.content[0];
        if (!content || content.type !== 'text') {
            throw new Error('Unexpected response type from Anthropic API.');
        }

        res.json({ result: content.text });
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        console.error('Error calling Anthropic API:', message);
        res.status(500).json({ error: 'Internal Server Error', details: message });
    }
});

/**
 * A strictly rebuilt, safe scan config. We never trust the posted object
 * verbatim: we copy only known fields into a fresh object and force our own
 * policy, dropping anything unexpected.
 */
interface SafeConfig {
    target: { command?: string; args?: string[]; cwd?: string; url?: string; transport?: 'http' | 'sse' };
    policy: { timeoutMs: number; maxTools: number };
}

function sanitizeConfig(raw: unknown): SafeConfig | null {
    if (typeof raw !== 'object' || raw === null) return null;
    const target = (raw as Record<string, unknown>).target;
    if (typeof target !== 'object' || target === null) return null;
    const t = target as Record<string, unknown>;

    const clean: SafeConfig = { target: {}, policy: { timeoutMs: 5000, maxTools: 100 } };
    if (typeof t.url === 'string') {
        clean.target.url = t.url;
        if (t.transport === 'sse' || t.transport === 'http') clean.target.transport = t.transport;
    } else if (typeof t.command === 'string') {
        clean.target.command = t.command;
        clean.target.args = Array.isArray(t.args)
            ? t.args.filter((arg): arg is string => typeof arg === 'string')
            : [];
        clean.target.cwd = typeof t.cwd === 'string' ? t.cwd : '.';
    } else {
        return null;
    }
    return clean;
}

/**
 * Run the MCP Verifier CLI against a posted config and return its JSON report.
 *
 * SECURITY: this endpoint deliberately runs **launch-configuration checks only**
 * — it never passes `--execute`, so the CLI statically inspects the config and
 * never spawns the target process. Network input therefore cannot cause code
 * execution. The config is strictly rebuilt (sanitizeConfig) before use. To run
 * a full discovery/`--execute` scan, use the CLI directly on a trusted host.
 */
app.post('/api/scan', async (req: Request, res: Response): Promise<void> => {
    const config = sanitizeConfig((req.body ?? {}).config);
    if (config === null) {
        res.status(400).json({
            error: 'A valid "config" is required: { target: { command, args?, cwd? } | { url, transport? } }.',
        });
        return;
    }

    let directory: string | undefined;
    try {
        directory = await mkdtemp(join(tmpdir(), 'mcp-scan-'));
        const configPath = join(directory, 'config.json');
        await writeFile(configPath, JSON.stringify(config), 'utf8');

        // No --execute: static launch-configuration checks only. The target is
        // never started, so a malicious command string cannot run.
        const args = ['scan', '--config', configPath, '--format', 'json'];

        const child = spawn(process.execPath, [VERIFIER_CLI, ...args], {
            env: { ...process.env, MCP_SECURITY_LAB_WEB: '1' },
        });

        let stdout = '';
        let stderr = '';
        child.stdout.on('data', (chunk) => (stdout += chunk));
        child.stderr.on('data', (chunk) => (stderr += chunk));

        const killTimer = setTimeout(() => child.kill('SIGKILL'), 30_000);
        child.on('close', () => {
            clearTimeout(killTimer);
            try {
                res.json(JSON.parse(stdout));
            } catch {
                res.status(500).json({
                    error: 'Scanner did not return a JSON report.',
                    details: stderr.slice(0, 2000),
                });
            }
        });
        child.on('error', (error) => {
            clearTimeout(killTimer);
            res.status(500).json({ error: 'Failed to start the scanner.', details: error.message });
        });
    } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        res.status(500).json({ error: 'Internal Server Error', details: message });
    } finally {
        // Best-effort cleanup once the response has been sent.
        res.on('finish', () => {
            if (directory) {
                void rm(directory, { recursive: true, force: true });
            }
        });
    }
});

// Bind to loopback only: this developer demo must not be reachable off-host.
app.listen(Number(port), '127.0.0.1', () => {
    console.log(`[MCP Security Lab] Backend server is running on http://127.0.0.1:${port}`);
});
