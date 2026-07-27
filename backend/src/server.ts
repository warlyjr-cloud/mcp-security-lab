import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Anthropic from '@anthropic-ai/sdk';
import { spawn } from 'node:child_process';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

dotenv.config();

// Resolve the installed verifier CLI entry so the web UI runs the REAL scanner
// (not a simulation). `require` is available under the CommonJS backend.
const VERIFIER_CLI = require.resolve('mcp-security-lab/dist/src/cli.js');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const apiKey = process.env.ANTHROPIC_API_KEY;
if (!apiKey) {
    console.error('ANTHROPIC_API_KEY environment variable is missing.');
}

const anthropic = new Anthropic({ apiKey: apiKey || 'MISSING_API_KEY' });

app.post('/api/consult', async (req: Request, res: Response): Promise<void> => {
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
 * Run the real MCP Verifier CLI against a posted config and return its JSON
 * report. This replaces the front-end simulation with a genuine scan.
 *
 * Body: { config: ScanConfig, execute?: boolean }
 * `execute` defaults to false (launch-configuration checks only). Enabling it
 * starts the target process on this host, so only allow it for trusted configs.
 */
app.post('/api/scan', async (req: Request, res: Response): Promise<void> => {
    const { config, execute } = req.body ?? {};
    if (typeof config !== 'object' || config === null) {
        res.status(400).json({ error: 'A "config" object (ScanConfig) is required.' });
        return;
    }

    let directory: string | undefined;
    try {
        directory = await mkdtemp(join(tmpdir(), 'mcp-scan-'));
        const configPath = join(directory, 'config.json');
        await writeFile(configPath, JSON.stringify(config), 'utf8');

        const args = ['scan', '--config', configPath, '--format', 'json'];
        if (execute === true) {
            args.push('--execute');
        }

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

app.listen(port, () => {
    console.log(`[MCP Security Lab] Backend server is running on http://localhost:${port}`);
});
