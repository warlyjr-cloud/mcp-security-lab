import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import Anthropic from '@anthropic-ai/sdk';

dotenv.config();

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

app.listen(port, () => {
    console.log(`[MCP Security Lab] Backend server is running on http://localhost:${port}`);
});
