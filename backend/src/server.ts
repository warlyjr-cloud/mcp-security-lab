import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const apiKey = process.env.GEMINI_API_KEY;
if (!apiKey) {
    console.error("GEMINI_API_KEY environment variable is missing.");
}

const ai = new GoogleGenAI({ apiKey: apiKey || 'MISSING_API_KEY' });

app.post('/api/gemini/consult', async (req: Request, res: Response): Promise<void> => {
    try {
        const { prompt, moduleContext } = req.body;

        if (!prompt) {
            res.status(400).json({ error: 'Prompt is required' });
            return;
        }

        const systemInstruction = `You are the AI Consultant for the CyberConsult Advanced Security Suite.
        You communicate in a professional, concise, hacker/cybersecurity expert persona.
        Keep answers highly technical, structured, and use markdown.
        Context: ${moduleContext || 'General Cybersecurity Consultation'}`;

        const response = await ai.models.generateContent({
            model: 'gemini-2.5-flash',
            contents: prompt,
            config: {
                systemInstruction: systemInstruction,
                temperature: 0.2
            }
        });

        res.json({ result: response.text });
    } catch (error: any) {
        console.error('Error calling Gemini API:', error);
        res.status(500).json({ error: 'Internal Server Error', details: error.message });
    }
});

app.listen(port, () => {
    console.log(`[CyberConsult] Backend server is running on http://localhost:${port}`);
});
