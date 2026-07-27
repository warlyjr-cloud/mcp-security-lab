import blessed from "blessed";
import Anthropic from "@anthropic-ai/sdk";
import type { Finding } from "../types.js";

export function openChatModal(screen: blessed.Widgets.Screen, finding: Finding): void {
  const key = process.env.ANTHROPIC_API_KEY;
  if (!key) {
    const errorBox = blessed.message({
      parent: screen,
      top: "center",
      left: "center",
      width: "50%",
      height: "shrink",
      border: "line",
      style: { border: { fg: "red" }, bg: "black", fg: "red" },
    });
    errorBox.display(
      "Error: ANTHROPIC_API_KEY is missing. Cannot open Cyber-Consultant.",
      3,
      () => {
        screen.render();
      },
    );
    return;
  }

  const anthropic = new Anthropic({ apiKey: key });
  const messages: Anthropic.MessageParam[] = [];

  const modal = blessed.box({
    parent: screen,
    top: "center",
    left: "center",
    width: "80%",
    height: "80%",
    border: "line",
    label: ` Cyber-Consultant: ${finding.id} `,
    style: { border: { fg: "green" }, bg: "black", fg: "green" },
  });

  const chatLog = blessed.log({
    parent: modal,
    top: 1,
    left: 1,
    width: "100%-4",
    height: "100%-6",
    scrollback: 100,
    scrollbar: { ch: " ", track: { bg: "green" }, style: { inverse: true } },
    tags: true,
  });

  const inputPrompt = blessed.textbox({
    parent: modal,
    bottom: 1,
    left: 1,
    width: "100%-4",
    height: 3,
    border: "line",
    inputOnFocus: true,
    style: { border: { fg: "green" }, bg: "black", fg: "white" },
  });

  chatLog.add(
    `{green-fg}SYSTEM:{/green-fg} Chat started for finding ${finding.id}: ${finding.title}`,
  );
  chatLog.add(
    `{green-fg}SYSTEM:{/green-fg} Type your question below and press ENTER. Press ESC to close.\n`,
  );

  const systemPrompt = `You are a Cyber-Consultant AI embedded in a hacker-style terminal.
The user is asking for help fixing this specific vulnerability in their MCP Server:
${JSON.stringify(finding, null, 2)}
Give concise, highly technical advice with code snippets. Keep responses short enough to fit in a terminal window.`;

  async function sendMessage(text: string): Promise<void> {
    chatLog.add(`{cyan-fg}YOU:{/cyan-fg} ${text}`);
    messages.push({ role: "user", content: text });
    chatLog.add(`{yellow-fg}CLAUDE:{/yellow-fg} Thinking...`);
    screen.render();

    try {
      const response = await anthropic.messages.create({
        model: "claude-opus-4-8",
        max_tokens: 1024,
        system: systemPrompt,
        messages: messages,
      });

      const reply = response.content[0];
      if (reply && reply.type === "text") {
        chatLog.add(`{yellow-fg}CLAUDE:{/yellow-fg} ${reply.text}\n`);
        messages.push({ role: "assistant", content: reply.text });
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      chatLog.add(`{red-fg}ERROR:{/red-fg} ${msg}\n`);
    }
    screen.render();
  }

  inputPrompt.key(["escape", "C-c"], () => {
    modal.destroy();
    screen.render();
  });

  inputPrompt.on("submit", (value) => {
    inputPrompt.clearValue();
    inputPrompt.focus(); // Keep focus after enter
    if (value.trim()) {
      sendMessage(value).catch(console.error);
    }
    screen.render();
  });

  inputPrompt.focus();
  screen.render();
}
