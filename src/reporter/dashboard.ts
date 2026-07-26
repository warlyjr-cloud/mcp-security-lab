import blessed from "blessed";
import type { ScanReport } from "../types.js";
import { openChatModal } from "./chat.js";

export function renderDashboard(report: ScanReport): void {
  const screen = blessed.screen({
    smartCSR: true,
    title: "MCP Security Lab - Dashboard",
  });

  const header = blessed.box({
    top: 0,
    left: "center",
    width: "100%",
    height: 3,
    content: "{center}{bold}MCP Security Lab - Live Audit Dashboard{/bold}{/center}",
    tags: true,
    style: {
      fg: "green",
      bg: "black",
    },
  });

  const targetLabel =
    report.target.url !== undefined
      ? report.target.url
      : `${report.target.command} ${(report.target.args ?? []).join(" ")}`.trim();

  const summaryText = [
    `Target: ${targetLabel}`,
    `Status: ${report.execution.connected ? "{green-fg}Connected{/green-fg}" : "{red-fg}Disconnected{/red-fg}"}`,
    `Tools Invoked: ${report.execution.toolsInvoked}`,
    `OS Sandbox: ${report.execution.osSandboxed ? "{green-fg}Enabled{/green-fg}" : "{red-fg}Disabled{/red-fg}"}`,
  ].join("\n");

  const summaryBox = blessed.box({
    top: 3,
    left: 0,
    width: "40%",
    height: 8,
    label: " Target Info ",
    content: summaryText,
    tags: true,
    border: {
      type: "line",
    },
    style: {
      fg: "green",
      bg: "black",
      border: { fg: "green" },
    },
  });

  const scoreText = [
    `{red-fg}Critical: ${report.summary.critical}{/red-fg}`,
    `{magenta-fg}High:     ${report.summary.high}{/magenta-fg}`,
    `{yellow-fg}Medium:   ${report.summary.medium}{/yellow-fg}`,
    `{blue-fg}Low:      ${report.summary.low}{/blue-fg}`,
    `{white-fg}Info:     ${report.summary.info}{/white-fg}`,
  ].join("\n");

  const scoreBox = blessed.box({
    top: 3,
    left: "40%",
    width: "60%",
    height: 8,
    label: " Vulnerability Scorecard ",
    content: scoreText,
    tags: true,
    border: {
      type: "line",
    },
    style: {
      fg: "green",
      bg: "black",
      border: { fg: "green" },
    },
  });

  const findingsList = blessed.list({
    top: 11,
    left: 0,
    width: "100%",
    height: "100%-14",
    label: " Findings (Use Up/Down Arrows) ",
    keys: true,
    vi: true,
    mouse: true,
    border: {
      type: "line",
    },
    style: {
      fg: "green",
      bg: "black",
      border: { fg: "green" },
      selected: { bg: "green", fg: "black" },
    },
    items:
      report.findings.length > 0
        ? report.findings.map((f) => `[${f.severity.toUpperCase()}] ${f.id}: ${f.title}`)
        : ["No findings detected."],
  });

  const footer = blessed.box({
    bottom: 0,
    left: 0,
    width: "100%",
    height: 3,
    content: "{center}Press Q, Escape, or Ctrl+C to quit.{/center}",
    tags: true,
    style: {
      fg: "green",
      bg: "black",
    },
  });

  screen.append(header);
  screen.append(summaryBox);
  screen.append(scoreBox);
  screen.append(findingsList);
  screen.append(footer);

  // Open Chat Modal on 'c'
  screen.key(["c"], () => {
    const selectedIndex = (findingsList as blessed.Widgets.ListElement & { selected: number })
      .selected;
    if (
      report.findings.length > 0 &&
      selectedIndex >= 0 &&
      selectedIndex < report.findings.length
    ) {
      const selectedFinding = report.findings[selectedIndex];
      if (selectedFinding) {
        openChatModal(screen, selectedFinding);
      }
    }
  });

  // Focus the list so the user can scroll
  findingsList.focus();

  // Quit on Escape, q, or Control-C.
  screen.key(["escape", "q", "C-c"], () => {
    // If a modal is open, escape will be handled by the modal first if it has focus
    // So this global exit won't necessarily kill the app if they are in the modal,
    // unless the screen captures it globally. We should check if we are in the list.
    if (screen.focused === findingsList) {
      return process.exit(0);
    }
  });

  screen.render();
}
