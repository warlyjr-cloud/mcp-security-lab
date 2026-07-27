import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import * as github from "@actions/github";

async function run() {
  try {
    const token = process.env.GITHUB_TOKEN;
    if (!token) {
      console.log("No GITHUB_TOKEN found. Skipping PR comment.");
      return;
    }

    // Only run on pull requests
    if (github.context.eventName !== "pull_request") {
      console.log("Not a pull request. Skipping PR comment.");
      return;
    }

    const octokit = github.getOctokit(token);
    const issue_number = github.context.payload.pull_request?.number;

    if (!issue_number) {
      console.log("Could not find PR number. Skipping PR comment.");
      return;
    }

    // Read the generated markdown scorecard
    let scorecard = "";
    try {
      const scorecardPath = resolve(process.cwd(), "MCP_SCORECARD.md");
      scorecard = readFileSync(scorecardPath, "utf8");
    } catch (error) {
      console.log("Could not read MCP_SCORECARD.md. Ensure the scanner ran with --format markdown and output to MCP_SCORECARD.md.");
      return;
    }

    const commentBody = `## 🛡️ MCP Security Lab Audit Report\n\n${scorecard}`;

    // Find if we already posted a comment so we can update it instead of spamming
    const { data: comments } = await octokit.rest.issues.listComments({
      owner: github.context.repo.owner,
      repo: github.context.repo.repo,
      issue_number: issue_number,
    });

    const botComment = comments.find(comment => {
      return comment.user?.type === "Bot" && comment.body?.includes("MCP Security Lab Audit Report");
    });

    if (botComment) {
      console.log("Updating existing PR comment...");
      await octokit.rest.issues.updateComment({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        comment_id: botComment.id,
        body: commentBody,
      });
    } else {
      console.log("Creating new PR comment...");
      await octokit.rest.issues.createComment({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        issue_number: issue_number,
        body: commentBody,
      });
    }
    
    console.log("Successfully posted PR comment.");
  } catch (error) {
    console.error("Failed to post PR comment:", error);
    process.exit(1);
  }
}

run();
