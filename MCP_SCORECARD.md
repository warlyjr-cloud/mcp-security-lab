# MCP Security Lab Report

![Security Grade](https://img.shields.io/badge/MCP_Security_Lab-Grade_C-orange?style=for-the-badge)

## Scan Summary

- **Target:** `node dist/fixtures/insecure-server.js`
- **Connected:** Yes
- **Transport:** stdio
- **Tools Invoked:** 0
- **OS Sandbox:** No

### Findings Summary

| Severity        | Count |
| --------------- | ----- |
| 🔴 **Critical** | 0     |
| 🟠 **High**     | 7     |
| 🟡 **Medium**   | 2     |
| 🔵 **Low**      | 2     |
| ⚪ **Info**     | 0     |

## Detailed Findings

### [HIGH] TOOL003: Text contains a prompt-injection-like instruction

- **Location:** `prompt:summarize`
- **CWE:** CWE-77
- **OWASP:** LLM01

**Evidence:**

> The prompt description matched the instruction override pattern.

**Recommendation:**
Describe functionality only; remove behavioral or hidden instructions.

---

### [HIGH] TOOL003: Text contains a prompt-injection-like instruction

- **Location:** `prompt:summarize`
- **CWE:** CWE-77
- **OWASP:** LLM01

**Evidence:**

> The prompt description matched the hidden prompt reference pattern.

**Recommendation:**
Describe functionality only; remove behavioral or hidden instructions.

---

### [HIGH] TOOL003: Text contains a prompt-injection-like instruction

- **Location:** `tool:delete_everything`
- **CWE:** CWE-77
- **OWASP:** LLM01

**Evidence:**

> The description matched the instruction override pattern.

**Recommendation:**
Describe functionality only; remove behavioral or hidden instructions.

---

### [HIGH] TOOL003: Text contains a prompt-injection-like instruction

- **Location:** `tool:delete_everything`
- **CWE:** CWE-77
- **OWASP:** LLM01

**Evidence:**

> The description matched the forced invocation pattern.

**Recommendation:**
Describe functionality only; remove behavioral or hidden instructions.

---

### [HIGH] TOOL005: Tool safety hints are missing

- **Location:** `tool:delete_everything`
- **CWE:** CWE-1188

**Evidence:**

> Neither destructiveHint nor readOnlyHint is explicitly declared.

**Recommendation:**
Declare the applicable MCP safety annotations explicitly.

---

### [HIGH] TOOL006: Potentially destructive tool is not marked destructive

- **Location:** `tool:delete_everything`
- **CWE:** CWE-250
- **OWASP:** LLM08

**Evidence:**

> Tool name "delete_everything" implies an external side effect.

**Recommendation:**
Set destructiveHint to true and keep the operation narrowly scoped.

---

### [HIGH] TOOL011: Dangerous Capability Combination (Least Privilege Violation)

- **Location:** `server`
- **CWE:** CWE-250
- **OWASP:** LLM08

**Evidence:**

> The server exposes both broad READ tools and destructive WRITE tools.

**Recommendation:**
Separate read and write capabilities into different MCP servers or require explicit user confirmation for write operations.

**Auto-Remediation:**

```typescript
// Separate read and write into different MCP servers or use user prompts:
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  if (request.params.name === "delete_database") {
    // Anthropic recommends keeping a human in the loop for destructive actions
    throw new McpError(ErrorCode.MethodNotFound, "Interactive human approval required.");
  }
});
```

---

### [MEDIUM] TOOL004: Tool annotation title is missing

- **Location:** `tool:delete_everything`

**Evidence:**

> annotations.title is absent or empty.

**Recommendation:**
Add a short human-readable title annotation.

---

### [MEDIUM] TOOL010: Context Exhaustion Risk: Missing pagination limits

- **Location:** `tool:list_items`
- **CWE:** CWE-400
- **OWASP:** LLM10

**Evidence:**

> Tool name implies reading, but inputSchema lacks limit, cursor, or offset fields.

**Recommendation:**
Implement pagination limits to prevent context window exhaustion attacks.

**Auto-Remediation:**

```typescript
// Example Zod schema with pagination limit:
const inputSchema = zodToJsonSchema(
  z.object({
    query: z.string(),
    limit: z.number().max(50).default(10), // Guard against context exhaustion
    cursor: z.string().optional(),
  }),
);
```

---

### [LOW] TOOL009: Input schema accepts undeclared properties

- **Location:** `tool:delete_everything`
- **CWE:** CWE-20

**Evidence:**

> inputSchema.additionalProperties is not explicitly false.

**Recommendation:**
Reject unknown input fields when the server framework supports it.

---

### [LOW] TOOL009: Input schema accepts undeclared properties

- **Location:** `tool:list_items`
- **CWE:** CWE-20

**Evidence:**

> inputSchema.additionalProperties is not explicitly false.

**Recommendation:**
Reject unknown input fields when the server framework supports it.

---
