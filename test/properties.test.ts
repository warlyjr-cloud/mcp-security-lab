import assert from "node:assert/strict";
import test from "node:test";

import fc from "fast-check";

import { redactArguments, redactUntrustedText, redactUrl } from "../src/environment.js";
import { inspectTool } from "../src/rules/tools.js";

test("property: sensitive flag values never survive argument redaction", () => {
  fc.assert(
    fc.property(
      fc.constantFrom("--token", "--api-key", "--password", "--secret", "--credential"),
      fc.stringMatching(/^[A-Za-z0-9]{8,64}$/),
      (flag, secret) => {
        const serialized = JSON.stringify(redactArguments([flag, secret]));
        assert.equal(serialized.includes(secret), false);
      },
    ),
    { numRuns: 500 },
  );
});

test("property: URL credentials and sensitive query values are redacted", () => {
  fc.assert(
    fc.property(
      fc.stringMatching(/^[A-Za-z0-9]{8,32}$/),
      fc.stringMatching(/^[A-Za-z0-9]{8,32}$/),
      (credential, token) => {
        const result = redactUrl(
          `https://user:${credential}@example.com/mcp?token=${token}&visible=yes`,
        );
        assert.equal(result.includes(credential), false);
        assert.equal(result.includes(token), false);
        assert.equal(result.includes("visible=yes"), true);
      },
    ),
    { numRuns: 250 },
  );
});

test("property: untrusted error text does not retain common secret forms", () => {
  fc.assert(
    fc.property(fc.stringMatching(/^[A-Za-z0-9]{8,64}$/), (secret) => {
      const result = redactUntrustedText(`Authorization: Bearer ${secret} token=${secret}`);
      assert.equal(result.includes(secret), false);
    }),
    { numRuns: 250 },
  );
});

test("property: tool inspection is deterministic for arbitrary bounded schemas", () => {
  fc.assert(
    fc.property(
      fc.dictionary(
        fc.stringMatching(/^[A-Za-z][A-Za-z0-9_]{0,12}$/),
        fc.jsonValue(),
        { maxKeys: 20 },
      ),
      (properties) => {
        const tool = {
          name: "inspect_fixture",
          title: "Inspect fixture",
          description: "Inspects a synthetic fixture.",
          inputSchema: {
            type: "object",
            additionalProperties: false,
            properties,
          },
          outputSchema: {
            type: "object",
            additionalProperties: false,
            properties: {},
          },
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            idempotentHint: true,
            openWorldHint: false,
          },
        };

        assert.deepEqual(inspectTool(tool), inspectTool(structuredClone(tool)));
      },
    ),
    { numRuns: 500 },
  );
});
