const SAFE_ENV_KEYS = [
  "COMSPEC",
  "OS",
  "PATH",
  "PATHEXT",
  "SYSTEMDRIVE",
  "SYSTEMROOT",
  "TEMP",
  "TMP",
  "WINDIR",
  "HOME",
  "LANG",
  "LC_ALL",
  "SHELL",
] as const;

const NON_OVERRIDABLE_ENV_KEYS = [
  "DYLD_INSERT_LIBRARIES",
  "DYLD_LIBRARY_PATH",
  "LD_LIBRARY_PATH",
  "LD_PRELOAD",
  "MCP_SECURITY_LAB",
  "NODE_OPTIONS",
  "NODE_PATH",
] as const;

export const RESERVED_ENV_KEYS: ReadonlySet<string> = new Set<string>([
  ...SAFE_ENV_KEYS,
  ...NON_OVERRIDABLE_ENV_KEYS,
]);

const SENSITIVE_FLAG_PATTERN =
  /^--?(?:api[-_]?key|authorization|credential|password|secret|token)$/i;
const SENSITIVE_ASSIGNMENT_PATTERN =
  /^((?:--?)?(?:api[-_]?key|authorization|credential|password|secret|token)=).+$/i;
const SENSITIVE_ENV_ASSIGNMENT_PATTERN =
  /^([A-Z0-9_]*(?:API_KEY|AUTHORIZATION|CREDENTIAL|PASSWORD|SECRET|TOKEN)=).+$/i;
const URL_CREDENTIAL_PATTERN = /^([a-z][a-z0-9+.-]*:\/\/)[^/@\s]+@/i;

export function createSanitizedEnvironment(
  source: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const environment: Record<string, string> = {};

  for (const key of SAFE_ENV_KEYS) {
    const value = source[key];
    if (value !== undefined) {
      environment[key] = value;
    }
  }

  environment.MCP_SECURITY_LAB = "1";
  return environment;
}

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[-_]/g, "");
}

// Compound names that are unambiguously credentials. Matched as substrings so
// client_secret, refresh_token, id_token, X-Amz-Security-Token, X-Amz-Signature,
// api_key, etc. are all caught.
const CREDENTIAL_NEEDLES = [
  "secret",
  "password",
  "passwd",
  "credential",
  "signature",
  "apikey",
  "accesskey",
  "privatekey",
  "accesstoken",
  "refreshtoken",
  "idtoken",
  "securitytoken",
  "sessiontoken",
  "bearer",
];

// Additional bare keys redacted from reports (over-redaction is safe there) but
// NOT treated as findings, since a bare ?token=/?key= is often an opaque cursor.
const BROAD_REDACTION_KEYS = new Set(["token", "key", "auth", "authorization", "sig", "pwd"]);

/** Strong, low-false-positive test used to RAISE a credentials-in-URL finding. */
export function isCredentialQueryKey(key: string): boolean {
  const normalized = normalizeKey(key);
  return CREDENTIAL_NEEDLES.some((needle) => normalized.includes(needle));
}

/** Broad test used only to REDACT report output, where over-redaction is safe. */
function isRedactableQueryKey(key: string): boolean {
  return isCredentialQueryKey(key) || BROAD_REDACTION_KEYS.has(normalizeKey(key));
}

function redactParams(params: URLSearchParams): boolean {
  let changed = false;
  for (const key of [...params.keys()]) {
    if (isRedactableQueryKey(key)) {
      params.set(key, "[REDACTED]");
      changed = true;
    }
  }
  return changed;
}

/**
 * Remove credentials from a URL before it enters a report: strip any userinfo
 * (`user:pass@`) and redact the value of sensitive query AND fragment parameters
 * (OAuth implicit-flow tokens live in the fragment). Falls back to a coarse regex
 * when the string is not a parseable URL.
 */
export function redactUrl(rawUrl: string): string {
  try {
    const url = new URL(rawUrl);
    if (url.username !== "" || url.password !== "") {
      url.username = "[REDACTED]";
      url.password = "";
    }
    redactParams(url.searchParams);
    if (url.hash.length > 1) {
      const fragment = new URLSearchParams(url.hash.slice(1));
      if (redactParams(fragment)) {
        url.hash = `#${fragment.toString()}`;
      }
    }
    // URL percent-encodes the brackets of our sentinel; restore it for readability.
    return url.toString().replace(/%5BREDACTED%5D/g, "[REDACTED]");
  } catch {
    return rawUrl.replace(URL_CREDENTIAL_PATTERN, "$1[REDACTED]@");
  }
}

export function redactArguments(args: string[]): string[] {
  const redacted: string[] = [];
  let redactNext = false;

  for (const argument of args) {
    if (redactNext) {
      redacted.push("[REDACTED]");
      redactNext = false;
      continue;
    }
    if (SENSITIVE_FLAG_PATTERN.test(argument)) {
      redacted.push(argument);
      redactNext = true;
      continue;
    }
    if (SENSITIVE_ASSIGNMENT_PATTERN.test(argument)) {
      redacted.push(argument.replace(SENSITIVE_ASSIGNMENT_PATTERN, "$1[REDACTED]"));
      continue;
    }
    if (SENSITIVE_ENV_ASSIGNMENT_PATTERN.test(argument)) {
      redacted.push(argument.replace(SENSITIVE_ENV_ASSIGNMENT_PATTERN, "$1[REDACTED]"));
      continue;
    }
    if (URL_CREDENTIAL_PATTERN.test(argument)) {
      redacted.push(argument.replace(URL_CREDENTIAL_PATTERN, "$1[REDACTED]@"));
      continue;
    }
    redacted.push(argument);
  }

  return redacted;
}
